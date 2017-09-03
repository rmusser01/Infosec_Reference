## Anonymity, Opsec & Privacy

### TOC

* Cull
* [Articles](#Articles)
* [How-Tos](#howtos)
* [Papers](#Papers)
* [Talks/Videos](#Talks)
* [Tools](#Tools)








#### Cull




#### end cull



### General

[OS X Security and Privacy Guide](https://github.com/drduh/OS-X-Security-and-Privacy-Guide)

[Bugger - Adam Curtis](http://www.bbc.co.uk/blogs/adamcurtis/entries/3662a707-0af9-3149-963f-47bea720b460)
* Maybe the real state secret is that spies aren't very good at their jobs and don't know much about the world


### Blogposts
[De-Anonymizing Alt.Anonymous.Messages](https://ritter.vg/blog-deanonymizing_amm.html)

[Defeating and Detecting Browser Spoofing - Browserprint](https://browserprint.info/blog/defeatingSpoofing)

[Invasion of Privacy - HackerFactor](http://www.hackerfactor.com/blog/index.php?/archives/703-Invasion-of-Privacy.html)

[Trawling Tor Hidden Service – Mapping the DHT](https://donncha.is/2013/05/trawling-tor-hidden-services/)

[China travel laptop setup](https://mricon.com/i/travel-laptop-setup.html?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&iid=88d246896d384d5292f51df954a2c8ba&uid=150127534&nid=244+272699400)

[Operational Security and the Real World - The Grugq](https://medium.com/@thegrugq/operational-security-and-the-real-world-3c07e7eeb2e8)

[CIA Vault7 Development Tradecraft DOs and DON'Ts](https://wikileaks.org/ciav7p1/cms/page_14587109.html)

[Dutch-Russian cyber crime case reveals how police tap the internet - ElectroSpaces](http://electrospaces.blogspot.de/2017/06/dutch-russian-cyber-crime-case-reveals.html?m=1)

[Deanonymizing Windows users and capturing Microsoft and VPN accounts](https://medium.com/@ValdikSS/deanonymizing-windows-users-and-capturing-microsoft-and-vpn-accounts-f7e53fe73834)

[The Paranoid's Bible: An anti-dox effort.](https://paranoidsbible.tumblr.com/)







### <a name="Articles">Articles</a>
| Title | Link
| -------- | --------- |
| De-anonymizing facebook users through CSP | http://www.myseosolution.de/deanonymizing-facebook-users-by-csp-bruteforcing/#inhaltsverzeichnis
| Anonymous’s Guide to OpSec | http://www.covert.io/research-papers/security/Anonymous%20Hacking%20Group%20--%20OpNewblood-Super-Secret-Security-Handbook.pdf
| Cat Videos and the Death of Clear Text | https://citizenlab.org/2014/08/cat-video-and-the-death-of-clear-text/

[How to Spot a SpoCTok](https://cryptome.org/dirty-work/spot-spook.htm)

[China travel laptop setup](https://mricon.com/i/travel-laptop-setup.html?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&iid=88d246896d384d5292f51df954a2c8ba&uid=150127534&nid=244+272699400)

[Operational Security and the Real World - The Grugq](https://medium.com/@thegrugq/operational-security-and-the-real-world-3c07e7eeb2e8)

[Protecting Your Sources When Releasing Sensitive Documents](https://source.opennews.org/articles/how-protect-your-sources-when-releasing-sensitive-/)

[Bugger - Adam Curtis](http://www.bbc.co.uk/blogs/adamcurtis/entries/3662a707-0af9-3149-963f-47bea720b460)
* Maybe the real state secret is that spies aren't very good at their jobs and don't know much about the world

[Detect Tor Exit doing sniffing by passively detecting unique DNS query (via HTML & PCAP parsing/viewing)](https://github.com/NullHypothesis/exitmap/issues/37)







### <a name="how-tos"How-Tos</a>

[How to stop Firefox from making automatic connections](https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections)



### <a name="Papers">Papers</a>
|**Protocol Misidentification Made Easy with Format-Transforming Encryption** | 
| -------- | 
|**Link:**  https://eprint.iacr.org/2012/494.pdf 
| **Description**: Deep packet inspection DPI technologies provide much- needed visibility and control of network trac using port- independent protocol identication, where a network ow is labeled with its application-layer protocol based on packet contents. In this paper, we provide the most comprehensive evaluation of a large set of DPI systems from the point of view of protocol misidentification attacks, in which adver- saries on the network attempt to force the DPI to mislabel connections. Our approach uses a new cryptographic primitive called format-transforming encryption FTE, which extends conventional symmetric encryption with the ability to transform the ciphertext into a format of our choosing. We design an FTE-based record layer that can encrypt arbi- trary application-layer trac, and we experimentally show that this forces misidentication for all of the evaluated DPI systems. This set includes a proprietary, enterprise-class DPI system used by large corporations and nation-states. We also show that using FTE as a proxy system incurs no latency overhead and as little as 16% bandwidth overhead compared to standard SSH tunnels. Finally, we integrate our FTE proxy into the Tor anonymity network and demonstrate that it evades real-world censorship by the Great Firewall of China. 
|---|
| **'I've Got Nothing to Hide' and Other Misunderstandings of Privacy** | **Link:** http://papers.ssrn.com/sol3/papers.cfm?abstract_id=998565& |
| **Description**: The web has become an essential part of our society and is currently the main medium of information delivery. Billions of users browse the web on a daily basis, and there are single websites that have reached over one billion user accounts. In this environment, the ability to track users and their online habits can be very lucrative for advertising companies, yet very intrusive for the privacy of users. In this paper, we examine how web-based device fingerprint- ing currently works on the Internet. By analyzing the code of three popular browser-fingerprinting code providers, we reveal the techniques that allow websites to track users without the need of client-side identifiers. Among these techniques, we show how current commercial fingerprinting approaches use questionable practices, such as the circumvention of HTTP proxies to discover a user’s real IP address and the installation of intrusive browser plugins. At the same time, we show how fragile the browser ecosystem is against fingerprinting through the use of novel browser- identifying techniques. With so many different vendors involved in browser development, we demonstrate how one can use diversions in the browsers’ implementation to distinguish successfully not only the browser-family, but also specific major and minor versions. Browser extensions that help users spoof the user-agent of their browsers are also evaluated. We show that current commercial approaches can bypass the extensions, and, in addition, take advantage of their shortcomings by using them as additional fingerprinting features.
| **'I've Got Nothing to Hide' and Other Misunderstandings of Privacy** : http://papers.ssrn.com/sol3/papers.cfm?abstract_id=998565&
| **Abstract:** We live in a surveillance state. Law enforcement and intelligence agencies have access to a huge amount of data about us, enabling them to learn intimate, private details about our lives. In part, the ease with which they can obtain such information reflects the fact that our laws have failed to keep up with advances in technology. However, privacy enhancing technologies can offer real protections even when the law does not. That intelligence agencies like the NSA are able to collect records about every telephone call made in the United States, or engage in the bulk surveillance of Internet communications is only possible because so much of our data is transmitted in the clear. The privacy enhancing technologies required to make bulk surveillance impossible and targeted surveillance more difficult already exist. We just need to start using them.**
|---|
| **Masquerade: How a Helpful Man-in-the-Middle Can Help You Evade Monitoring** - Defcon22| 
| Link: https://www.youtube.com/watch?v=_KyfJW2lHtk&spfreload=1
| **Description:** Sometimes, hiding the existence of a communication is as important as hiding the contents of that communication. While simple network tunneling such as Tor or a VPN can keep the contents of communications confidential, under active network monitoring or a restrictive IDS such tunnels are red flags which can subject the user to extreme scrutiny. Format-Transforming Encryption FTE can be used to tunnel traffic within otherwise innocuous protocols, keeping both the contents and existence of the sensitive traffic hidden.  However, more advanced automated intrusion detection, or moderately sophisticated manual inspection, raise other red flags when a host reporting to be a laser printer starts browsing the web or opening IM sessions, or when a machine which appears to be a Mac laptop sends network traffic using Windows-specific network settings.  We present Masquerade: a system which combines FTE and host OS profile selection to allow the user to emulate a user-selected operating system and application-set in network traffic and settings, evading both automated detection and frustrating after-the-fact analysis.
| Slides https://www.portalmasq.com/portal-defcon.pdf
| --
| **The NSA: Capabilities and Countermeasures** - Bruce Schneier - ShmooCon 2014 
| **Link:** https://www.youtube.com/watch?v=D5JA8Ytk9EI
|**Description:** Edward Snowden has given us an unprecedented window into the NSA's surveillance activities. Drawing from both the Snowden documents and revelations from previous whistleblowers, I will describe the sorts of surveillance the NSA does and how it does it. The emphasis is on the technical capabilities of the NSA, not the politics of their actions. This includes how it conducts Internet surveillance on the backbone, but is primarily focused on their offensive capabilities: packet injection attacks from the Internet backbone, exploits against endpoint computers and implants to exfiltrate information, fingerprinting computers through cookies and other means, and so on. I will then talk about what sorts of countermeasures are likely to frustrate the NSA. Basically, these are techniques to raise the cost of wholesale surveillance in favor of targeted surveillance: encryption, target hardening, dispersal, and so on.
| --
| **You're Leaking Trade Secrets** - Defcon22 Michael Schrenk
| **Link:** https://www.youtube.com/watch?v=JTd5TL6_zgY
|**Description:** Networks don't need to be hacked for information to be compromised. This is particularly true for organizations that are trying to keep trade secrets. While we hear a lot about personal privacy, little is said in regard to organizational privacy. Organizations, in fact, leak information at a much greater rate than individuals, and usually do so with little fanfare. There are greater consequences for organizations when information is leaked because the secrets often fall into the hands of competitors. This talk uses a variety of real world examples to show how trade secrets are leaked online, and how organizational privacy is compromised by seemingly innocent use of The Internet.

[Deep-Spying: Spying using Smartwatch and Deep Learning - Tony Beltramelli](https://arxiv.org/pdf/1512.05616v1.pdf)

[HORNET: High-speed Onion Routing at the Network Layer](http://arxiv.org/pdf/1507.05724v1.pdf)




### **<a name="Talks">Talks & Videos(& Presentatios)</a>**

| Title | Link
| -------- | --------- |
| **Cookieless Monster: Exploring the Ecosystem of Web-based Device Fingerprinting** | http://securitee.org/files/cookieless_sp2013.pdf |
| **Because Jail is for WUFTPD** - Legendary talk, a must watch. | https://www.youtube.com/watch?v=9XaYdCdwiWU
| **The Gruqgs blog** | http://grugq.tumblr.com/
| **COMSEC: Beyond encryption** | https://grugq.github.io/presentations/COMSEC%20beyond%20encryption.pdf
| **DEFCON 20: Can You Track Me Now? Government And Corporate Surveillance Of Mobile Geo-Location Data** | https://www.youtube.com/watch?v=NjuhdKUH6U4
| **Detecting and Defending Against a Surveillance State** - DEFCON 22 - Robert Rowley | https://www.youtube.com/watch?v=d5jqV06Yijw
| **Detecting and Defending Against a Surveillance State** - Robert Rowley - DEF CON 22 | https://www.youtube.com/watch?v=d5jqV06Yijw
| **The NSA: Capabilities and Countermeasures** - ShmooCon 2014 | https://www.youtube.com/watch?v=D5JA8Ytk9EI
| **Blinding The Surveillance State** - Christopher Soghoian - DEF CON 22 | https://www.youtube.com/watch?v=pM8e0Dbzopk
| **-------------**
| Client Identification Mechanisms | http://www.chromium.org/Home/chromium-security/client-identification-mechanisms
| Can you track me now?  - Defcon20 | https://wEww.youtube.com/watch?v=DxIF66Tcino

| **Phones and Privacy for Consumers** - Matt Hoy (mattrix) and David Khudaverdyan (deltaflyer) | http://www.irongeek.com/i.php?page=videos/grrcon2015/submerssion-therapy05-phones-and-privacy-for-consumers-matt-hoy-mattrix-and-david-khudaverdyan-deltaflyerhttps://ritter.vg/blog-deanonymizing_amm.html

[ Retail Surveillance / Retail Countersurveillance 50 most unwanted retail surveillance technologies / 50 most wanted countersurveillance technologies](https://media.ccc.de/v/33c3-8238-retail_surveillance_retail_countersurveillance#video&t=1993)

[OPSEC Concerns in Using Crypto](https://www.slideshare.net/JohnCABambenek/defcon-crypto-village-opsec-concerns-in-using-crypto)

[De-Anonymizing Alt.Anonymous. Messages - Defcon21 - Tom Ritter](https://www.youtube.com/watch?v=_Tj6c2Ikq_E)

[PISSED: Privacy In a Surveillance State Evading Detection - Joe Cicero - CYPHERCON11 ](https://www.youtube.com/watch?v=keA3WcKwZwA)

[What Happens Next Will Amaze You](http://idlewords.com/talks/what_happens_next_will_amaze_you.htm#six_fixes)

[Wifi Tracking: Collecting the (probe) Breadcrumbs - David Switzer](https://www.youtube.com/watch?v=HzQHWUM8cNo)
* Wifi probes have provided giggles via Karma and Wifi Pineapples for years, but is there more fun to be had? Like going from sitting next to someone on a bus, to knowing where they live and hang out? Why try to MITM someone’s wireless device in an enterprise environment where they may notice — when getting them at their favorite burger joint is much easier. In this talk we will review ways of collecting and analyzing probes. We’ll use the resulting data to figure out where people live, their daily habits, and discuss uses (some nice, some not so nice) for this information. We’ll also dicuss how to make yourself a little less easy to track using these methods. Stingrays are price prohibitive, but for just tracking people’s movements.. this is cheap and easy.

[How Tor Users Got Caught - Defcon 22](https://www.youtube.com/watch?v=7G1LjQSYM5Q)
* [Part 2](https://www.youtube.com/watch?v=TQ2bk9kMneI)
* [Article -  How Tor Users Got Caught by Government Agencies](http://se.azinstall.net/2015/11/how-tor-users-got-caught.html)








### **<a name="Tools">Tools</a>**

[FakeNameGenerator](http://www.fakenamegenerator.com/)


[MAT: Metadata Anonymisation Toolkit](https://mat.boum.org/) 
* MAT is a toolbox composed of a GUI application, a CLI application and a library.

[fteproxy](https://fteproxy.org/about)
* fteproxy is fast, free, open source, and cross platform. It has been shown to circumvent network monitoring software such as bro, YAF, nProbe, l7-filter, and appid, as well as closed-source commercial DPI systems

[Streisand](https://github.com/jlund/streisand)
* Streisand sets up a new server running L2TP/IPsec, OpenSSH, OpenVPN, Shadowsocks, sslh, Stunnel, and a Tor bridge. It also generates custom configuration instructions for all of these services. At the end of the run you are given an HTML file with instructions that can be shared with friends, family members, and fellow activists.

[exitmap](https://github.com/NullHypothesis/exitmap)
* Exitmap is a fast and modular Python-based scanner for Tor exit relays. Exitmap modules implement tasks that are run over (a subset of) all exit relays. If you have a background in functional programming, think of exitmap as a map() interface for Tor exit relays. Modules can perform any TCP-based networking task; fetching a web page, uploading a file, connecting to an SSH server, or joining an IRC channel.

[OnionCat - an Anonymous VPN adapter](https://www.onioncat.org/about-onioncat/)

[howmanypeoplearearound](https://github.com/schollz/howmanypeoplearearound)
*  Count the number of people around you 👨‍👨‍👦 by monitoring wifi signals 📡

[Decentraleyes](https://addons.mozilla.org/en-US/firefox/addon/decentraleyes/)
* Protects you against tracking through "free", centralized, content delivery. It prevents a lot of requests from reaching networks like Google Hosted Libraries, and serves local files to keep sites from breaking. Complements regular content blockers.

[Decentraleyes - Github](https://github.com/Synzvato/decentraleyes)
* A web browser extension that emulates Content Delivery Networks to improve your online privacy. It intercepts traffic, finds supported resources locally, and injects them into the environment. All of this happens automatically, so no prior configuration is required.

[Destroy-Windows-10-Spying](https://github.com/Nummer/Destroy-Windows-10-Spying)
* Destroy Windows Spying tool

[meek](https://github.com/Yawning/meek)
* meek is a blocking-resistant pluggable transport for Tor. It encodes a data stream as a sequence of HTTPS requests and responses. Requests are reflected through a hard-to-block third-party web server in order to avoid talking directly to a Tor bridge. HTTPS encryption hides fingerprintable byte patterns in Tor traffic.sek





