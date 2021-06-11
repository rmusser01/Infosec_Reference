## Anonymity, Operations Security & Privacy

### Table of Contents
- [General](#general)
	- [Android/iOS/Mobile](#mobile)
	- [Browser Related](#browser)
	- [Communications Security](#comsec)
	- [Data Collection](#dcollect)
	- [De-anonymization](#de-anon)
	- [Documents/Writing](#writing)
	- [Facial Identification](#facial)
	- [Informative/Educational](#informative)
	- [Journalism & Media Publishing](#media)
	- [Network Obfuscation](#obfuscation)
	- [References/Resources](#ref)
	- [Tor](#tor)
	- [Traveling](#travel)
	- [Miscellaneous Stuff](#misc)
	- [Miscellaneous Tools](#misc-tools)
- [Counter-Surveillance](#counter)
	- [Writeups](#cwriteup)
	- [Videos/Talks](#cvideos)
	- [Papers](#cpapers)
- [Disinformation & Propaganda](#disinfo)
- [Emissions Security](#emissions)
	- [Papers](#papers)
- [Modern Surveillance](#modern)
	- [China](#china)
	- [United States](#usa)
- [Commercial Surveillance](#commercial)
- [Mobile Device Surveillane](#mobile)
- [Web-based Surveillance](#web)
- [OPSEC(Specifically)](#opsec)

-----------------------------------------------------------------------------------------------------------------------------
### <a name="general"></a>General
* **101**
	* [A Guide to Law Enforcement Spying Technology - EFF](https://www.eff.org/sls)
	* [Anonymity](https://en.wikipedia.org/wiki/Anonymity)
	* [Operations Security - Wikipedia](https://en.wikipedia.org/wiki/Operations_security)
	* [Selected Papers in Anonymity - Anonymity Bibliography](https://www.freehaven.net/anonbib/)
* **General**
	* [OS X Security and Privacy Guide](https://github.com/drduh/OS-X-Security-and-Privacy-Guide)
	* [Bugger - Adam Curtis](http://www.bbc.co.uk/blogs/adamcurtis/entries/3662a707-0af9-3149-963f-47bea720b460)
		* Maybe the real state secret is that spies aren't very good at their jobs and don't know much about the world
	* [Mobile Phone Data lookup](https://medium.com/@philipn/want-to-see-something-crazy-open-this-link-on-your-phone-with-wifi-turned-off-9e0adb00d024)
	* [Privacy Online Test And Resource Compendium](https://github.com/CHEF-KOCH/Online-Privacy-Test-Resource-List/blob/master/README.md)
	* [Winning and Quitting the Privacy Game What it REALLY takes to have True Privacy in the 21st Century - Derbycon 7](https://www.youtube.com/watch?v=bxQSu06yuZc)
	* [We Should All Have Something To Hide - Moxie Marlinspike](https://moxie.org/blog/we-should-all-have-something-to-hide/)
	* ['I've Got Nothing to Hide' and Other Misunderstandings of Privacy](http://papers.ssrn.com/sol3/papers.cfm?abstract_id=998565&)
		* We live in a surveillance state. Law enforcement and intelligence agencies have access to a huge amount of data about us, enabling them to learn intimate, private details about our lives. In part, the ease with which they can obtain such information reflects the fact that our laws have failed to keep up with advances in technology. However, privacy enhancing technologies can offer real protections even when the law does not. That intelligence agencies like the NSA are able to collect records about every telephone call made in the United States, or engage in the bulk surveillance of Internet communications is only possible because so much of our data is transmitted in the clear. The privacy enhancing technologies required to make bulk surveillance impossible and targeted surveillance more difficult already exist. We just need to start using them.
	* [The Gruqgs blog](http://grugq.tumblr.com/)
	* [How to Cover Your Tracks - ouah.org](http://www.ouah.org/cover_your_tracks1.html)
	* [Becoming Virtually Untraceable (Eps1.0_B4s!c_T3chn1qu3s.onion) - Ian Barwise](https://medium.com/@IanBarwise/becoming-virtually-untraceable-part-1-e8470ae60745)
	* [The Dating Brokers: An autopsy of online love - Joana Moll, Tactical Tech](https://datadating.tacticaltech.org/viz)
* **Advertising**<a name="advertising"></a>
	* [Powering ads and analytics innovations with machine learning - Google Adwords Blog(2017)](https://adwords.googleblog.com/2017/05/powering-ads-and-analytics-innovations.html)
	* [Google Now Tracks Your Credit Card Purchases and Connects Them to Its Online Profile of You - Michael Reilly(2017)](https://www.technologyreview.com/2017/05/25/242717/google-now-tracks-your-credit-card-purchases-and-connects-them-to-its-online-profile-of-you/)
	* [Google and Mastercard Cut a Secret Ad Deal to Track Retail Sales - Mark Bergen, Jennifer Surane(2018)](https://www.bloomberg.com/news/articles/2018-08-30/google-and-mastercard-cut-a-secret-ad-deal-to-track-retail-sales)
* **Android/iOS/Mobile**<a name="mobile"></a>
	* [Click and Dragger: Denial and Deception on Android mobile](https://www.slideshare.net/grugq/mobile-opsec/34-WHAT_ARETHEY_GOOD_FOR_Threat)
	* [DEFCON 20: Can You Track Me Now? Government And Corporate Surveillance Of Mobile Geo-Location Data](https://www.youtube.com/watch?v=NjuhdKUH6U4)
	* [Can you track me now? - Defcon20](https://wEww.youtube.com/watch?v=DxIF66Tcino)
	* [Phones and Privacy for Consumers - Matt Hoy (mattrix) and David Khudaverdyan (deltaflyer)](http://www.irongeek.com/i.php?page=videos/grrcon2015/submerssion-therapy05-phones-and-privacy-for-consumers-matt-hoy-mattrix-and-david-khudaverdyan-deltaflyerhttps://ritter.vg/blog-deanonymizing_amm.html)
	* [Hacking FinSpy - a Case Study - Atilla Marosi - Troopers15](https://www.youtube.com/watch?v=Mb4mfBi06K4)
* **Communication Security**<a name="comsec"></a>
	* **Articles/Blogposts/Writeups**
		* [A Study of COMINT Personnel Security Standards and Practices](https://www.cia.gov/library/readingroom/document/cia-rdp82s00527r000100060014-6)
		* [COMSEC Beyond Encryption](https://grugq.github.io/presentations/COMSEC%20beyond%20encryption.pdf)
		* [I don't trust Signal - Drew DeVault](https://drewdevault.com/2018/08/08/Signal.html)
			* Making promises about security without explaining the tradeoffs you made in order to appeal to the average user is unethical. Tradeoffs are necessary - but self-serving tradeoffs are not, and it’s your responsibility to clearly explain the drawbacks and advantages of the tradeoffs you make. If you make broad and inaccurate statements about your communications product being “secure”, then when the political prisoners who believed you are being tortured and hanged, it’s on you. The stakes are serious. Let me explain why I don’t think Signal takes them seriously.
	* **Talks/Presentations/Videos**
		* [NSA operation ORCHESTRA: Annual Status Report(2014) - Poul-Henning Kamp - FOSDEM14](https://www.youtube.com/watch?v=fwcl17Q0bpk&feature=youtu.be)
	* **Tools**
		* **XMPP**
			* **101**
				* [XMPP - Official page](https://xmpp.org)
					* [About Page](https://xmpp.org/about/technology-overview.html)
					* XMPP is the Extensible Messaging and Presence Protocol, a set of open technologies for instant messaging, presence, multi-party chat, voice and video calls, collaboration, lightweight middleware, content syndication, and generalized routing of XML data.
				* [XMPP - Wikipedia](https://en.wikipedia.org/wiki/XMPP)
			* **Clients**
				* [Conversations.im](https://conversations.im)
					* Conversations is a Jabber/XMPP client for Android 4.0+ smartphones that has been optimized to provide a unique mobile experience.
				* [Converse.js](https://github.com/conversejs/converse.js)
					* Converse is a web based XMPP/Jabber chat client. You can either use it as a webchat app, or you can integrate it into your own website. It's 100% client-side JavaScript, HTML and CSS and the only backend required is a modern XMPP server.
				* [Dino.im](https://dino.im)
					* Dino is a modern open-source chat client for the desktop. It focuses on providing a clean and reliable Jabber/XMPP experience while having your privacy in mind.
				* [Pidgin](https://pidgin.im)
					* Pidgin is a chat program which lets you log into accounts on multiple chat networks simultaneously. This means that you can be chatting with friends on XMPP and sitting in an IRC channel at the same time. Pidgin runs on Windows, Linux, and other UNIX-like operating systems. Looking for Pidgin for OS X? Try Adium! Pidgin is compatible with the following chat networks out of the box: Jabber/XMPP, Bonjour, Gadu-Gadu, IRC, Novell GroupWise Messenger, Lotus Sametime, SILC, SIMPLE, and Zephyr. It can support many more with plugins. Pidgin supports many features of these chat networks, such as file transfers, away messages, buddy icons, custom smileys, and typing notifications. Numerous plugins also extend Pidgin’s functionality above and beyond the standard features.
			* **Servers**
				* [ejabberd](https://github.com/processone/ejabberd)
					* ejabberd is a distributed, fault-tolerant technology that allows the creation of large-scale instant messaging applications. The server can reliably support thousands of simultaneous users on a single node and has been designed to provide exceptional standards of fault tolerance. As an open source technology, based on industry-standards, ejabberd can be used to build bespoke solutions very cost effectively.
				* [Prosody](https://prosody.im)
					* Prosody is a modern XMPP communication server. It aims to be easy to set up and configure, and efficient with system resources. Additionally, for developers it aims to be easy to extend and give a flexible system on which to rapidly develop added functionality, or prototype new protocols. Prosody is open-source software under the permissive MIT/X11 license.
		* **Others**
			* [Tinfoil Chat](https://github.com/maqp/tfc)
				* Tinfoil Chat (TFC) is a FOSS+FHD peer-to-peer messaging system that relies on high assurance hardware architecture to protect users from passive collection, MITM attacks and most importantly, remote key exfiltration. TFC is designed for people with one of the most complex threat models: organized crime groups and nation state hackers who bypass end-to-end encryption of traditional secure messaging apps by hacking the endpoint.
			* [Zulip](https://github.com/zulip/zulip)
				* Zulip is a powerful, open source group chat application that combines the immediacy of real-time chat with the productivity benefits of threaded conversations. Zulip is used by open source projects, Fortune 500 companies, large standards bodies, and others who need a real-time chat system that allows users to easily process hundreds or thousands of messages a day. With over 500 contributors merging over 500 commits a month, Zulip is also the largest and fastest growing open source group chat project.
			* [Jitsi](https://jitsi.org/what-is-jitsi/)
				* Jitsi is a set of open-source projects that allows you to easily build and deploy secure videoconferencing solutions. At the heart of Jitsi are Jitsi Videobridge and Jitsi Meet, which let you have conferences on the internet, while other projects in the community enable other features such as audio, dial-in, recording, and simulcasting.
			* [Retroshare](https://retroshare.cc)
				* Retroshare establish encrypted connections between you and your friends to create a network of computers, and provides various distributed services on top of it: forums, channels, chat, mail... Retroshare is fully decentralized, and designed to provide maximum security and anonymity to its users beyond direct friends. Retroshare is entirely free and open-source software. It is available on Android, Linux, MacOS and Windows. There are no hidden costs, no ads and no terms of service.
			* [Secushare](https://secushare.org)
				* Disclaimer: secushare is a research project that hasn't reached prototype status, yet.
* **Data Collection**<a name="dcollect"></a>
	* [This Time, Facebook Is Sharing Its Employees’ Data: Some of the biggest companies turn over their workers’ most personal information to the troubled credit reporting agency Equifax](https://www.fastcompany.com/40485634/equifax-salary-data-and-the-work-number-database)
	* [No boundaries: Exfiltration of personal data by session-replay scripts](https://freedom-to-tinker.com/2017/11/15/no-boundaries-exfiltration-of-personal-data-by-session-replay-scripts/)
	* [Data release: list of websites that have third-party “session replay” scripts ](https://webtransparency.cs.princeton.edu/no_boundaries/session_replay_sites.html)
	* [.NET Github: .NET core should not SPY on users by default #3093](https://github.com/dotnet/cli/issues/3093)
	* [.NET Github: Revisit Telemetry configuration #6086 ](https://github.com/dotnet/cli/issues/6086)
	* [iTerm2 Leaks Everything You Hover in Your Terminal via DNS Requests](https://www.bleepingcomputer.com/news/security/iterm2-leaks-everything-you-hover-in-your-terminal-via-dns-requests/)
	* [Google Has Quietly Dropped Ban on Personally Identifiable Web Tracking - ProPublica(2016)](https://www.propublica.org/article/google-has-quietly-dropped-ban-on-personally-identifiable-web-tracking)
	* [No boundaries: Exfiltration of personal data by session-replay scripts - Freedom to Tinker](https://freedom-to-tinker.com/2017/11/15/no-boundaries-exfiltration-of-personal-data-by-session-replay-scripts/)
	* [Notes on privacy and data collection of Matrix.org - maxidorius](https://gist.github.com/maxidorius/5736fd09c9194b7a6dc03b6b8d7220d0)
	* [PSA: Go 1.13 Default Module Proxy Privacy - codeengineered.org](https://codeengineered.com/blog/2019/go-mod-proxy-psa/)
	* [Ring Doorbell App Packed with Third-Party Trackers - Bill Buddington(EFF 2020)](https://www.eff.org/deeplinks/2020/01/ring-doorbell-app-packed-third-party-trackers)
* **De-Anonymization**<a name="de-anon"></a>
	* **Articles/Blogposts/Writeups**
		* [De-Anonymizing Alt.Anonymous. Messages - Tom Ritter - Defcon21](https://www.youtube.com/watch?v=_Tj6c2Ikq_E)
		* [De-Anonymizing Alt.Anonymous.Messages](https://ritter.vg/blog-deanonymizing_amm.html)
		* [Defeating and Detecting Browser Spoofing - Browserprint](https://browserprint.info/blog/defeatingSpoofing)
		* [Deanonymizing Windows users and capturing Microsoft and VPN accounts](https://medium.com/@ValdikSS/deanonymizing-windows-users-and-capturing-microsoft-and-vpn-accounts-f7e53fe73834)
		* [De-anonymizing facebook users through CSP](http://www.myseosolution.de/deanonymizing-facebook-users-by-csp-bruteforcing/#inhaltsverzeichnis)
	* **Papers**
		* [Speaker Recognition in Encrypted Voice Streams - Michael Backes,Goran Doychev,Markus Durmuth,Boris Kopf](http://software.imdea.org/~gdoychev/publications/esorics10.pdf)
			* We develop a novel approach for unveiling the identity of speakers who participate in encrypted voice communication, solely by eavesdropping on the encrypted traffic. Our approach exploits the concept of voice activity detection (VAD), a widely used technique for reducing the bandwidth consumption of voice traffic. We show that the reduction of traffic caused by VAD techniques creates patterns in the encrypted traffic, which in turn reveal the patterns of pauses in the underlying voice stream. We show that these patterns are speaker-characteristic, and that they are sufficient to undermine the anonymity of the speaker in encrypted voice communication. In an empirical setup with 20 speakers our analysis is able to correctly identify an unknown speaker in about 48% of all cases. Our work extends and generalizes existing work that exploits variable bit-rate encoding for identifying the conversation language and content of encrypted voice streams)
* **Informative/Educational**<a name="informative"></a>
	* [Bugger - Adam Curtis](http://www.bbc.co.uk/blogs/adamcurtis/entries/3662a707-0af9-3149-963f-47bea720b460)
		* Maybe the real state secret is that spies aren't very good at their jobs and don't know much about the world
	* [Detect Tor Exit doing sniffing by passively detecting unique DNS query (via HTML & PCAP parsing/viewing)](https://github.com/NullHypothesis/exitmap/issues/37)
	* [Dutch-Russian cyber crime case reveals how police tap the internet - ElectroSpaces](http://electrospaces.blogspot.de/2017/06/dutch-russian-cyber-crime-case-reveals.html?m=1)
	* [An Underground education](https://www.slideshare.net/grugq/underground-education-21151795)
	* [How to Spot a Spook](https://cryptome.org/dirty-work/spot-spook.htm)
* **Journalism/Media Publishing**<a name="media"></a>
	* [Information Security For Journalist book - Centre for Investigative Journalism](http://files.gendo.nl/Books/InfoSec_for_Journalists_V1.1.pdf)
	* [Protecting Your Sources When Releasing Sensitive Documents](https://source.opennews.org/articles/how-protect-your-sources-when-releasing-sensitive-/)
* **Network Obfuscation**<a name="obfuscation"></a>
	* [HORNET: High-speed Onion Routing at the Network Layer](http://arxiv.org/pdf/1507.05724v1.pdf)
	* [Decoy Routing: Toward Unblockable Internet Communication](https://www.usenix.org/legacy/events/foci11/tech/final_files/Karlin.pdf)
		* We present decoy routing, a mechanism capable of circumventing common network filtering strategies. Unlike other circumvention techniques, decoy routing does not require a client to connect to a specific IP address (which is easily blocked) in order to provide circumvention. We show that if it is possible for a client to connect to any unblocked host/service, then decoy routing could be used to connect them to a blocked destination without coop- eration from the host. This is accomplished by placing the circumvention service in the network itself – where a single device could proxy traffic between a significant fraction of hosts – instead of at the edge.
	* [obfs4 (The obfourscator)](https://gitweb.torproject.org/pluggable-transports/obfs4.git/tree/doc/obfs4-spec.txt)
		* This is a protocol obfuscation layer for TCP protocols. Its purpose is to keep a third party from telling what protocol is in use based on message contents. Unlike obfs3, obfs4 attempts to provide authentication and data integrity, though it is still designed primarily around providing a layer of obfuscation for an existing authenticated protocol like SSH or TLS.
	* [obfs3 (The Threebfuscator)](https://gitweb.torproject.org/pluggable-transports/obfsproxy.git/tree/doc/obfs3/obfs3-protocol-spec.txt)
		* This is a protocol obfuscation layer for TCP protocols. Its purpose is to keep a third party from telling what protocol is in use based on message contents. Like obfs2, it does not provide authentication or data integrity. It does not hide data lengths. It is more suitable for providing a layer of obfuscation for an existing authenticated protocol, like SSH or TLS. 
* **Online Influence Methods**
	* [The Art of Deception: Training for a New Generation of Online Covert Operations](https://theintercept.com/document/2014/02/24/art-deception-training-new-generation-online-covert-operations/)
	* [How Covert Agents Infiltrate the Internet to Manipulate, Deceive, and Destroy Reputations - TheIntercept](https://theintercept.com/2014/02/24/jtrig-manipulation/)
* **Reference/Resources**<a name="ref"></a>
	* [The Paranoid's Bible: An anti-dox effort.](https://paranoidsbible.tumblr.com/)
	* [Debian-Privacy-Server-Guide](https://github.com/drduh/Debian-Privacy-Server-Guide)
		* This is a step-by-step guide to configuring and managing a domain, remote server and hosted services, such as VPN, a private and obfuscated Tor bridge, and encrypted chat, using the Debian GNU/Linux operating system and other free software.
	* [Anonymous’s Guide to OpSec](http://www.covert.io/research-papers/security/Anonymous%20Hacking%20Group%20--%20OpNewblood-Super-Secret-Security-Handbook.pdf)
	* [Extreme Privacy: What it takes to disappear in America; Personal Data Removal Workbook & Credit Freeze Guide(Nov2019)](https://inteltechniques.com/data/workbook.pdf)
* **Steganography**
	* [When steganography stops being cool - David Sancho(BSides LV 2015)](http://www.irongeek.com/i.php?page=videos/bsideslasvegas2015/gt01-when-steganography-stops-being-cool-david-sancho)
		* The art and science of concealing stuff inside other stuff is what we know as steganography. People have used it for ages to keep adversaries from looking at their secret information. In this presentation, we look specifically at malware writers and how they are using steganography to hide malicious data in strange places.
* **Tool Configuration**
	* [How to stop Firefox from making automatic connections](https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections)
* **Tor**<a name="tor"></a>
	* **101**
		* [Tor - Wikipedia](https://en.wikipedia.org/wiki/Tor_(anonymity_network))
		* [Onion Routing](https://www.onion-router.net/History.html)
		* [Tor Project Overview](https://www.torproject.org/about/overview.html.en)
		* [Tor Official FAQ](https://www.torproject.org/docs/faq.html.en)
		* [Tor Official Documentation](https://www.torproject.org/docs/documentation.html.en)
		* [Tor Wiki](https://trac.torproject.org/projects/tor/wiki)
	* **Articles/Blogposts/Writeups**
		* [Trawling Tor Hidden Service – Mapping the DHT](https://donncha.is/2013/05/trawling-tor-hidden-services/)
		* [How Tor Users Got Caught by Government Agencies](http://se.azinstall.net/2015/11/how-tor-users-got-caught.html)
	* **Talks/Presentations/Videos**
		* [How Tor Users Got Caught - Defcon 22](https://www.youtube.com/watch?v=7G1LjQSYM5Q)
			* [Part 2](https://www.youtube.com/watch?v=TQ2bk9kMneI)
		* [Deep Dive Into Tor Onion Services - David Goulet](https://www.youtube.com/watch?v=AkoyCLAXVsc)
	* **Tools**
		* [Nipe](https://github.com/GouveaHeitor/nipe)
			* Nipe is a script to make Tor Network your default gateway.
		* [P.O.R.T.A.L.](https://github.com/grugq/portal)
			* PORTAL is a project that aims to keep people out of jail. It is a dedicated hardware device (a router) which forces all internet traffic to be sent over the Tor network. This significantly increases the odds of using Tor effectively, and reduces the potential to make fatal mistakes.
		* [PORTAL of Pi](https://github.com/grugq/PORTALofPi)
			* This will guide you through configuring an Arch based RaspberryPi installation which transparently forwards all TCP traffic over the Tor network. There is also a Tor SOCKS proxy for explicitly interacting with the Tor network, either for more security, or to access a Hidden Service.
		* [Bine](https://github.com/cretz/bine)
			* Bine is a Go API for using and controlling Tor. It is similar to Stem.
		* [Nyx](https://nyx.torproject.org)
			* Nyx is a command-line monitor for Tor. With this you can get detailed real-time information about your relay such as bandwidth usage, connections, logs, and much more.
		* [stem](https://stem.torproject.org)
			* Stem is a Python controller library for Tor. With it you can use Tor's control protocol to script against the Tor process, or build things such as Nyx.
		* [OnionShare](https://github.com/micahflee/onionshare)
			* OnionShare is an open source tool for securely and anonymously sending and receiving files using Tor onion services. It works by starting a web server directly on your computer and making it accessible as an unguessable Tor web address that others can load in Tor Browser to download files from you, or upload files to you. It doesn't require setting up a separate server, using a third party file-sharing service, or even logging into an account. Unlike services like email, Google Drive, DropBox, WeTransfer, or nearly any other way people typically send files to each other, when you use OnionShare you don't give any companies access to the files that you're sharing. So long as you share the unguessable web address in a secure way (like pasting it in an encrypted messaging app), no one but you and the person you're sharing with can access the files.
	* **Papers**
		* [SkypeMorph: Protocol Obfuscation for Tor Bridges](https://www.cypherpunks.ca/~iang/pubs/skypemorph-ccs.pdf)
			* The Tor network is designed to provide users with low- latency anonymous communications. Tor clients build circuits with publicly listed relays to anonymously reach their destinations. However, since the relays are publicly listed, they can be easily blocked by censoring adversaries. Consequently, the Tor project envisioned the possibility of unlisted entry points to the Tor network, commonly known as bridges. We address the issue of preventing censors from detecting the bridges by observing the communications between them and nodes in their network. We propose a model in which the client obfuscates its messages to the bridge in a widely used protocol over the Inter- net. We investigate using Skype video calls as our target protocol and our goal is to make it difficult for the censor- ing adversary to distinguish between the obfuscated bridge connections and actual Skype calls using statistical compar- isons. We have implemented our model as a proof-of-concept pluggable transport for Tor, which is available under an open-source licence. Using this implementation we observed the obfuscated bridge communications and compared it with those of Skype calls and presented the results.
		* [StegoTorus: A Camouflage Proxy for the Tor Anonymity System](https://research.owlfolio.org/pubs/2012-stegotorus.pdf)
			* Internet censorship by governments is an increasingly common practice worldwide. Internet users and censors are locked in an arms race: as users find ways to evade censorship schemes, the censors develop countermeasures for the evasion tactics. One of the most popular and effective circumvention tools, Tor, must regularly adjust its network traffic signature to remain usable. We present StegoTorus, a tool that comprehensively disguises Tor from protocol analysis. To foil analysis of packet contents, Tor’s traffic is steganographed to resemble an innocuous cover protocol, such as HTTP. To foil analysis at the transport level, the Tor circuit is distributed over many shorter-lived connections with per-packet characteristics that mimic cover-protocol traffic. Our evaluation demonstrates that StegoTorus improves the resilience of Tor to fingerprinting attacks and delivers usable performance.
		* [Spoiled Onions](https://www.cs.kau.se/philwint/spoiled_onions/)
			* In this research project, we were monitoring all exit relays for several months in order to expose, document, and thwart malicious or misconfigured relays. In particular, we monitor exit relays with two scanners we developed specifically for that purpose: exitmap and HoneyConnector. Since September 2013, we discovered 65 malicious or misconfigured exit relays which are listed in Table 1 and Table 2 in our research paper. These exit relays engaged in various attacks such as SSH and HTTPS MitM, HTML injection, SSL stripping, and traffic sniffing. We also found exit relays which were unintentionally interfering with network traffic because they were subject to DNS censorship. 
		* [Breaking and (Partially) Fixing Provably Secure Onion Routing - Christiane Kuhn, Martin Beck, Thorsten Strufe](https://arxiv.org/abs/1910.13772)
			* After several years of research on onion routing, Camenisch and Lysyanskaya, in an attempt at rigorous analysis, defined an ideal functionality in the universal composability model, together with properties that protocols have to meet to achieve provable security. A whole family of systems based their security proofs on this work. However, analyzing HORNET and Sphinx, two instances from this family, we show that this proof strategy is broken. We discover a previously unknown vulnerability that breaks anonymity completely, and explain a known one. Both should not exist if privacy is proven correctly. In this work, we analyze and fix the proof strategy used for this family of systems. After proving the efficacy of the ideal functionality, we show how the original properties are flawed and suggest improved, effective properties in their place. Finally, we discover another common mistake in the proofs. We demonstrate how to avoid it by showing our improved properties for one protocol, thus partially fixing the family of provably secure onion routing protocols.
* **Travel**<a name="travel"></a>
	* [China travel laptop setup](https://mricon.com/i/travel-laptop-setup.html?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&iid=88d246896d384d5292f51df954a2c8ba&uid=150127534&nid=244+272699400)
* **Misc/Unsorted**
	* [Cat Videos and the Death of Clear Text](https://citizenlab.org/2014/08/cat-video-and-the-death-of-clear-text/)
	* [You Are Being Tracked: How License Plate Readers Are Being Used to Record Americans' Movements - ACLU](https://www.aclu.org/other/you-are-being-tracked-how-license-plate-readers-are-being-used-record-americans-movements?redirect=technology-and-liberty/you-are-being-tracked-how-license-plate-readers-are-being-used-record)
	* [A Technical Description of Psiphon](https://psiphon.ca/en/blog/psiphon-a-technical-description)
	* [LMGTFY-queries](https://github.com/ctrlaltdev/LMGTFY-queries)
		* You might be familiar with the website Let Me Google That For You - which allow someone to send a passive aggressive link to someone too lazy to seach online by themself - well LMGTFY allow you to shorten this link and it appears that the URLs created are sequencial! So, naturally, someone had to poll those URLs to obtain all the queries.
	* **Papers**
		* [Deep-Spying: Spying using Smartwatch and Deep Learning - Tony Beltramelli](https://arxiv.org/pdf/1512.05616v1.pdf)
* **Windows**
	* [Manage connection endpoints for Windows 10 Enterprise, version 1809 - MS github](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/privacy/manage-windows-1809-endpoints.md)
		* List of some data collections in Win10
	* [Manage connections from Windows operating system components to Microsoft services - docs.ms](https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
* **Miscellaneous**<a name="misc"></a>
* **Miscellaneous Tools**<a name="misc-tools"></a>
	* [FakeNameGenerator](http://www.fakenamegenerator.com/)
	* [MAT: Metadata Anonymisation Toolkit](https://mat.boum.org/) 
		* MAT is a toolbox composed of a GUI application, a CLI application and a library.
	* [fteproxy](https://fteproxy.org/about)
		* fteproxy is fast, free, open source, and cross platform. It has been shown to circumvent network monitoring software such as bro, YAF, nProbe, l7-filter, and appid, as well as closed-source commercial DPI systems
	* [Streisand](https://github.com/jlund/streisand)
		* Streisand sets up a new server running L2TP/IPsec, OpenSSH, OpenVPN, Shadowsocks, sslh, Stunnel, and a Tor bridge. It also generates custom configuration instructions for all of these services. At the end of the run you are given an HTML file with instructions that can be shared with friends, family members, and fellow activists.
	* [exitmap](https://github.com/NullHypothesis/exitmap)
		* Exitmap is a fast and modular Python-based scanner for Tor exit relays. Exitmap modules implement tasks that are run over (a subset of) all exit relays. If you have a background in functional programming, think of exitmap as a map() interface for Tor exit relays. Modules can perform any TCP-based networking task; fetching a web page, uploading a file, connecting to an SSH server, or joining an IRC channel.
	* [OnionCat - an Anonymous VPN adapter](https://www.onioncat.org/about-onioncat/)
	* [howmanypeoplearearound](https://github.com/schollz/howmanypeoplearearound)
		*  Count the number of people around you 👨‍👨‍👦 by monitoring wifi signals 📡
	* [Decentraleyes - FF Addon](https://addons.mozilla.org/en-US/firefox/addon/decentraleyes/)
		* Protects you against tracking through "free", centralized, content delivery. It prevents a lot of requests from reaching networks like Google Hosted Libraries, and serves local files to keep sites from breaking. Complements regular content blockers.
	* [Decentraleyes - Github](https://github.com/Synzvato/decentraleyes)
		* A web browser extension that emulates Content Delivery Networks to improve your online privacy. It intercepts traffic, finds supported resources locally, and injects them into the environment. All of this happens automatically, so no prior configuration is required.
	* [Destroy-Windows-10-Spying](https://github.com/Nummer/Destroy-Windows-10-Spying)
		* Destroy Windows Spying tool
	* [meek](https://github.com/Yawning/meek)
		* meek is a blocking-resistant pluggable transport for Tor. It encodes a data stream as a sequence of HTTPS requests and responses. Requests are reflected through a hard-to-block third-party web server in order to avoid talking directly to a Tor bridge. HTTPS encryption hides fingerprintable byte patterns in Tor traffic.sek
	* [HTTPLeaks](https://github.com/cure53/HTTPLeaks)
		* HTTPLeaks - All possible ways, a website can leak HTTP requests
	* [haven](https://guardianproject.github.io/haven/)
		* Android application that leverages on-device sensors to provide monitoring and protection of physical spaces.
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### <a name="anonymity"></a>Achieving Anonymity
* **Articles**
	* [The $19.95 anonymous cyber profile - Patrick Matthews(Derbycon2019)](https://www.youtube.com/watch?v=ZzIAguDCFZM)
		* The presentation: ?The $19.95 anonymous cyber profile? is a walkthrough of how to create an almost untraceable cyber profile for threat hunting and red team engagements using prepaid debit cards or cash to create anonymous profiles, companies, infrastructure and business services.
* **Talks/Videos/Presentations**
	* 
-----------------------------------------------------------------------------------------------------------------------------



	
	
	
		https://www.eff.org/pages/cell-site-simulatorsimsi-catchers
	https://github.com/EFForg/crocodilehunter
	https://www.theguardian.com/us-news/2020/dec/15/revealed-china-suspected-of-spying-on-americans-via-caribbean-phone-networks
	
	
-----------------------------------------------------------------------------------------------------------------------------
### <a name="cellular"></a>Cellular-Device Surveillance
* **Articles**
	* [Carpenter v. United States - Wikipedia](https://en.wikipedia.org/wiki/Carpenter_v._United_States)
	* [FBI taps cell phone mic as eavesdropping tool - Declan McCullagh(2006)](https://www.cnet.com/news/fbi-taps-cell-phone-mic-as-eavesdropping-tool/)
		* "Agency used novel surveillance technique on alleged Mafioso: activating his cell phone's microphone and then just listening. "
	* [Documents: Texas National Guard Installed Cellphone Spying Devices on Surveillance Planes - G.W. Schulz, Melissa del Bosque(2017)](https://www.texasobserver.org/texas-national-guard-spying-devices-surveillance/)
	* [Qualcomm iZat and baseband location tracking - firmwaresecurity(2018)](https://firmwaresecurity.com/2018/05/18/qualcomm-izat-and-baseband-location-tracking/)
	* [Can tracking people through phone-call data improve lives? - Amy Maxmen(2019)](https://www.nature.com/articles/d41586-019-01679-5)
		* "Researchers have analysed anonymized phone records of tens of millions of people in low-income countries. Critics question whether the benefits outweigh the risks."
	* [Popular iOS SDK Accused of Spying on Billions of Users and Committing Ad Fraud - Ravie Lakshmanan(2020)](https://thehackernews.com/2020/08/ios-sdk-ad-fraud.html)
	* [IRS Could Search Warrantless Location Database Over 10,000 Times - Joseph Cox(2020)](https://www.vice.com/en/article/m7agpa/irs-location-data-venntel-contract)
		* "Motherboard obtained IRS documents describing the sale of a database of smartphone movements."
	* [FBI Expands Ability to Collect Cellphone Location Data, Monitor Social Media, Recent Contracts Show - Lee Fang(2020)](https://theintercept.com/2020/06/24/fbi-surveillance-social-media-cellphone-dataminr-venntel/)
		* "Recent contracts with Dataminr and Venntel show a growing focus on harnessing the latest private sector tools for mass surveillance."
	* [Smartphones can tell when you're drunk by analyzing your walk - Journal of Studies on Alcohol and Drugs(2020)](https://www.eurekalert.org/pub_releases/2020-08/joso-sct081120.php#.XztzZn6lA8I.wordpress)
	* [5G: The outsourced elephant in the room - Bert Hubert(2020)](https://berthub.eu/articles/posts/5g-elephant-in-the-room/)
	* [Intelligence Analysts Use U.S. Smartphone Location Data Without Warrants, Memo Says - Charlie Savage(2021)](https://www.nytimes.com/2021/01/22/us/politics/dia-surveillance-data.html)
	* [Security News This Week: How the FBI Finally Got Into the San Bernardino Shooter’s iPhone - Lily Hay Newman(2021)](https://www.wired.com/story/fbi-iphone-solarwinds-security-news/)
	* [A Hacker Got All My Texts for $16 - Jospeh Cox(2021)](https://www.vice.com/en/article/y3g8wb/hacker-got-my-texts-16-dollars-sakari-netnumber)
		* "A gaping flaw in SMS lets hackers take over phone numbers in minutes by simply paying a company to reroute text messages."
* **Talks/Videos/Presentations**
	* [PHONOPTICON - leveraging low-rent mobile ad services to achieve state-actor level mass surveillance on a shoestring budget - Mark Milhouse(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/track-4-14-phonopticon-leveraging-low-rent-mobile-ad-services-to-achieve-state-actor-level-mass-surveillance-on-a-shoestring-budget-mark-milhouse)
		* By now we all know that mobile advertisements aren't secure. How would an attacker take advantage of that, though, and spy on people without their consent, knowledge or interaction, and how do we defend against it? Let's take a journey through the demand-side of advertising as we put ourselves in the role of an attacker, build an ad-based surveillance system, and unleash it on the masses. I'll demonstrate how, using the built-in features of advertising Demand Side Platforms (DSPs), it's easy to build a surveillance system that can track unsuspecting people. I'll demonstrate that some platforms make it much easier than it needs to be, and I'll show that there's more than just geo-locations at risk here. Finally I will discuss some ways that everyone can help mitigate this, from the users, all the way up to the ad networks and software developers. Like every good spy story, this one includes Russian ad networks, hastily written code, and GPS coordinates - lots of GPS coordinates. By now if you're still clinging desperately to the hope that your location is safe then this talk is for you!
* **Papers**
	* [Evolution of Positioning Techniques in Cellular Networks, from 2G to 4G - Rafael Saraiva Campos(2016)](https://www.hindawi.com/journals/wcmc/2017/2315036/)
		* This review paper presents within a common framework the mobile station positioning methods applied in 2G, 3G, and 4G cellular networks, as well as the structure of the related 3GPP technical specifications. The evolution path through the generations is explored in three steps at each level: first, the new network elements supporting localization features are introduced; then, the standard localization methods are described; finally, the protocols providing specific support to mobile station positioning are studied. To allow a better understanding, this paper also brings a brief review of the cellular networks evolution paths.
* **Tools**
	* [cellscan](https://github.com/jcrawfordor/cellscan)
		* Mobile sensor to collect data useful in detecting use of IMSI catcher ("Stingray") devices. Loosely based on Project Seaglass from UWashington but with reduced cost/complexity. Still very much a work in progress but "minimum viable" and running in my truck right now. 
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### <a name="counter"></a>Counter Surveillance
* **Articles**
	* [NCCA Polygraph Countermeasure Course Files Leaked](https://antipolygraph.org/blog/2018/06/09/ncca-polygraph-countermeasure-course-files-leaked/)
	* [How a Bitcoin Evangelist Made Himself Vanish, in 15 (Not So Easy) Steps - Nathaniel Popper](https://www.nytimes.com/2019/03/12/technology/how-to-disappear-surveillance-state.html)
	* [How to Purge Google and Start Over – Part 2 - Mike Felch](https://www.blackhillsinfosec.com/how-to-purge-google-and-start-over-part-2/)
	* [How to explain the KGB's amazing success identifying CIA agents in the field? - Jonathan Haslam](https://www.salon.com/2015/09/26/how_to_explain_the_kgbs_amazing_success_identifying_cia_agents_in_the_field/)
		* Paranoid CIA heads blamed Soviet moles, but the real reason for the repeated disasters was much simpler [Poor opsec, repeating behaviours, etc.]
	* [The Spy and the Traitor: The Greatest Espionage Story of the Cold War - cia.gov](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/csi-studies/studies/vol-63-no-1/spy_and_traitor.html)
	* [The Spy and the Traitor: The Greatest Espionage Story of the Cold War - Ben MacIntyre/CIA Archive](https://web.archive.org/web/20201019201101/https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/csi-studies/studies/vol-63-no-1/spy_and_traitor.html)
* **Writeups**<a name="cwriteup"></a>
	* Detecting Surveillance - Spiderlabs blog
		* [1 Hardware Implants](http://blog.spiderlabs.com/2014/03/detecting-surveillance-state-surveillance-part-1-hardware-impants.html)
		* [2 Radio Frequency Exfiltration](http://blog.spiderlabs.com/2014/03/detecting-a-surveillance-state-part-2-radio-frequency-exfiltration.html)
		* [3 Infected Firmware](http://blog.spiderlabs.com/2014/04/detecting-a-surveillance-state-part-3-infected-firmware.html)
	* [A Simple Guide to TSCM Sweeps](http://www.international-intelligence.co.uk/tscm-sweep-guide.html)
	* [Dutch-Russian cyber crime case reveals how police tap the internet - ElectroSpaces](http://electrospaces.blogspot.de/2017/06/dutch-russian-cyber-crime-case-reveals.html?m=1)
* **Presentations/Talks/Videos**<a name="cvideos"></a>
	* **General**
		* [PISSED: Privacy In a Surveillance State Evading Detection - Joe Cicero - CYPHERCON11 ](https://www.youtube.com/watch?v=keA3WcKwZwA)
		* [Fuck These Guys: Practical Countersurveillance Lisa Lorenzin - BsidesSF15](http://www.irongeek.com/i.php?page=videos/bsidessf2015/201-fck-these-guys-practical-countersurveillance-lisa-lorenzin)
			* We've all seen the steady stream of revelations about the NSA's unconstitutional, illegal mass surveillance. Seems like there's a new transgression revealed every week! I'm getting outrage fatigue. So I decided to fight back... by looking for practical, realistic, everyday actions I can take to protect my privacy and civil liberties on the Internet, and sharing them with my friends. Join me in using encryption and privacy technology to resist eavesdropping and tracking, and to start to opt out of the bulk data collection that the NSA has unilaterally decided to secretly impose upon the world. Let's take back the Internet, one encrypted bit at a time.
		* [Dr. Philip Polstra - Am I Being Spied On?](https://www.youtube.com/watch?v=Bc7WoDXhcjM)
			* Talk on cheap/free counter measures
		* [Espionage In The Modern Age of Information Warfare - Scot Terban](https://www.irongeek.com/i.php?page=videos/circlecitycon2018/circle-city-con-50-100-espionage-in-the-modern-age-of-information-warfare-scot-terban)
			* [Slides](https://krypt3ia.files.wordpress.com/2018/06/espionge-in-the-modern-age-of-information-warfare.pdf)
	* **Facial/Person Identification**
		* [Fooling automated surveillance cameras: adversarial patches to attack person detection - Simen Thys, Wiebe Van Ranst, Toon Goedemé](https://arxiv.org/abs/1904.08653)
			* Adversarial attacks on machine learning models have seen increasing interest in the past years. By making only subtle changes to the input of a convolutional neural network, the output of the network can be swayed to output a completely different result. The first attacks did this by changing pixel values of an input image slightly to fool a classifier to output the wrong class. Other approaches have tried to learn "patches" that can be applied to an object to fool detectors and classifiers. Some of these approaches have also shown that these attacks are feasible in the real-world, i.e. by modifying an object and filming it with a video camera. However, all of these approaches target classes that contain almost no intra-class variety (e.g. stop signs). The known structure of the object is then used to generate an adversarial patch on top of it. In this paper, we present an approach to generate adversarial patches to targets with lots of intra-class variety, namely persons. The goal is to generate a patch that is able successfully hide a person from a person detector. An attack that could for instance be used maliciously to circumvent surveillance systems, intruders can sneak around undetected by holding a small cardboard plate in front of their body aimed towards the surveillance camera. From our results we can see that our system is able significantly lower the accuracy of a person detector. Our approach also functions well in real-life scenarios where the patch is filmed by a camera. To the best of our knowledge we are the first to attempt this kind of attack on targets with a high level of intra-class variety like persons.
	* [Blinding The Surveillance State - Christopher Soghoian - DEF CON 22](https://www.youtube.com/watch?v=pM8e0Dbzopk)
	* [CounterStrike Lawful Interception](https://www.youtube.com/watch?v=7HXLaRWk1SM)
		* This short talk will cover the standards, devices and implementation of a mandatory part of our western Internet infrastructure. The central question is whether an overarching interception functionality might actually put national Internet infrastructure at a higher risk of being attacked successfully. The question is approached in this talk from a purely technical point of view, looking at how LI functionality is implemented by a major vendor and what issues arise from that implementation. Routers and other devices may get hurt in the process.
		* [Slides](http://phenoelit.org/stuff/CSLI.pdf)
	* [Detecting and Defending Against a Surveillance State - Robert Rowley - DEF CON 22](https://www.youtube.com/watch?v=d5jqV06Yijw)
		* [Slides](https://www.defcon.org/images/defcon-22/dc-22-presentations/Rowley/DEFCON-22-Robert-Rowley-Detecting-Defending-Against-Surveillance-State.pdf)
	* [Retail Surveillance / Retail Countersurveillance 50 most unwanted retail surveillance technologies / 50 most wanted countersurveillance technologies](https://media.ccc.de/v/33c3-8238-retail_surveillance_retail_countersurveillance#video&t=1993)
	* [Masquerade: How a Helpful Man-in-the-Middle Can Help You Evade Monitoring** - Defcon22](https://www.youtube.com/watch?v=_KyfJW2lHtk&spfreload=1)
		* Sometimes, hiding the existence of a communication is as important as hiding the contents of that communication. While simple network tunneling such as Tor or a VPN can keep the contents of communications confidential, under active network monitoring or a restrictive IDS such tunnels are red flags which can subject the user to extreme scrutiny. Format-Transforming Encryption FTE can be used to tunnel traffic within otherwise innocuous protocols, keeping both the contents and existence of the sensitive traffic hidden.  However, more advanced automated intrusion detection, or moderately sophisticated manual inspection, raise other red flags when a host reporting to be a laser printer starts browsing the web or opening IM sessions, or when a machine which appears to be a Mac laptop sends network traffic using Windows-specific network settings.  We present Masquerade: a system which combines FTE and host OS profile selection to allow the user to emulate a user-selected operating system and application-set in network traffic and settings, evading both automated detection and frustrating after-the-fact analysis.
		* [Slides](https://www.portalmasq.com/portal-defcon.pdf)
	* [Wagging the Tail:Covert Passive Surveillance - Si, Agent X - DEF CON 26](https://www.youtube.com/watch?v=tYFOXeItRFM)
		* This talk will focus on mobile and foot surveillance techniques used by surveillance teams. It will also include tips on identifying if you are under surveillance and how to make their life difficult.
* **Papers**<a name="cpapers"></a>
	* [Ghostbuster: Detecting the Presence of Hidden Eavesdroppers](https://synrg.csl.illinois.edu/papers/ghostbuster-mobicom18.pdf)
	* [Exploiting Lawful Intercept to Wiretap the Internet](https://www.blackhat.com/presentations/bh-dc-10/Cross_Tom/BlackHat-DC-2010-Cross-Attacking-LawfulI-Intercept-wp.pdf)
		* This paper will review Cisco's architecture for lawful intercept from asecurity perspective. We explain how a number of different weaknesses in its design coupled with publicly disclosed security vulnerabilities could enable a malicious person to access the interface and spy on communications without leaving a trace. We then provide a set of recommendations for the redesign of the interface as well as SNMP authentication in general to better mitigate the security risks. 
	* [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://kpdyer.com/publications/ccs2013-fte.pdf)
		* Deep packet inspection (DPI) technologies provide much needed visibility and control of network traffic using port- independent protocol identification, where a network flow is labeled with its application-layer protocol based on packet contents. In this paper, we provide the first comprehensive evaluation of a large set of DPI systems from the point of view of protocol misidentification attacks, in which adver- saries on the network attempt to force the DPI to mislabel connections. Our approach uses a new cryptographic prim- itive called format-transforming encryption (FTE), which extends conventional symmetric encryption with the ability to transform the ciphertext into a format of our choosing. We design an FTE-based record layer that can encrypt arbitrary application-layer traffic, and we experimentally show that this forces misidentification for all of the evaluated DPI systems. This set includes a proprietary, enterprise-class DPI system used by large corporations and nation-states. We also show that using FTE as a proxy system incurs no latency overhead and as little as 16% bandwidth overhead compared to standard SSH tunnels. Finally, we integrate our FTE proxy into the Tor anonymity network and demon- strate that it evades real-world censorship by the Great Fire- wall of China
	* [Protocol Misidentification Made Easy with Format-Transforming Encryption](https://eprint.iacr.org/2012/494.pdf)
		* Deep packet inspection DPI technologies provide much- needed visibility and control of network traffic using port- independent protocol identification, where a network ow is labeled with its application-layer protocol based on packet contents. In this paper, we provide the most comprehensive evaluation of a large set of DPI systems from the point of view of protocol misidentification attacks, in which adver- saries on the network attempt to force the DPI to mislabel connections. Our approach uses a new cryptographic primitive called format-transforming encryption FTE, which extends conventional symmetric encryption with the ability to transform the ciphertext into a format of our choosing. We design an FTE-based record layer that can encrypt arbi- trary application-layer traffic, and we experimentally show that this forces misidentification for all of the evaluated DPI systems. This set includes a proprietary, enterprise-class DPI system used by large corporations and nation-states. We also show that using FTE as a proxy system incurs no latency overhead and as little as 16% bandwidth overhead compared to standard SSH tunnels. Finally, we integrate our FTE proxy into the Tor anonymity network and demonstrate that it evades real-world censorship by the Great Firewall of China. 
	* [Unblocking the Internet: Social networks foil censors](http://kscope.news.cs.nyu.edu/pub/TR-2008-918.pdf)
		* Many countries and administrative domains exploit control over their communication infrastructure to censor online content. This paper presents the design, im plementation and evaluation of Kaleidoscope , a peer-to-peer system of relays that enables users within a censored domain to access blocked content. The main challenge facing Kaleidoscope is to resist the cens or’s efforts to block the circumvention system itself. Kaleidoscope achieves blocking-resilienc e using restricted service discovery that allows each user to discover a small set of unblocked relays while only exposing a small fraction of relays to the censor. To restrict service discovery, Kaleidoscope leverages a trust network where links reflects real-world social relationships among users and uses a limited advertisement protocol based on random routes to disseminate relay addresses along the trust netwo rk; the number of nodes reached by a relay advertisement should ideally be inversely proportional to the maximum fraction of infiltration and is independent of the network size. To increase service availa bility in large networks with few exit relay nodes, Kaleidoscope forwards the actual data traffic across multiple relay hops without risking exposure of exit relays. Using detailed analysis and simulations, we show that Kaleidoscope provides > 90% service availability even under substantial infiltration (close to 0.5% of edges) and when only 30% of the relay nodes are online. We have implemented and deployed our system on a small scale serving over 100,000 requests to 40 censored users (relatively small user base to realize Kaleidoscope’s anti-blocking guarantees) spread across different countries and administrative domains over a 6-month period
	* [Chipping Away at Censorship Firewalls with User-Generated Content](https://www.usenix.org/legacy/event/sec10/tech/full_papers/Burnett.pdf)
		* Oppressive regimes and even democratic governments restrict Internet access. Existing anti-censorship systems often require users to connect through proxies, but these systems are relatively easy for a censor to discover and block. This paper offers a possible next step in the cen- sorship arms race: rather than relying on a single system or set of proxies to circumvent censorship firewalls, we explore whether the vast deployment of sites that host user-generated content can breach these firewalls. To explore this possibility, we have developed Collage, which allows users to exchange messages through hidden chan- nels in sites that host user-generated content. Collage has two components: a message vector layer for embedding content in cover traffic; and a rendezvous mechanism to allow parties to publish and retrieve messages in the cover traffic. Collage uses user-generated content (e.g. , photo-sharing sites) as “drop sites” for hidden messages. To send a message, a user embeds it into cover traffic and posts the content on some site, where receivers retrieve this content using a sequence of tasks. Collage makes it difficult for a censor to monitor or block these messages by exploiting the sheer number of sites where users can exchange messages and the variety of ways that a mes- sage can be hidden. Our evaluation of Collage shows that the performance overhead is acceptable for sending small messages (e.g., Web articles, email). We show how Collage can be used to build two applications: a direct messaging application, and a Web content delivery system
	* [Cirripede: Circumvention Infrastructure using Router Redirection with Plausible Deniability](http://hatswitch.org/~nikita/papers/cirripede-ccs11.pdf)
		* Many users face surveillance of their Internet communications and a significant fraction suffer from outright blocking of certain destinations. Anonymous communication systems allow users to conceal the destinations they communicate with, but do not hide the fact that the users are using them. The mere use of such systems may invite suspicion, or access to them may be blocked. We therefore propose Cirripede, a system that can be used for unobservable communication with Internet destinations. Cirripede is designed to be deployed by ISPs; it intercepts connections from clients to innocent-looking desti- nations and redirects them to the true destination requested by the client. The communication is encoded in a way that is indistinguishable from normal communications to anyone without the master secret key, while public-key cryptogra- phy is used to eliminate the need for any secret information that must be shared with Cirripede users. Cirripede is designed to work scalably with routers that handle large volumes of traffic while imposing minimal over- head on ISPs and not disrupting existing traffic. This allows Cirripede proxies to be strategically deployed at central lo- cations, making access to Cirripede very difficult to block. We built a proof-of-concept implementation of Cirripede and performed a testbed evaluation of its performance proper- ties
	* [TapDance: End-to-Middle Anticensorship without Flow Blocking](https://jhalderm.com/pub/papers/tapdance-sec14.pdf)
		* In response to increasingly sophisticated state-sponsored Internet censorship, recent work has proposed a new ap- proach to censorship resistance: end-to-middle proxying. This concept, developed in systems such as Telex, Decoy Routing, and Cirripede, moves anticensorship technology into the core of the network, at large ISPs outside the censoring country. In this paper, we focus on two technical obstacles to the deployment of certain end-to-middle schemes: the need to selectively block flows and the need to observe both directions of a connection. We propose a new construction, TapDance, that removes these require- ments. TapDance employs a novel TCP-level technique that allows the anticensorship station at an ISP to function as a passive network tap, without an inline blocking com- ponent. We also apply a novel steganographic encoding to embed control messages in TLS ciphertext, allowing us to operate on HTTPS connections even under asymmetric routing. We implement and evaluate a TapDance proto- type that demonstrates how the system could function with minimal impact on an ISP’s network operations.
	* [Of Moles and Molehunters: A Review of Counterintelligence Literature, 1977-92](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/books-and-monographs/U-Oct%20%201993-%20Of%20Moles%20-%20Molehunters%20-%20A%20Review%20of%20Counterintelligence%20Literature-%201977-92%20-v2.pdf)
	* [Ghostbuster: Detecting the Presence of Hidden Eavesdroppers](https://synrg.csl.illinois.edu/papers/ghostbuster-mobicom18.pdf)
	* [An Alternative Framework for Agent Recruitment: From MICE to RASCLS - Randy Burkett](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/csi-studies/studies/vol.-57-no.-1-a/vol.-57-no.-1-a-pdfs/Burkett-MICE%20to%20RASCALS.pdf)
* **Misc**
	* [Laser Surveillance Defeater - Shomer-Tec](https://www.shomer-tec.com/laser-surveillance-defeater.html)
	* [Granite Island Group](http://tscm.com/)
		* Founded in 1987 and located near Boston Massachusetts, Granite Island Group, is the internationally recognized leader in the field of Electronics Engineering, Technical Surveillance Counter Measures (TSCM), Bug Sweeps, Wiretap Detection, Surveillance Technology, Communications Security (COMSEC), Counter-Intelligence, Technical Security, and Spy Hunting. Granite Island Group provides expert technical, analytical and research capability for the detection, nullification, and isolation of eavesdropping devices, technical surveillance penetrations, technical surveillance hazards, and physical security weaknesses.
* **Tools**
	* [Salamandra](https://github.com/eldraco/Salamandra)
		* Salamandra is a tool to detect and locate spy microphones in closed environments. It find microphones based on the strength of the signal sent by the microphone and the amount of noise and overlapped frequencies. Based on the generated noise it can estimate how close or far away you are from the microphone.
-----------------------------------------------------------------------------------------------------------------------------
	

-----------------------------------------------------------------------------------------------------------------------------
### <a name="disinfo"></a> Disinformation & Propaganda
* **101**
	* [Propaganda(The Book) - Wikipedia](https://en.wikipedia.org/wiki/Propaganda_(book))
		* Propaganda, an influential book written by Edward L. Bernays in 1928, incorporated the literature from social science and psychological manipulation into an examination of the techniques of public communication. Bernays wrote the book in response to the success of some of his earlier works such as Crystallizing Public Opinion (1923) and A Public Relations Counsel (1927). Propaganda explored the psychology behind manipulating masses and the ability to use symbolic action and propaganda to influence politics, effect social change, and lobby for gender and racial equality.[1] Walter Lippman was Bernays' unacknowledged American mentor and his work The Phantom Public greatly influenced the ideas expressed in Propaganda a year later.[2] The work propelled Bernays into media historians' view of him as the "father of public relations."[3]
	* [Toward an Information Operations Kill Chain - Bruce Schneier](https://www.lawfareblog.com/toward-information-operations-kill-chain)
* **Concision**
	* [Concision (media studies) - Wikipedia](https://en.wikipedia.org/wiki/Concision_(media_studies))
		* In media studies, concision is a form of broadcast media censorship by limiting debate and discussion of important topics on the rationale of time allotment.
		* [The Century of the Self - BBC Documentary](https://en.wikipedia.org/wiki/The_Century_of_the_Self)
	* [Accelerating dynamics of collective attention - Philipp Lorenz-Spreen, Bjarke Mørch Mønsted(2019)](https://www.nature.com/articles/s41467-019-09311-w)
		* With news pushed to smart phones in real time and social media reactions spreading across the globe in seconds, the public discussion can appear accelerated and temporally fragmented. In longitudinal datasets across various domains, covering multiple decades, we find increasing gradients and shortened periods in the trajectories of how cultural items receive collective attention. Is this the inevitable conclusion of the way information is disseminated and consumed? Our findings support this hypothesis. Using a simple mathematical model of topics competing for finite collective attention, we are able to explain the empirical data remarkably well. Our modeling suggests that the accelerating ups and downs of popular content are driven by increasing production and consumption of content, resulting in a more rapid exhaustion of limited attention resources. In the interplay with competition for novelty, this causes growing turnover rates and individual topics receiving shorter intervals of collective attention.
	* **Articles/Blogposts/Writeups**
		* [Zersetzung - Wikipedia](https://en.wikipedia.org/wiki/Zersetzung)
			* "Zersetzung (pronounced [t͡sɛɐ̯ˈzɛt͡sʊŋ], German for "decomposition") is a psychological warfare technique used by the Ministry for State Security (Stasi) to repress political opponents in East Germany during the 1970s and 1980s. Zersetzung served to combat alleged and actual dissidents through covert means, using secret methods of abusive control and psychological manipulation to prevent anti-government activities."
		* [CIA's Strategic Intelligence in Iraq - Richard L. Russell(2002)](https://www.jstor.org/stable/798180?seq=1)
		* [ABC News' Amy Robach caught on hot mic saying network spiked Jeffrey Epstein bombshell - Brian Flood](https://www.foxnews.com/media/abc-amy-robach-jeffrey-epstein-hot-mic)
			* "ABC News anchor Amy Robach was recorded on a hot mic claiming the network spiked a story exposing Jeffrey Epstein three years ago. The hot mic outburst was published by Project Veritas, a controversial conservative watchdog group that claimed the tape was leaked by an ABC News insider."
		* [Fake News at 11: A Breif History of Fake News - Action Dan(2020)](https://lockboxx.blogspot.com/2020/05/fake-news-at-11-breif-history-of-fake.html)
		* [Feds are treating BlueLeaks organization as ‘a criminal hacker group,’ documents show - Ali Winston(2020)](https://www.theverge.com/2020/8/13/21365448/blueleaks-dhs-distributed-denial-secrets-dds-ddosecrets-police)
		* [The Lawfare Podcast: Israel’s 'Cyber Unit' and Extra-legal Content Take-downs - Jen Patja Howell(2021)](https://www.lawfareblog.com/lawfare-podcast-israels-cyber-unit-and-extra-legal-content-take-downs)
		* [Sheryl Sandberg and Top Facebook Execs Silenced an Enemy of Turkey to Prevent a Hit to the Company’s Business - Jack Gillum, Justin Elliott(2021)](https://www.propublica.org/article/sheryl-sandberg-and-top-facebook-execs-silenced-an-enemy-of-turkey-to-prevent-a-hit-to-their-business)
			* "Amid a 2018 Turkish military campaign, Facebook ultimately sided with Turkey’s demand to block the page of a mostly Kurdish militia. “I am fine with this,” Sandberg wrote."
		* [New NYPD press officer co-wrote The Intercept Russiagate story that landed source in prison - Ben Norton(2020)](https://thegrayzone.com/2020/05/20/the-intercept-reality-winner-richard-esposito-nypd/)
		* [Biden administration limits what Border Patrol can share with media about migrant surge at border - Julia Ainsley(2021)](https://www.nbcnews.com/politics/immigration/biden-administration-limits-what-border-patrol-can-share-media-about-n1261133)
			* "Restrictions on what border agents can share with the media were passed down verbally, say officials. Some have released videos of the border surge anyway."
		* [No ‘Negative’ News: How China Censored the Coronavirus - Raymond Zhong, Paul Mozur, Jeff Kao, Aaron Krolik](https://www.nytimes.com/2020/12/19/technology/china-coronavirus-censorship.html)
			* "Thousands of internal directives and reports reveal how Chinese officials stage-managed what appeared online in the early days of the outbreak."	
	* **Papers**
		* [Wait, There's Torture in Zootopia?: Examining the Prevalence of Torture in Popular Movies - Casey Delehanty, Erin Kearns(2019)](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=3342908)
* **Disinformation**
	* **Articles/Blogposts/Writeups**
		* [A DC Think Tank Used Fake Social Media Accounts, A Bogus Expert, And Fancy Events To Reach The NSA, FBI, And White House - Craig Silverman(BuzzFeed News)](https://www.buzzfeednews.com/article/craigsilverman/icit-james-scott-think-tank-fake-twitter-youtube#.dnqv2lQJr)
		* [Dezinformatsiya - John Barron](http://www.heretical.com/miscella/dinform.html)
			* John Barron, KGB, Hodder & Stoughton, 1974. In The Penguin Book of Lies, pp. 420-423
		* [25 Rules of Disinformation](http://vigilantcitizen.com/latestnews/the-25-rules-of-disinformation/)
		* [8 Traits of the Disinformationalist](https://calloutjoe.wordpress.com/psyop/eight-traits-of-the-disinformationalist/)
		* [Disinformation of Charlie Hebdo and The Fake BBC Website](http://thetrendythings.com/read/18256)
		* [Counterintelligence, False Flags, Disinformation, and Network Defense - krypt3ia](https://krypt3ia.wordpress.com/2012/10/17/counterintelligence-false-flags-disinformation-and-network-defense/)
		* [Attribution As A Weapon & Marketing Tool: Hubris In INFOSEC & NATSEC](https://krypt3ia.wordpress.com/2014/12/30/attribution-as-a-weapon-marketing-tool-hubris-in-infosec-natsec/)
		* [SyTech’s FSB Document Dump: Owning The Information Space and Disconnecting It - Krytp3ia](https://krypt3ia.wordpress.com/2019/08/03/sytechs-fsb-document-dump-owning-the-information-space-and-disconnecting-it/)
		* [The Gentleperson’s Guide to Forum Spies](http://www.cryptome.org/2012/07/gent-forum-spies.htm)
		* [A Digital World Full of Ghost Armies](http://www.cigtr.info/2015/02/a-digital-world-full-of-ghost-armies.html)
		* [Disinformation demystified - icyphox](https://icyphox.sh/blog/disinfo/)
		* [PsyOps and Socialbots](http://resources.infosecinstitute.com/psyops-and-socialbots/)
		* [Down the Memory Hole: NYT Erases CIA’s Efforts to Overthrow Syria’s Government](https://web.archive.org/web/20150921054800id_/http://fair.org/home/down-the-memory-hole-nyt-erases-cias-efforts-to-overthrow-syrias-government/)
		* [IRA Code Words Spell Real Threat - William Montalbano(LA Times 1997)](https://articles.latimes.com/1997-04-19/news/mn-50393_1_code-words)
		* [‘A man who’s seen society's black underbelly’ Meduza meets ‘Anonymous International’](https://meduza.io/en/feature/2015/02/02/a-man-who-s-seen-society-s-black-underbelly)
		* [The men behind QAnon - Chris Francescani(2020)](https://abcnews.go.com/Politics/men-qanon/story?id=73046374)
		* [How the 1% Scrubs Its Image Online - Rachael Levy(2019)](https://www.wsj.com/articles/how-the-1-scrubs-its-image-online-11576233000)
			* "Prominent figures from Jacob Gottlieb to Betsy DeVos got help from a reputation management firm that can bury image-sensitive Google results by placing flattering content on websites that masquerade as news outlets"
		* [A Global Guide to State-Sponsored Trolling - Michael Riley, Lauren Etter, Bibhudatta Pradhan(2018)](https://www.bloomberg.com/features/2018-government-sponsored-cyber-militia-cookbook/)
	* **General**
		* [A Syllabus of Psychological Warfare - US Gov(1946)](https://collections.nlm.nih.gov/ext/dw/01130770R/PDF/01130770R.pdf)
		* [Information Operations in and around EVE Online - Paul Chamberlain(2009)](https://memeover.arkem.org/2009/12/information-operations-in-and-around.html)
			* "Massively Multiplayer Online Role Playing Games (MMOs) provide a persistent virtual world for players to explore and interact with. CCP’s EVE Online is a science fiction MMO that explicitly encourages conflict between players. Information operation strategies are employed by groups of EVE Online players inside and outside the virtual world to seek tactical and strategic advantage. Players use propaganda, deception, and computer hacking techniques to complement their virtual military and economic operations. This paper examines how information operations are being conducted in and around EVE Online and the effect MMO information operations can have on the greater information environment."
		* [Bots, Trolls, and Warriors: The Modern Adversary Playbook - Andrea Little Limbago(Derbycon2017)](https://www.irongeek.com/i.php?page=videos/derbycon7/s03-bots-trolls-and-warriors-the-modern-adversary-playbook-andrea-little-limbago)
			* Adversaries increasingly integrate "traditional" computer attack vectors with advances in automation and the power of disinformation to reach a wider range of targets and achieve a wider range of objectives. Increasingly, these bots, trolls and warriors are employed simultaneously to achieve strategic impact and surprise. Bots reflect the implementation of automation and machine learning, and manifest in everything from widespread DDoS to malvertising to social bots. Trolls represent groups or individuals who leverage online forums to influence opinions, perspectives, and achieve specific objectives. Finally, cyber warriors are increasingly brazen and leverage both tried and true techniques as well as highly customized attacks. To counter this playbook, defenders must similarly pursue socio-technical innovations. The stakes are high, as it has far-reaching impact on stability, democracy, security and privacy for the foreseeable future.
		* [Fighting Fake News Online (Disinformation) - Action Dan(2020)](https://lockboxx.blogspot.com/2020/08/fighting-fake-news-online-disinformation.html)
		* [Early detection of internet trolls: Introducing an algorithm based on word pairs / single words multiple repetition ratio - Sergei Monakhov(2020)](https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0236832)
    	* [Facebook Closes 5 Accounts Tied to Russia-Like Tactics in Alabama Senate Race - Scott Shane(2018)](https://www.nytimes.com/2018/12/22/us/politics/facebook-suspends-alabama-elections.html)
			* "The group that carried out the operation, composed of tech specialists who leaned Democratic, created a Facebook page on which they posed as conservative Alabamians."
		* [Emilia Seikkanen Worked in a Trendy Video Start-Up in Berlin – Tells All about the Kremlin's Global Information Operation - Jessikka Aro(2021)](https://yle.fi/uutiset/3-11820154)
			* "American in Finland, Emilia Seikkanen, 33, wants to make amends for having worked at Ruptly, Russian state media meddling elections and promoting extremism in the West."
    	* [Industrialized Disinformation: 2020 Global Inventory of Organized Social Media Manipulation - Samantha Bradshaw, Hannah Bailey, Philip N. Howard(2021)](https://demtech.oii.ox.ac.uk/research/posts/industrialized-disinformation/)
    	* [Fighting Disinformation Online - RANDcorp](https://www.rand.org/research/projects/truth-decay/fighting-disinformation.html)
			* Database of tools
		* [Fake News at 11 - A Brief Look at Astroturfing - Dan Borges(2020)](https://www.youtube.com/watch?v=50MI6GYIEfI)
		* [Evaluating the fake news problem at the scale of the information ecosystem - Jennifer Allen, Baird Howland, Markus Mobius, David Rothschild, Duncan J. Watts](https://advances.sciencemag.org/content/6/14/eaay3539)
			* “Fake news,” broadly defined as false or misleading information masquerading as legitimate news, is frequently asserted to be pervasive online with serious consequences for democracy. Using a unique multimode dataset that comprises a nationally representative sample of mobile, desktop, and television consumption, we refute this conventional wisdom on three levels. First, news consumption of any sort is heavily outweighed by other forms of media consumption, comprising at most 14.2% of Americans’ daily media diets. Second, to the extent that Americans do consume news, it is overwhelmingly from television, which accounts for roughly five times as much as news consumption as online. Third, fake news comprises only 0.15% of Americans’ daily media diet. Our results suggest that the origins of public misinformedness and polarization are more likely to lie in the content of ordinary news or the avoidance of news altogether as they are in overt fakery.
	* **Facebook-related**
    		* ["I Have Blood on My Hands”: A Whistleblower Says Facebook Ignored Global Political Manipulation - Craig Silverman, Ryan Mac, Pranav Dixit(2020)](https://www.buzzfeednews.com/article/craigsilverman/facebook-ignore-political-manipulation-whistleblower-memo)
    			* "A 6,600-word internal memo from a fired Facebook data scientist details how the social network knew leaders of countries around the world were using their site to manipulate voters — and failed to act."
	* **Twitter**
    		* [Twitter as a Vector for Disinformation - Paul Chamberlain(2009)](https://memeover.arkem.org/2009/12/twitter-as-vector-for-disinformation.html)
    			* " Twitter is a social network that represents a powerful information channel with the potential to be a useful vector for disinformation. This paper examines the structure of the Twitter social network and how this structure has facilitated the passing of disinformation both accidental and deliberate. Examples of the use of Twitter as an information channel are examined from recent events. The possible effects of Twitter disinformation on the information sphere are explored as well as the defensive responses users are developing to protect against tainted information."
		* [Former Twitter employees charged with spying for Saudi Arabia by digging into the accounts of kingdom critics - Ellen Nakashima, Greg Bensinger(2019)](https://www.washingtonpost.com/national-security/former-twitter-employees-charged-with-spying-for-saudi-arabia-by-digging-into-the-accounts-of-kingdom-critics/2019/11/06/2e9593da-00a0-11ea-8bab-0fc209e065a8_story.html)
			* "The Justice Department has charged two former Twitter employees with spying for Saudi Arabia by accessing the company’s information on dissidents who use the platform, marking the first time federal prosecutors have publicly accused the kingdom of running agents in the United States."
	* **Russian**
		* [Your Facts Are Not Safe With Us: Russian Information Operations as Social Engineering -  Meagan Keim(BSidesNova2018)](https://www.irongeek.com/i.php?page=videos/bsidesnova2018/200-your-facts-are-not-safe-with-us-russian-information-operations-as-social-engineering-meagan-keim)
			* Over the past few years, Russia has proven itself to be an undeniable master of information operations. The techniques vary, but the majority of them focus on creating new realities and subverting Western values. This makes response efforts much more challenging, and Russia’s info ops strategies have become a key part of the arsenal the country draws upon in achieving its aims both at home and abroad. By describing personal experience with a steady diet of state-sponsored propaganda while studying abroad in Russia, and by examining the country’s annexation of the Ukrainian peninsula of Crimea as a case study, I will give you an in-depth look at Russia’s info ops and why they’re so effective. I will explain why it’s useful to frame Russian information operations as large-scale social engineering and the implications that has for mitigating the resulting security problems.
		* [Engaging with others: How the IRA coordinated information operation made friends - Darren L. Linvill, Patrick L. Warren(2020)](https://misinforeview.hks.harvard.edu/article/engaging-ira-coordinated-information-operation/)
			* "We analyzed the Russian Internet Research Agency’s (IRA) 2015–2017 English-language information operation on Twitter to understand the special role that engagement with outsiders (i.e., non-IRA affiliated accounts) played in their campaign. By analyzing the timing and type of engagement of IRA accounts with non-IRA affiliated accounts, and the characteristics of the latter, we identified a three-phases life cycle of such engagement, which was central to how this IRA network operated. Engagement with external accounts was key to introducing new troll accounts, to increasing their prominence, and, finally, to amplifying the messages these external accounts produced."
		* [Russian Disinformation Networks Detailed in New State Department Report - Patrick Tucker(2020)](https://www.defenseone.com/technology/2020/08/russian-disinformation-networks-detailed-new-state-department-report/167537/)
		* [The GRU's MH17 Disinformation Operations Part 1: The Bonanza Media Project - Bellingcat](https://www.bellingcat.com/news/uk-and-europe/2020/11/12/the-grus-mh17-disinformation-operations-part-1-the-bonanza-media-project/)
		* [Soviet Active Measures in the West and the Developing World - psywar.org](https://www.psywar.org/content/sovietActiveMeasures)
		* [Aquarium Leaks. Inside the GRU’s Psychological Warfare Program - Michael Weiss(2020)](https://www.4freerussia.org/aquarium-leaks-inside-the-gru-s-psychological-warfare-program/)
			* "In this exclusive and groundbreaking report, Free Russia Foundation has translated and published five documents from the GRU, Russia’s military intelligence agency."
		* [Inside The 'Propaganda Kitchen' -- A Former Russian 'Troll Factory' Employee Speaks Out - Dmitry Volchek(2021)](https://www.rferl.org/a/russian-troll-factory-hacking/31076160.html)
	* **Campaigns**
		* **2016/2020 USA-Elections related**
			* [Barrier Breakers 2016: A Project of Correct The Record - CorrectTheRecord.org](https://web.archive.org/web/20160421163946/http://correctrecord.org/barrier-breakers-2016-a-project-of-correct-the-record/)
	    	* [Rachel Maddow’s Conspiracy Brain - Willa Paskin(2019)](https://slate.com/culture/2019/03/rachel-maddow-mueller-report-trump-barr.html)
	    	* [Did the media botch the Russia story? A conversation with Matt Taibbi. - Sean Illing(2019)](https://www.vox.com/2019/3/31/18286902/trump-mueller-report-russia-matt-taibbi)
			* [What if Facebook Is the Real ‘Silent Majority’? - Kevin Roose(2020)](https://www.nytimes.com/2020/08/27/technology/what-if-facebook-is-the-real-silent-majority.html)
				* "Right-wing influencers are dominating the political discussion on Facebook, raising questions about whether it will translate into electoral success in November."
		* **Mockingbird**(USA)
			* [Operation Mockingbird - Wikipedia](https://en.wikipedia.org/wiki/Operation_Mockingbird)
				* Operation Mockingbird is an alleged large-scale program of the United States Central Intelligence Agency (CIA) that began in the early years of the Cold War and attempted to manipulate news media for propaganda purposes."
			* [Behind TV Analysts, Pentagon’s Hidden Hand - David Barstow(2008)](https://www.nytimes.com/2008/04/20/us/20generals.html)
			* [Inside Operation Mockingbird — The CIA’s Plan To Infiltrate The Media - Kara Goldfarb(2018)](https://allthatsinteresting.com/operation-mockingbird)
			* [The Spies Who Came in to the TV Studio - Jack Schafer(2018)](https://www.politico.com/magazine/story/2018/02/06/john-brennan-james-claper-michael-hayden-former-cia-media-216943/)
				* "Former intelligence officials are enjoying second acts as television pundits. Here’s why that should bother us."
			* [News networks use retired military brass as war analysts without disclosing their defense-industry ties - Paul Farhi(2020)](https://www.washingtonpost.com/lifestyle/style/news-networks-use-retired-military-brass-as-war-analysts-without-disclosing-their-defense-industry-ties/2020/01/13/7b507bfe-323c-11ea-91fd-82d4e04a3fac_story.html)
			* [CNN let army staff into newsroom - Julian Borger(2000)](https://www.theguardian.com/world/2000/apr/12/julianborger)
				* "Two leading US news channels have admitted that they allowed psychological operations officers from the military to work as placement interns at their headquarters during the Kosovo war."
* **Marketing**
	* [Takedowns and Adventures in Deceptive Affiliate Marketing - Jeff White(2019)](https://unit42.paloaltonetworks.com/takedowns-and-adventures-in-deceptive-affiliate-marketing/)
		* At Palo Alto Networks, Unit 42 analyzes threats across the spectrum – from nation state all the way down to Florida state. In this blog, I’ll be covering two aspects of multi-year affiliate marketing spam campaigns designed to deceive individuals, scam, and profit off of people’s desire to change their lives.
* **Media Companies**
	* [Agenda-setting theory - Wikipedia](https://en.wikipedia.org/wiki/Agenda-setting_theory)
	* [How Roger Ailes Built the Fox News Fear Factory - Tim Dickinson(2011)](https://www.rollingstone.com/politics/politics-news/how-roger-ailes-built-the-fox-news-fear-factory-244652/)
		* "The onetime Nixon operative has created the most profitable propaganda machine in history. Inside America’s Unfair and Imbalanced Network"
	* [Former Fox News commentator sentenced to prison for faking CIA ties - Reuters(2016)](https://www.reuters.com/article/us-twenty-first-fox-crime-analyst-idUSKCN0ZV21Q)
	* [Journalism’s Gates keepers - Tim Schwab(Columbia Journalism Review2020)](https://www.cjr.org/criticism/gates-foundation-journalism-funding.php)
	* [During Floyd protests, media industry reckons with long history of collaboration with law enforcement - Carol A. Stabile (2020)](https://theconversation.com/during-floyd-protests-media-industry-reckons-with-long-history-of-collaboration-with-law-enforcement-140221)
	* [Nearly all Black Lives Matter protests are peaceful despite Trump narrative, report finds - Lois Beckett(2020)](https://www.theguardian.com/world/2020/sep/05/nearly-all-black-lives-matter-protests-are-peaceful-despite-trump-narrative-report-finds)
	* [Reddit For Sale: How We Bought The Top Spot For $200 (reupload) - Point Report](https://www.youtube.com/watch?v=6SAkUs3urrg)
	* [The 2016 POLICE Presidential Poll - David Griffith](https://www.policemag.com/342098/the-2016-police-presidential-poll)
		* [An Oscar Winner Made a Khashoggi Documentary. Streaming Services Didn’t Want It. - Nicole Sperling(2020)](https://www.nytimes.com/2020/12/24/business/media/dissident-jamal-khashoggi-netflix-amazon.html)
		* "Bryan Fogel’s examination of the killing of the Saudi dissident Jamal Khashoggi had trouble finding a home among the companies that can be premier platforms for documentary films."
	* [Sinclair's Soldiers in Trump's War on Media - Deadspin](https://www.youtube.com/watch?v=_fHfgU8oMSo)
		* "Anchors at Sinclair-owned local news station parrot a script pushing Trump talking points and “the troubling trend of irresponsible, one sided news stories plaguing our country.”"
	* ["Mark Changed The Rules": How Facebook Went Easy On Alex Jones And Other Right-Wing Figures - Ryan Mac, Craig Silverman(2021)](https://www.buzzfeednews.com/article/ryanmac/mark-zuckerberg-joel-kaplan-facebook-alex-jones)
		* "Facebook’s rules to combat misinformation and hate speech are subject to the whims and political considerations of its CEO and his policy team leader."
* **Propaganda**
	* **Ads-Based**
		* [I Used Google Ads for Social Engineering. It Worked. - Patrick Berlinquette(2019)](https://www.nytimes.com/2019/07/07/opinion/google-ads.html)
		* [Project Feels: How USA Today, ESPN and The New York Times are targeting ads to mood - digiday](https://digiday.com/media/project-feels-usa-today-espn-new-york-times-targeting-ads-mood/)
		* [The New York Times Advertising & Marketing Solutions Group Introduces ‘nytDEMO’: A Cross-Functional Team Focused on Bringing Insights and Data Solutions to Brands(2018)](https://investors.nytco.com/press/press-releases/press-release-details/2018/The-New-York-Times-Advertising--Marketing-Solutions-Group-Introduces-nytDEMO-A-Cross-Functional-Team-Focused-on-Bringing-Insights-and-Data-Solutions-to-Brands/default.aspx)
	* **China**
		* Geostrategically Motivated Co-Option Of Social Media - The Case Of Chinese LinkedIn Spy Recruitment - Mika Aaltola/Finnish Institute of International Affairs(2019)](https://www.fiia.fi/wp-content/uploads/2019/06/bp267_geostrategically_motivated_co-option_of_social-media.pdf)
		* [How the Chinese Government Fabricates SocialMedia Posts for Strategic Distraction, not Engaged Argument - Gary King, Jennifer Pan, Margaret E. Roberts(2017)](https://gking.harvard.edu/files/gking/files/50c.pdf?m=1463587807)
			* "The Chinese government has long been suspected of hiring as many as 2,000,000people to surreptitiously insert huge numbers of pseudonymous and other deceptivewritings into the stream of real social media posts, as if they were the genuine opinions of ordinary people. Many academics, and most journalists and activists, claimthat these so-called “50c party” posts vociferously argue for the government’s sidein political and policy debates. As we show, this is also true of the vast majority ofposts openly accused on social media of being 50c. Yet, almost no systematic em-pirical evidence exists for this claim, or, more importantly, for the Chinese regime’sstrategic objective in pursuing this activity. In the first large scale empirical analysis of this operation, we show how to identify the secretive authors of these posts,the posts written by them, and their content. We estimate that the government fabri-cates and posts about 448 million social media comments a year. In contrast to priorclaims, we show that the Chinese regime’s strategy is to avoid arguing with skepticsof the party and the government, and to not even discuss controversial issues. Weshow that the goal of this massive secretive operation is instead to distract the publicand change the subject, as most of the these posts involve cheerleading for China,the revolutionary history of the Communist Party, or other symbols of the regime.We discuss how these results fit with what is known about the Chinese censorshipprogram, and suggest how they may change our broader theoretical understanding of“common knowledge” and information control in authoritarian regimes."
		* [How China’s Communist Party trains foreign politicians - TheEconomist(2020)](https://www.economist.com/china/2020/12/10/how-chinas-communist-party-trains-foreign-politicians)
	* **USA**
		* [Southern strategy - Wikipedia](https://en.wikipedia.org/wiki/Southern_strategy)
			* "In American politics, the Southern strategy was a Republican Party electoral strategy to increase political support among white voters in the South by appealing to racism against African Americans. As the civil rights movement and dismantling of Jim Crow laws in the 1950s and 1960s visibly deepened existing racial tensions in much of the Southern United States, Republican politicians such as presidential candidate Richard Nixon and Senator Barry Goldwater developed strategies that successfully contributed to the political realignment of many white, conservative voters in the South who had traditionally supported the Democratic Party rather than the Republican Party."
		* [Theaters Of War: The Military-Entertainment Complex - Tim Lenoir, Henry Lowood(2003)](https://web.stanford.edu/dept/HPST/TimLenoir/Publications/Lenoir-Lowood_TheatersOfWar.pdf)
			* "Building on a brief overview of the history of war games, we will sketch the history of military simulations leading to SIMNET in the late 1980s and projects building on this work through the mid-1990s. Changes in government procurement policies, we argue, led the military to spin off many of its key technologies for simulation and training. Their adoption and further development by the game entertainment industry has resulted in the improvement of tools for designing war games. It has also fueled the growth of the videogame industry, which by several measures has reached the level of film and television in its importance as an entertainment medium. During the Cold War it was customary to critique the military-industrial complex as an economic parasite separated from, but living off the free enterprise system.  We conclude that the new military-entertainment complex of the 1990s has become a partner of the entertainment industry while transforming itself into the training ground for what we might consider the post-human warfare of the future."
		* [Update: U.S. Navy Comments on Twitch Streamer Guidelines - James Fudge(2020)](https://esportsobserver.com/foia-navy-twitch-guidance/)
		* [How the New York Times A/B tests their headlines - TJCX(2021)](https://blog.tjcx.me/p/new-york-times-ab-testing)
			* Part 1 of a series on the New York Times, in which I take a close look at how (and when) the New York Times tests multiple headlines for a single article.
	* **Papers**
		* [The Effects of Participatory Propaganda: From Socialization to Internalization of Conflicts - Gregory Asmolov(2019)](https://jods.mitpress.mit.edu/pub/jyzg7j6x/release/2)
			* "A look at how propaganda has been rewired for the digital age and how this new, “participatory propaganda” mediates conflict, manipulates relationships and creates isolation, both online and offline."
	* **North Korea**
		* [Kim Jong Undead - Dr. Neal Krawetz(2020)](https://www.hackerfactor.com/blog/index.php?/archives/881-Kim-Jong-Undead.html)
	* **Talks/Presentations**
		* [COVID-1984: Propaganda and Surveillance During a Pandemic - Mauro Eldritch](https://www.youtube.com/watch?v=2ldvZVAQHTQ&list=PLruly0ngXhPGvyl-gOp4d_TvIiedloX1l&index=30)
			* "The official political propaganda and digital surveillance in Argentina are not new. However, in the last fifteen years, both phenomena have adopted in their favor a new technological approach worthy of study, with the emergence of companies dedicated to manufacturing online trends; cyber militancy groups aimed at setting up debates, responding to them or denouncing rival trends in a coordinated way; the project to establish an exclusive social network for pro-government and “against the establishment” militants (sponsored by the Government itself); the rise of state digital surveillance after the implementation of a Cyber ​​Patrol Protocol, and the permanent monitoring of citizens through a mandatory mobile government application during the COVID-19 Pandemic. This work aims not only to review the previous events, but also to detail the two greatest milestones of political propaganda and digital surveillance in Argentina today: the political propaganda apparatus on social networks and the digital privacy abuses caused by the government application CUIDAR-COVID19 (ar.gob.coronavirus). For the first case, a fictitious account (sock puppet) will be infiltrated within the propaganda apparatus on social networks to achieve a detailed technical dissection of its entire operation (including its interventions and actors). Our own cyber intelligence tool, Venator.lua, will be used to obtain and process data. The following section will be devoted to the study of privacy abuses caused by the mandatory government application CUIDAR-COVID19, reverse engineering it and analyzing its source code."
		* [Hacking Public Opinion - Renée DiResta(BH2020)](https://www.youtube.com/watch?v=aA_VFXDcVvw&list=PLH15HpR5qRsXE_4kOSy_SXwFkFQre4AV_&index=88)
			* This talk offers an overview of the mechanics of modern-day information operations. Using a deep dive into the tactics behind some of the most impactful recent operations, the speaker will demonstrate the ways in which hacking the information environment is similar and different from the kind of intrusions the audience normally deals with. We will conclude with a look ahead to the 2020 elections and a call-to-action for the audience to deploy their skills in the defense of democracy.
		* [Hacking the Voter: Lessons from a Decade of Russian Military Operations - Nate Beach-Westmoreland(BH2020)](https://www.youtube.com/watch?v=dmXJ6fWUAoM&list=PLH15HpR5qRsXE_4kOSy_SXwFkFQre4AV_&index=32)
			* Election security faces a persistent problem: defenders are often thinking tactically, while the most capable, deliberate adversaries are thinking strategically. Getting ahead of ever evolving election interference operations will require understanding adversaries' long-term goals and how they are shaping their election interference activities to outmaneuver tactical defenses. In this talk, we will look at lessons learned from nearly a decade of election interference activities linked to the Russian military's espionage and special forces agency, the GRU. We will examine how Russia's policy elites believe information has a fundamental role in international relations and how this perspective shapes GRU strategies and tactics.
		* [Meme Hacking: Subverting The IdeoSphere - Broward Horne(DEFCON14)](https://www.youtube.com/watch?v=V1EWgPya-YA&list=PL9fPq3eQfaaAxDI0xo83ZFzDAZgXO3Yhy&index=8)
			* “Meme Hacking – Subverting The IdeoSphere” is a followup and expansion of last year’s “Meme Mining” presentation. It expands upon previous material and shifts from passive data mining to active meme manipulation. Concrete examples and patterns for meme manipulation are demonstrated, including an example of how I legally used active meme propagation to disrupt a former employer. The material ranges from specific tactical examples up to a strategic framework for Meme theory and the possible evolution of memes due to information technology changes.
		* [PLA Information Warfare Development Timeline and Nodal analysis - Zulu Meet(Defcon17)](https://www.youtube.com/watch?v=86uKD_2HkGU)
			* [Slides](https://www.defcon.org/images/defcon-17/dc-17-presentations/defcon-17-tk234-pla_information_warfare.pdf)
			* The development timeline is consistent with the broad contours of China's current IW theory. It showed clearly the footprints of China's common war preparation patterns and People's war concept. For China, IW is a People's War, beyond simple "hacking," and is a long-term strategy that considered a necessary component for total war preparation. China has thus integrated IW units at multiple layers into the civilian and national emergency infrastructure. Also, ten years of practicing suggests that China has developed a mature understanding of IW and methodology, which it is able to quickly deploy and duplicate.
		* [Inside the Fake Science Factory - Svea, Suggy, Till(Defcon26)](https://www.youtube.com/watch?v=ras_VYgA77Q)
			* Fake News has got a sidekick and it's called Fake Science. This talk presents the findings and methodology from a team of investigative journalists, hackers and data scientists who delved into the parallel universe of fraudulent pseudo-academic conferences and journals; Fake science factories, twilight companies whose sole purpose is to give studies an air of scientific credibility while cashing in on millions of dollars in the process. Until recently, these fake science factories have remained relatively under the radar, with few outside of academia aware of their presence; but the highly profitable industry is growing significantly and with it, so are the implications. To the public, fake science is indistinguishable from legitimate science, which is facing similar accusations itself. Our findings highlight the prevalence of the pseudo-academic conferences, journals and publications and the damage they can and are doing to society.
		* [AMITT - Adversarial Misinformation Playbooks - Roger Johnston, Sara-Jayne Terp(NorthSec2020)](https://www.youtube.com/watch?v=OcnaJHYQjE4&list=PLuUtcRxSUZUqhwo0e6j0hrqXifo8jItdl&index=11)
			* We describe the use of adversarial misinformation playbooks to detect and counter disinformation, and explore advances in misinfosec tooling appropriated from the infosec community.  Adversarial Misinformation Influence Tactics and Techniques (AMITT) framework is a common language for describing organized communication attacks.  Misinformation, and more nefariously disinformation, has become a hot button issue as the public and private sector struggle to contain influence operations which threaten to degrade political and social fabrics.  Using well-established information-sharing standards and tooling appropriated from the InfoSec community, we explore the use of the AMITT for the detection and disruption of influence operations. Where response to disinformation has been largely reactive, we discuss left-of-boom operational playbooks and strategies for working with disinformation at scale.
* **Presentations/Talks/Videos**
	* [The Cyberlous Mrs. Maisel: A Comedic (and Slightly Terrifying) Introduction to Information Warfare - Zhanna Malekos Smith](https://cdn.shopify.com/s/files/1/0177/9886/files/phv2019-zmalenkosmith.pdf)
* **Papers**
* **Talks**
	* [Governments and UFOs: A Historical Analysis of Disinformation and Deception - Richard Thieme](http://www.irongeek.com/i.php?page=videos/bsideslasvegas2013/1-2-7-governments-and-ufos-a-historical-analysis-of-disinformation-and-deception-richard-thieme)
	* [[TROOPERS15] Azhar Desai, Marco Slaviero - Weapons of Mass Distraction](https://www.youtube.com/watch?v=jdaPJLJCK1M)
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### <a name="docs"></a> Documents (Phyiscal & Digital) 
* **General**	
	* **Authorship Analysis/Identification**
		* [anonymouth](https://github.com/psal/anonymouth)
			* Document Anonymization Tool, Version 0.5
		* [F⁠ingerprinting documents​ with steganography​](http://blog.fastforwardlabs.com/2017/06/23/fingerprinting-documents-with-steganography.html)
		* [Text Authorship Verification through Watermarking - Stefano Giovanni Rizzo, Flavio Bertini, Danilo Montesi](https://pdfs.semanticscholar.org/4028/f904da8e2c50672e6037168bf2bd72bc4cb9.pdf)
	* **Obfuscation/Making it harder to OCR/Redaction Tactics and Methods**
		* [Redaction of PDF Files Using Adobe Acrobat Professional X - NSA](https://www.cs.columbia.edu/~smb/doc/Redaction-of-PDF-Files-Using-Adobe-Acrobat-Professional-X.pdf)
		* [Why Government Agencies Use Ugly, Difficult to Use Scanned PDFs - There's More Than Meets the Eye - circleid.com](http://www.circleid.com/posts/20180720_why_government_agencies_use_ugly_difficul_to_use_scanned_pdfs/)
	* **Removing Identifying materials**
		* [Remove hidden data and personal information by inspecting documents, presentations, or workbooks - support.office.com](https://support.office.com/en-us/article/remove-hidden-data-and-personal-information-by-inspecting-documents-presentations-or-workbooks-356b7b5d-77af-44fe-a07f-9aa4d085966f)
			* When you share an electronic copy of certain Office documents with clients or colleagues, it is a good idea to review the document for hidden data or personal information. You can remove this hidden information before you share the document with other people. The Document Inspector feature in Word, Excel, PowerPoint, or Visio can help you find and remove hidden data and personal information in documents that you plan to share.
	* **Stegonagraphy**
		* [steganos](https://github.com/fastforwardlabs/steganos)
			* This is a library to encode bits into text.... steganography in text!
		* [Content-preserving Text Watermarking through Unicode Homoglyph Substitution](https://www.researchgate.net/publication/308044170_Content-preserving_Text_Watermarking_through_Unicode_Homoglyph_Substitution)
			* Digital watermarking has become crucially important in authentication and copyright protection of the digital contents, since more and more data are daily generated and shared online through digital archives, blogs and social networks. Out of all, text watermarking is a more difficult task in comparison to other media watermarking. Text cannot be always converted into image, it accounts for a far smaller amount of data (eg. social network posts) and the changes in short texts would strongly affect the meaning or the overall visual form. In this paper we propose a text watermarking technique based on homoglyph characters substitution for latin symbols1. The proposed method is able to efficiently embed a password based watermark in short texts by strictly preserving the content. In particular, it uses alternative Unicode symbols to ensure visual indistinguishability and length preservation, namely content-preservation. To evaluate our method, we use a real dataset of 1.8 million New York articles. The results show the effectiveness of our approach providing an average length of 101 characters needed to embed a 64bit password based watermark.
		* [zwsp-steg](https://github.com/offdev/zwsp-steg-js)
			* Zero-Width Space Steganography. Encodes and decodes hidden messages as non printable/readable characters. [A demo can be found here](https://offdev.net/demos/zwsp-steg-js).
	* **Tracking Ownership**
		* [DEDA](https://github.com/dfd-tud/deda)
			* DEDA - tracking Dots Extraction, Decoding and Anonymisation toolkit; Document Colour Tracking Dots, or yellow dots, are small systematic dots which encode information about the printer and/or the printout itself. This process is integrated in almost every commercial colour laser printer. This means that almost every printout contains coded information about the source device, such as the serial number.
			* https://dfd.inf.tu-dresden.de/
		* [Forensic Analysis and Anonymisation of Printed Documents](https://dl.acm.org/citation.cfm?doid=3206004.3206019)
			* Contrary to popular belief, the paperless office has not yet established itself. Printer forensics is therefore still an important field today to protect the reliability of printed documents or to track criminals. An important task of this is to identify the source device of a printed document. There are many forensic approaches that try to determine the source device automatically and with commercially available recording devices. However, it is difficult to find intrinsic signatures that are robust against a variety of influences of the printing process and at the same time can identify the specific source device. In most cases, the identification rate only reaches up to the printer model. For this reason we reviewed document colour tracking dots, an extrinsic signature embedded in nearly all modern colour laser printers. We developed a refined and generic extraction algorithm, found a new tracking dot pattern and decoded pattern information. Through out we propose to reuse document colour tracking dots, in combination with passive printer forensic methods. From privacy perspective we additional investigated anonymization approaches to defeat arbitrary tracking. Finally we propose our toolkitdeda which implements the entire workflow of extracting, analysing and anonymisation of a tracking dot pattern.
* **Papers**
	* [Exploitation and Sanitization of Hidden Data in PDF Files - Supriya Adhatarao, Cédric Lauradoux(2021)](https://arxiv.org/abs/2103.02707)
		* Organizations publish and share more and more electronic documents like PDF files. Unfortunately, most organizations are unaware that these documents can compromise sensitive information like authors names, details on the information system and architecture. All these information can be exploited easily by attackers to footprint and later attack an organization. In this paper, we analyze hidden data found in the PDF files published by an organization. We gathered a corpus of 39664 PDF files published by 75 security agencies from 47 countries. We have been able to measure the quality and quantity of information exposed in these PDF files. It can be effectively used to find weak links in an organization: employees who are running outdated software. We have also measured the adoption of PDF files sanitization by security agencies. We identified only 7 security agencies which sanitize few of their PDF files before publishing. Unfortunately, we were still able to find sensitive information within 65% of these sanitized PDF files. Some agencies are using weak sanitization techniques: it requires to remove all the hidden sensitive information from the file and not just to remove the data at the surface. Security agencies need to change their sanitization methods.
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### <a name="emissions"></a> Emissions Security 
* **101**
* **Articles/Blogposts/Writeups**
* **Presentations/Talks/Videos**
* **Papers**
	* [Compromising Reflections - or - How to Read LCD Monitors Around the Corner- Michael Backes, Markus Dürmuth, Dominique Unruh](https://kodu.ut.ee/~unruh/publications/reflections.pdf)
		* We present a novel eavesdropping technique for spying at a distance on data that is displayed on an arbitrary computer screen, including the currently prevalent LCD monitors. Our technique exploits reflections of the screen’s optical emanations in various objects that one commonly finds in close proximity to the screen and uses those reflections to recover the original screen content. Such objects include eyeglasses, tea pots, spoons, plastic bottles,  and even the eye of the user. We have demonstrated that this attack can be successfully mounted to spy on even small fonts using inexpensive, off-the-shelf equipment (less than 1500 dollars) from a distance of up to 10 meters. Relying on more expensive equipment allowed us to conduct this attack from over 30 meters away, demonstrating that similar at- tacks are feasible from the other side of the street or from a close-by building. We additionally establish theoretical limitations of the attack; these limitations may help to estimate the risk that this attack can be successfully mounted in a given environment.
	* [Acoustic Side-Channel Attacks on Printers -Michael Backes,Markus Drmuth,Sebastian Gerling,Manfred Pinkal,Caroline Sporleder](http://www.usenix.net/legacy/events/sec10/tech/full_papers/Backes.pdf)
		* We examine the problem of acoustic emanations of printers. We present a novel attack that recovers what a dot- matrix printer processing English text is printing based on a record of the sound it makes, if the microphone is close enough to the printer. In our experiments, the attack recovers up to 72% of printed  words, and up to 95% if we assume contextual knowledge about the text, with a microphone at a distance of 10 cm from the printer. After an upfront training phase, the attack is fully automated and uses a combination of machine learning, audio processing, and speech recognition techniques, including spectrum features, Hidden Markov Models and linear classification; moreover, it allows for feedback-based incremental learning. We evaluate the effectiveness of countermeasures, and we describe how we successfully mounted the attack in-field (with appropriate privacy protections) in a doctor’s practice to recover the content of medical prescriptions.
	* [Tempest in a Teapot: Compromising Reflections Revisited](http://www.mia.uni-saarland.de/Publications/backes-sp09.pdf)
		* Reflecting objects such as tea pots and glasses, but also diffusely reflecting objects such as a user’s shirt, can be used to spy on confidential data displayed on a monitor. First, we show how reflections in the user’s eye can be exploited for spying  on  confidential data. Second, we investigate to what extent monitor images can be reconstructed from the diffuse reflections on a wall or the user’s clothes, and provide information- theoretic bounds limiting this type of attack. Third, we evaluate the effectiveness of several countermeasures
	* [GSMem: Data Exfiltration from Air-Gapped Computers over GSM Frequencies - usenix conference](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-guri-update.pdf)
* **Tools**
* **Miscellaneous**
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### Facial Identification<a name="facial"></a>
* **Articles**
* **101**
	* [How does facial recognition work? - Steve Symanovich(2019)](https://us.norton.com/internetsecurity-iot-how-facial-recognition-software-works.html)
* **General**
	* [Achieving anonymity against major face recognition algorithms - Benedikt Driessen, Markus Dürmuth](http://www.mobsec.rub.de/forschung/veroeffentlichungen/driessen-13-face-rec/)
	* [IBM Used NYPD Surveillance Footage to Develop Technology That Lets Police Search by Skin Color](https://theintercept.com/2018/09/06/nypd-surveillance-camera-skin-tone-search/)
	* [These clothes use outlandish designs to trick facial recognition software into thinking you're not human - Aaron Holmes(BusinessInsider)](https://www.businessinsider.com/clothes-accessories-that-outsmart-facial-recognition-tech-2019-10)
	* [Wrongfully Arrested Because Face Recognition Can’t Tell Black People Apart - Victoria Burton-Harris, Philip Mayor(2020)](https://www.aclu.org/news/privacy-technology/wrongfully-arrested-because-face-recognition-cant-tell-black-people-apart/)
	* [Russia to Install ‘Orwell’ Facial Recognition Tech in Every School – Vedomosti - Mikhail Japaridze(2020)](https://www.themoscowtimes.com/2020/06/16/russia-to-install-orwell-facial-recognition-tech-in-every-school-vedomosti-a70585)
	* [AWS Facial Recognition Platform Misidentified Over 100 Politicians As Criminals - Lindsey O'Donnell(2020)](https://threatpost.com/aws-facial-recognition-platform-misidentified-over-100-politicians-as-criminals/156984/)
	* [Rite Aid deployed facial recognition systems in hundreds of U.S. stores - Jeffrey Dastin(2020)](https://www.reuters.com/investigates/special-report/usa-riteaid-software/)
		* "In the hearts of New York and metro Los Angeles, Rite Aid installed facial recognition technology in largely lower-income, non-white neighborhoods, Reuters found. Among the technology the U.S. retailer used: a state-of-the-art system from a company with links to China and its authoritarian government."
	* [The Rise of Facial Recognition in China’s Real Estate Market - Manya Koetse(2020)](https://www.whatsonweibo.com/the-rise-of-facial-recognition-in-chinas-real-estate-market/)
		* "Some homebuyers counter the rise of facial recognition technology in real estate offices by wearing helmets during their visit."
	* [Surveillance Nation - Ryan Mac, Brianna Sacks, Caroline Haskins, Logan McDonald(2021)](https://www.buzzfeednews.com/article/ryanmac/clearview-ai-local-police-facial-recognition)
		* "A BuzzFeed News investigation has found that employees at law enforcement agencies across the US ran thousands of Clearview AI facial recognition searches — often without the knowledge of the public or even their own departments."
* **Talks/Presentations/Videos**
	* [Open Source Facial Recognition and Mass Surveillance - Ian O'Neil(2018)](https://www.youtube.com/watch?v=jFa7RK9yGQk&list=PL7D3STHEa66TbZwq9w3S2qWzoJeNo3YYN&index=23)
		* "Facial recognition and biometric data systems are being integrated worldwide on a massive scale. While these existing systems are only operated by a relative few, the technologies which form these systems are widely available, and even open-source. Utilizing machine learning, facial recognition, data crawling, and modern database management, this same style of surveillance system can be integrated by practically anyone."
	* [Adversarial Fashion Sartorial Hacking - Kate Rose(DEF CON 27 Crypto and Privacy Village)](https://www.youtube.com/watch?v=jVcGZ_Ak4NI)
		* [Slides](https://adversarialfashion.com/pages/defcon-27-crypto-privacy-presentation)
		* Use of patterning and adversarial input techniques are on the rise as computer vision analysis of everything from our faces to our license plates becomes ubiquitous for everything from marketing to state surveillance. This talk will be a highly tactical guide to give an overview of the work in the area of confounding or intentionally triggering computer vision systems with fashion. This presentation will show you the same open source guides, libraries, and resources to build your own adversarial clothing, via the process used to develop ALPR-triggering fabrics. This talk will review not only the technical and aesthetic considerations, but also getting over the manufacturing hurdle from design to prototype so you can quickly deploy your fashion hacks to the people
	* [Face/Off: Action Plan for Perils & Privileges of Facial Recognition - Elizabeth Wharton, Suchi Pahi(Shmoocon2020)](https://www.youtube.com/watch?v=L6Hzm2HTWJo&list=PL7-g2-mnZwSFX0qd41qOYHO28tmisjwCJ&index=13&t=1s)
		* Biometric data points, facial recognition, is becoming ubiquitous–unlocking your phone, airline boarding passes, law enforcement, in-store marketing metrics, even ordering fast food. As engineers, managers, or leaders–focus is on revenue, design, and cutting-edge technology. But what about the other effects of facial recognition? Your voice may be your password, but what happens when it’s your face and there’s a data breach or the data is wrong. With studies indicating error ranges in excess of 35%, increasing state biometric related privacy statutes, and biometric data breaches on the rise–what should you be worried about and watching as an architect and designer of such systems?  We’re going to discuss the current facial recognition use cases, growing regulatory concerns, the consequences of facial recognition, and what you can do to make sure that facial recognition technology doesn’t run amok.
* **Papers**
* **Building One**
	* [Build a Face Recognition System for $60 with the New Nvidia Jetson Nano 2GB and Python - Adam Geitgey(2020)](https://medium.com/@ageitgey/build-a-face-recognition-system-for-60-with-the-new-nvidia-jetson-nano-2gb-and-python-46edbddd7264)
	* [Facial Recognition for Verification (Missing Persons) - Chris(2020)](https://www.osintcombine.com/post/facial-recognition-for-verification-missing-persons)
	* [Who-Where-WhomWith(WWWW): A Facial Recognition Tool for Image-based Data Gathering and Graph Analysis - Lorenzo Romani(2020)](https://medium.com/analytics-vidhya/who-where-whomwith-wwww-a-facial-recognition-tool-for-image-based-data-gathering-and-graph-dd8f2b13c279)
	* [Facial Recognition with Python and Elasticsearch: quick Tutorial! - Lorenzo Romani(2020)](https://lorenzoromani.medium.com/facial-recognition-with-python-and-elasticsearch-quick-tutorial-85cd02fe903d)
* **Facial Identification Anonymization**
	* [Image Scrubber](https://everestpipkin.github.io/image-scrubber/)
		* [Code](https://github.com/everestpipkin/image-scrubber)
		* "This is a tool for anonymizing photographs taken at protests. It will remove identifying metadata (Exif data) from photographs, and also allow you to selectively blur parts of the image to cover faces and other identifiable information."
* **Countering Facial Recognition**
	* [DIY Textile Design Resources](https://adversarialfashion.com/pages/diy-resources)
		* "Looking for resources to make your own Computer Vision-triggering fashion and fabric designs? Check out the resource library below, and view the tutorial slides from my DEFCON 27 Crypto & Privacy Village Talk to get started."
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### Human Intelligence<a name="humint"></a>
* **Articles**
	* [Study Manual Handling Of Sources 1989 - School of Americas Watch](https://web.archive.org/web/20070119123627/http://www.soaw.org/new/article.php?id=46)
		* "The purpose of this booklet is to provide the basic information on handling of sources. This booklet in dedicated to CI concepts in the handling of sources; obtaining and utilization, location of the placement of employees, training of employee, communication with the employees, development of an identity, scrutiny of employees, reparation of employees. and control of employees. The term Special Counterintelligence Agent (SA) refers to all those persons who convey or contribute in to counteract the collection of information of the multidisciplinary intelligence of hostile services. This booklet is primarily directed to those persons involved in the control or execution of CI operations. Likewise, this booklet has a significant value for other members of the Armed Forces who function in the security areas or services and other intelligence departments."
	* [HUMINT in the age of cyber - (2021)](https://xorl.wordpress.com/2021/04/01/humint-in-the-age-of-cyber/)
	* https://edwardsnowden.com/wp-content/uploads/2014/02/the-art-of-deception-training-for-a-new.pdf
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### <a name="modern"></a> Modern Surveillance
* **Vendors**
	* [buggedplanet.info](https://buggedplanet.info/index.php?title=Main_Page)
* **Articles**
	* **General**
		* [List of government mass surveillance projects - Wikipedia](https://en.wikipedia.org/wiki/List_of_government_mass_surveillance_projects)
			* This is a list of government surveillance projects and related databases throughout the world.
		* [Understanding & Improving Privacy "Audits" under FTC Orders](https://cyberlaw.stanford.edu/blog/2018/04/understanding-improving-privacy-audits-under-ftc-orders)
			* This new white paper, entitled “Understanding and Improving Privacy ‘Audits’ under FTC Orders,” carefully parses the third-party audits that Google and Facebook are required to conduct under their 2012 Federal Trade Commission consent orders.  Using only publicly available documents, the article contrasts the FTC’s high expectations for the audits with what the FTC actually received (as released to the public in redacted form).   These audits, as a practical matter, are often the only “tooth” in FTC orders to protect consumer privacy.  They are critically important to accomplishing the agency’s privacy mission.  As such, a failure to attend to their robust enforcement can have unintended consequences, and arguably, provide consumers with a false sense of security. The paper shows how the audits are not actually audits as commonly understood.  Instead, because the FTC order language only requires third-party “assessments,” the companies submit reports that are termed “attestations.”  Attestations fundamentally rely on a few vague privacy program aspects that are self-selected by the companies themselves.  While the FTC could reject attestation-type assessments, the agency could also insist the companies bolster certain characteristics of the attestation assessments to make them more effective and replicate audit attributes.  For example, the FTC could require a broader and deeper scope for the assessments.  The agency could also require that assessors evaluate Fair Information Practices, data flows, notice/consent effectiveness, all company privacy assurances, and known order violations.
		* [Creating Your Own Citizen Database -  Aiganysh Aidarbekova](https://www.bellingcat.com/resources/how-tos/2019/02/14/creating-your-own-citizen-database/)
		* [Spy companies using Channel Islands to track phones around the world - Crofton Black(2020)](https://www.thebureauinvestigates.com/stories/2020-12-16/spy-companies-using-channel-islands-to-track-phones-around-the-world)
	* **China**<a name="china"></a>
		* **Articles**
			* [China's Xinjiang Region A Surveillance State Unlike Any the World Has Ever Seen - Bernhard Zand(2018)](http://www.spiegel.de/international/world/china-s-xinjiang-province-a-surveillance-state-unlike-any-the-world-has-ever-seen-a-1220174.html)
			* [China's 5 Steps for Recruiting Spies - Wired(2018)](https://www.wired.com/story/china-spy-recruitment-us/)
			* [Revealed: China suspected of spying on Americans via Caribbean phone networks - Stephanie Kirchgaessner(2020)](https://www.theguardian.com/us-news/2020/dec/15/revealed-china-suspected-of-spying-on-americans-via-caribbean-phone-networks)
			* [China: Big Data Program Targets Xinjiang’s Muslims - Badiucao/HRW(2020)](https://www.hrw.org/news/2020/12/09/china-big-data-program-targets-xinjiangs-muslims)
				* "Leaked List of Over 2,000 Detainees Demonstrates Automated Repression"
			* [How Orbán’s Eastern Opening brought Chinese spy games to Budapest - Panyi Szabolcs(2014)](https://www.direkt36.hu/en/kemjatszmakat-hozott-budapestre-orban-kinai-nyitasa/)
			* [Zhenhua Data leak: personal details of millions around world gathered by China tech company - Daniel Hurst, Lily Kuo, Charlotte Graham-McLay(2020)](https://www.theguardian.com/world/2020/sep/14/zhenhua-data-full-list-leak-database-personal-details-millions-china-tech-company)
				* "The personal details of millions of people around the world have been swept up in a database compiled by a Chinese tech company with reported links to the country’s military and intelligence networks, according to a trove of leaked data."		
			* [China Under the Grid  - ChinaMediaProject(2018)](https://chinamediaproject.org/2018/12/07/china-under-the-grid/)
			* [China’s Top Spy is a Working Class Hero  - Matthew Brazil(2021)](https://www.spytalk.co/p/chinas-top-spy-is-a-working-class)
				* "Chen Wenqing has risen from street cop to boss of China's powerful Ministry of State Security. Loyalty paid off."
			* [China Secretly Built A Vast New Infrastructure To Imprison Muslims - Megha Rajagopalan, Alison Killing, Christo Buschek(2020)](https://www.buzzfeednews.com/article/meghara/china-new-internment-camps-xinjiang-uighurs-muslims)
				* [Part 2](https://www.buzzfeednews.com/article/alison_killing/china-ex-prisoners-horrors-xinjiang-camps-uighurs)
				* [Part 3](https://www.buzzfeednews.com/article/alison_killing/xinjiang-camps-china-factories-forced-labor)
				* [Part 4](https://www.buzzfeednews.com/article/meghara/inside-xinjiang-detention-camp)
			* [China growing use of emotion recognition tech raises rights concerns - Avi Asher-Schapiro(2021)](https://news.trust.org/item/20210127135848-dgm34/)
			* [Revealed: Massive Chinese Police Database - Yael Grauer(2021)](https://theintercept.com/2021/01/29/china-uyghur-muslim-surveillance-police/)
				* "Millions of Leaked Police Files Detail Suffocating Surveillance of China’s Uyghur Minority"
	* **Denmark**
		* [Danish military intelligence uses XKEYSCORE to tap cables in cooperation with the NSA - P/K(2020)](https://www.electrospaces.net/2020/10/danish-military-intelligence-uses.html)
		* [NSA spying row: Denmark accused of helping US spy on European officials - BBC(2021)](https://www.bbc.com/news/world-europe-57302806)
	* **EU(catchall)**
		* [Maximator and other European SIGINT alliances - Electrospaces(2020)](https://www.electrospaces.net/2020/05/maximator-and-other-european-sigint.html)
		* [Maximator: European signals intelligence cooperation, from a Dutch perspective - Bart Jacobs(2020)](https://www.tandfonline.com/doi/full/10.1080/02684527.2020.1743538)
			* This article is first to report on the secret European five-partner sigint alliance Maximator that started in the late 1970s. It discloses the name Maximator and provides documentary evidence. The five members of this European alliance are Denmark Sweden, Germany, the Netherlands, and France. The cooperation involves both signals analysis and crypto analysis. The Maximator alliance has remained secret for almost fifty years, in contrast to its Anglo-Saxon Five-Eyes counterpart. The existence of this European sigint alliance gives a novel perspective on western sigint collaborations in the late twentieth century. The article explains and illustrates, with relatively much attention for the cryptographic details, how the five Maximator participants strengthened their effectiveness via the information about rigged cryptographic devices that its German partner provided, via the joint U.S.-German ownership and control of the Swiss producer Crypto AG of cryptographic devices.
	* **France**
	* **Germany**
		* [German Intelligence Also Snooped on White House - Maik Baumgärtner, Martin Knobbe, Jörg Schindler(2017)](https://www.spiegel.de/international/germany/german-intelligence-also-snooped-on-white-house-a-1153592.html)
			* "German Chancellor Angela Merkel is famous for the terse remark she made after learning her mobile phone had been tapped by the NSA. "Spying among friends, that isn't done." As it turns out, Germany was spying on America too, even targeting the White House."
		* [Bulk interception by Germany's BND and what the Constitutional Court said about it - Electrospaces(2020)](https://www.electrospaces.net/2020/06/bulk-interception-by-germanys-bnd-and.html)
	* **Japan**
		* [The Untold Story of Japan’s Secret Spy Agency - TheIntercept](https://theintercept.com/2018/05/19/japan-dfs-surveillance-agency/)
	* **Russia**
		* [Sophisticated New Devices : KGB Eavesdropping Pervasive, Persistent - Robert Gillete(LA Times 1987)](https://www.latimes.com/archives/la-xpm-1987-04-13-mn-504-story.html)
		* [U.S. Embassy has history of spying charges, countercharges - Andrew Rosenthal(AP 1985)](https://apnews.com/article/d79106674e3cac8460d3f8035f1e70fc)
		* [Assessing the Recently Leaked FSB Contractor Data - A Peek Inside Russia's Understanding of Social Network Analysis and Tailored Access Operations - Dancho Danchev(2019)](https://ddanchev.blogspot.com/2019/08/assessing-recently-leaked-fsb.html)
		* [Does a BEAR Leak in the Woods? The DNC Breach, Russian APTs, and the 2016 US Election - Toni Gidwani(2017)](https://sector.ca/wp-content/uploads/presentations17/Toni-Gidwani-Does-a-BEAR-Leak-in-the-Woods_14-Nov.pdf)
	* **United States**<a name="usa"></a>
		* **General**
			* [Secrecy Power Sinks Patent Case - Kevin Poulsen(2005)](https://www.wired.com/2005/09/secrecy-power-sinks-patent-case/)
			* [U.S. pressed to disclose secret court's order on Yahoo email search - Joseph Menn(Reuters 2016)](https://www.reuters.com/article/us-yahoo-nsa-order-idUSKCN12800D)
				* "SAN FRANCISCO (Reuters) - A U.S. senator and civil groups critical of surveillance practices on Friday called on the government to release a 2015 order by a secret court directing Yahoo to scan all its users’ incoming email, saying it appeared to involve new interpretations of at least two important legal issues."
			* [New Federal Court Rulings Find Geofence Warrants Unconstitutional - Jennifer Lynch, Nathaniel Sobel(2020)](https://www.eff.org/deeplinks/2020/08/new-federal-court-rulings-find-geofence-warrants-unconstitutional-0)
			* [NSA offering 'billions' for Skype eavesdrop solution - Lewis Page(2009)](https://www.theregister.com/2009/02/12/nsa_offers_billions_for_skype_pwnage/)
			* [Microsoft Buys Skype for $8.5 Billion. Why, Exactly? - Peter Bright(2011)](https://www.wired.com/2011/05/microsoft-buys-skype-2/)
				* Just days after reports that Google and Facebook were interested in partnering with, and possibly buying VoIP company Skype, Microsoft announced that it was buying the company for $8.56 billion in cash. Last year, Skype had revenue of $860 million on which it posted an operating profit of $264 million. However, overall it made a small loss of $7 million, and had long-term debt of $686 million.
			* [Report: The Government Monitors Literally Every Phone Call in the US - Brian Barrett(2013)](https://gizmodo.com/this-government-phone-tapping-thing-just-got-as-bad-as-511762830)
			* [Scathing Report Puts Secret FISA Court Into The Spotlight. Will Congress Act? - Ryan Lucas(2019)](https://www.npr.org/2019/12/22/790281142/scathing-report-puts-secret-fisa-court-into-the-spotlight-will-congress-act)
			* [Customs to Expand License Plate Reading Program Nationwide - Aaron Boyd(2020)](https://www.nextgov.com/analytics-data/2020/07/customs-expand-license-plate-reading-program-nationwide/166841/)
				* "Customs will have access to commercial datasets including license plate images and data from parking garages, toll booth cameras and financial institutions, as well as local governments and law enforcement."
			* [Feds Tracking Americans' Credit Cards in Real-Time Without a Warrant - Ms Smith](https://www.csoonline.com/article/2227912/feds-tracking-americans--credit-cards-in-real-time-without-a-warrant.html)
				* "Federal law enforcement agencies have been tracking Americans in real-time using credit cards, loyalty cards and travel reservations without getting court orders for the "hotwatch."
			* [U.S. Used Patriot Act to Gather Logs of Website Visitors - Charlie Savage(2020)]
				* "A disclosure sheds new light on a high-profile national security law as lawmakers prepare to revive a debate over it in the Biden administration."
			* [Cartapping: How Feds Have Spied On Connected Cars For 15 Years - Thomas Brewer(2017)](https://www.forbes.com/sites/thomasbrewster/2017/01/15/police-spying-on-car-conversations-location-siriusxm-gm-chevrolet-toyota-privacy/)
			* [Through apps, not warrants, ‘Locate X’ allows federal law enforcement to track phones - Charles Levinson(2020)](https://www.protocol.com/government-buying-location-data)
			* [Inside America's Secretive $2 Billion Research Hub: Collecting Fingerprints FromFacebook, Hacking Smartwatches and Fighting Covid-19 - Thomas Brewster(2020)](https://www.forbes.com/sites/thomasbrewster/2020/07/13/inside-americas-secretive-2-billion-research-hub-collecting-fingerprints-from-facebook-hacking-smartwatches-and-fighting-covid-19/)
				* "Mitre Corp. runs some of the U.S. government's most hush-hush science and tech labs. The cloak-and-dagger R&D shop might just be the most important organization you've never heard of."
			* [Collection of domestic phone records under the USA FREEDOM Act  - electrospaces(2020)](https://www.electrospaces.net/2018/07/collection-of-domestic-phone-records.html)
			* [Spy Plane was Sent to Monitor Protest in Affluent Suburb, Home to Head of California National Guard - Paul Pringle, Alene Tchekmedyian(2020)](https://www.aviationpros.com/aircraft/defense/news/21159244/spy-plane-was-sent-to-monitor-protest-in-affluent-suburb-home-to-head-of-california-national-guard)
				* "In early June, four National Guard spy planes took to the skies over several cities to monitor street protests following the killing of George Floyd, triggering concerns that the military was improperly gathering intelligence on U.S. citizens."
		* **CBP**
			* [CBP Bought 'Unlimited' Use of a Nationwide Tracking Database - Joseph Cox(2020)](https://www.vice.com/en/article/pky47y/cbp-surveillance-license-plate-reader-vigilant)
				* "A map and files obtained by Motherboard show Customs and Border Protection bought access to a license plate reader database that can locate vehicles far from the border region."
		* **CIA**
			* [Why We Spy on Our Allies - R. James Woolsey](https://cryptome.org/echelon-cia2.htm)
			* [Is Graphic Design the C.I.A.’s Passion? - Ezra Marcus(2021)](https://www.nytimes.com/2021/01/08/style/cia-rebrand.html)
			* [Cables Detail C.I.A. Waterboarding at Secret Prison Run by Gina Haspel - Julian E. Barnes and Scott Shane(2018)](https://www.nytimes.com/2018/08/10/us/politics/waterboarding-gina-haspel-cia-prison.html)
			* [Elite CIA unit that developed hacking tools failed to secure its own systems, allowing massive leak, an internal report found - Ellen Nakashima, Shane Harris(2020)](https://www.washingtonpost.com/national-security/elite-cia-unit-that-developed-hacking-tools-failed-to-secure-its-own-systems-allowing-massive-leak-an-internal-report-found/2020/06/15/502e3456-ae9d-11ea-8f56-63f38c990077_story.html)
			* [The CIA's communications suffered a catastrophic compromise. It started in Iran. - Zach Dorfman, Jenna McLaughlin(2018)](https://news.yahoo.com/cias-communications-suffered-catastrophic-compromise-started-iran-090018710.html)
			* **Family Jewels**
				* [Family Jewels (Central Intelligence Agency) - Wikipedia](https://en.wikipedia.org/wiki/Family_Jewels_(Central_Intelligence_Agency)
					* ""Family Jewels" is the name of a set of reports that detail sensitive activities conducted by the United States Central Intelligence Agency. Considered illegal or inappropriate, these actions were conducted from 1959 to 1973. William Colby, who was the CIA director who received the reports, dubbed them the "skeletons" in the CIA's closet. Most of the documents were publicly released on June 25, 2007, after more than three decades of secrecy. The non-governmental National Security Archive had filed a FOIA request fifteen years earlier."
				* [CIA Reading room copy](https://www.cia.gov/readingroom/collection/family-jewels)
				* [Family Jewels - ](https://web.archive.org/web/20201101104822/https://www.cia.gov/open/Family%20Jewels.pdf)
					* "The purpose of this memorandum is to forward for your personal review summaries of activities conducted either by or under the sponsorship of the Office of Security in the past which in my opinion conflict with the provisions of the National Security Act of 1947."
		* **DEA**
			* [The DEA and ICE are hiding surveillance cameras in streetlights - Justin Rohrlich & Dave Gershgorn(2018)](https://qz.com/1458475/the-dea-and-ice-are-hiding-surveillance-cameras-in-streetlights/)
		* **DHS**
			* [DHS removes official who oversaw intelligence reports on journalists - Betsy Woodruff Swan, Daniel Lippman(2020)](https://www.politico.com/news/2020/08/01/dhs-removes-official-who-oversaw-intelligence-reports-on-journalists-390042)
				* "The Department of Homeland Security is removing its top intelligence official from his post amid criticism of his office's role in the civil unrest in Portland, Oregon."
		* **FBI**<
			* [FBI Spied and Lied, Misled Justice Department on Improper Surveillance of Peace Groups - Ms Smith(2010)](https://www.csoonline.com/article/2227236/fbi-spied-and-lied--misled-justice-department-on-improper-surveillance-of-peace-gro.html)
				* "The FBI misled the Justice Department and improperly spied on peaceful activist groups based on the factually weak possibility of a federal crime."
			* [The Fusion of Paranoia and Bad Policy - Harley Geiger(2009)](https://cdt.org/insights/the-fusion-of-paranoia-and-bad-policy/)
				* "Last week, the Missouri Information Analysis Center (the Missouri fusion center) retracted a report entitled "The Modern Militia Movement" which said that support for mainstream third party presidential candidates was indicative of involvement in violent militia groups. The Missouri fusion center’s characterization of people engaged in legitimate political activity as potentially dangerous drew public condemnation and raised questions about oversight of fusion center activities."
			* [Senate Votes to Allow FBI to Look at Your Web Browsing History Without a Warrant - Janus Rose(2020)](https://www.vice.com/en/article/jgxxvk/senate-votes-to-allow-fbi-to-look-at-your-web-browsing-history-without-a-warrant)
				* "The US Senate has voted to allow law enforcement agencies to access web browsing data without a warrant as part of a Patriot Act reauthorization vote."
			* [The FBI Is Secretly Using A $2 Billion Travel Company As A Global Surveillance Tool - Thomas Brewster(2020)](https://www.forbes.com/sites/thomasbrewster/2020/07/16/the-fbi-is-secretly-using-a-2-billion-company-for-global-travel-surveillance--the-us-could-do-the-same-to-track-covid-19/)
			* [Citizens' Commission to Investigate the FBI - Wikipedia](https://en.m.wikipedia.org/wiki/Citizens%27_Commission_to_Investigate_the_FBI)
				* "The Citizens' Commission to Investigate the FBI was an activist group operational in the US during the early 1970s. Their only known action was breaking into a two-man Media, Pennsylvania, office of the Federal Bureau of Investigation (FBI) and stealing over 1,000 classified documents. They then mailed these documents anonymously to several US newspapers to expose numerous illegal FBI operations which were infringing on the First Amendment rights of American civilians. Most news outlets initially refused to publish the information, saying it related to ongoing operations and that disclosure might have threatened the lives of agents or informants. However, The Washington Post, after affirming the veracity of the files which the Commission sent them, ran a front-page story on March 24, 1971, at which points other media organizations followed suit."
			* [Burglars in 1971 FBI office break-in come forward after 43 years - Ed Pilkington](https://www.theguardian.com/world/2014/jan/07/fbi-office-break-in-1971-come-forward-documents)
		* **ICE**
			* [The Trump Administration Is Trying To Force BuzzFeed News To Divulge Its Sources With A Subpoena - Hamed Aleaziz(2020)](https://www.buzzfeednews.com/article/hamedaleaziz/ice-subpoena-buzzfeed-immigration-sources)
			* [ICE Withdraws Demand For Journalists' Sources After Having Its Unconstitutional Demand Outed By BuzzFeed - Tim Cushing(2020)](https://www.techdirt.com/articles/20201209/21210145858/ice-withdraws-demand-journalists-sources-after-having-unconstitutional-demand-outed-buzzfeed.shtml)
		* **NSA**
			* [James Clapper denies lying to Congress about NSA surveillance program - Andrew Blake(2019)](https://apnews.com/article/33a88feb083ea35515de3c73e3d854ad)
			* [National Security Archive](https://nsarchive.gwu.edu/about)
				* Founded in 1985 by journalists and scholars to check rising government secrecy, the National Security Archive combines a unique range of functions: investigative journalism center, research institute on international affairs, library and archive of declassified U.S. documents ("the world's largest nongovernmental collection" according to the Los Angeles Times), leading non-profit user of the U.S. Freedom of Information Act, public interest law firm defending and expanding public access to government information, global advocate of open government, and indexer and publisher of former secrets.
			* [NSA Spying - EFF](https://www.eff.org/nsa-spying)
				* The US government, with assistance from major telecommunications carriers including AT&T, has engaged in massive, illegal dragnet surveillance of the domestic communications and communications records of millions of ordinary Americans since at least 2001. Since this was first reported on by the press and discovered by the public in late 2005, EFF has been at the forefront of the effort to stop it and bring government surveillance programs back within the law and the Constitution.
			* [NSA operation ORCHESTRA Annual Status Report - Poul-Henning Kemp(FOSDEM2014)](https://www.youtube.com/watch?v=3jQoAYRKqhg)
				* [Slides](https://web.archive.org/web/20200903100811/http://phk.freebsd.dk/_downloads/FOSDEM_2014.pdf)
			* [The NSA: Capabilities and Countermeasures** - Bruce Schneier - ShmooCon 2014](https://www.youtube.com/watch?v=D5JA8Ytk9EI)
				* Edward Snowden has given us an unprecedented window into the NSA's surveillance activities. Drawing from both the Snowden documents and revelations from previous whistleblowers, I will describe the sorts of surveillance the NSA does and how it does it. The emphasis is on the technical capabilities of the NSA, not the politics of their actions. This includes how it conducts Internet surveillance on the backbone, but is primarily focused on their offensive capabilities: packet injection attacks from the Internet backbone, exploits against endpoint computers and implants to exfiltrate information, fingerprinting computers through cookies and other means, and so on. I will then talk about what sorts of countermeasures are likely to frustrate the NSA. Basically, these are techniques to raise the cost of wholesale surveillance in favor of targeted surveillance: encryption, target hardening, dispersal, and so on.
			* [Boundless Informant - Wikipedia](https://en.wikipedia.org/wiki/Boundless_Informant)
				* "Boundless Informant (stylized as BOUNDLESSINFORMANT) is a big data analysis and data visualization tool used by the United States National Security Agency (NSA). It gives NSA managers summaries of the NSA's worldwide data collection activities by counting metadata. The existence of this tool was disclosed by documents leaked by Edward Snowden, who worked at the NSA for the defense contractor Booz Allen Hamilton. Those disclosed documents were in a direct contradiction to the NSA's assurance to United States Congress that it does not collect any type of data on millions of Americans."
			* [Project MINARET - Wikipedia](https://en.wikipedia.org/wiki/Project_MINARET)
				* "Project MINARET was a domestic espionage project operated by the National Security Agency (NSA), which, after intercepting electronic communications that contained the names of predesignated US citizens, passed them to other government law enforcement and intelligence organizations.[1] Intercepted messages were disseminated to the FBI, CIA, Secret Service, Bureau of Narcotics and Dangerous Drugs (BNDD), and the Department of Defense. The project was a sister project to Project SHAMROCK."
			* [Project SHAMROCK - Wikipedia](https://en.wikipedia.org/wiki/Project_SHAMROCK)
				* "Project SHAMROCK was the sister project to Project MINARET, an espionage exercise started in August 1945. Project MINARET involved the accumulation of all telegraphic data that entered or exited the United States. The Armed Forces Security Agency (AFSA) and its successor, the National Security Agency (NSA), were given direct access to daily microfilm copies of all incoming, outgoing, and transiting telegrams via the Western Union and its associates RCA and ITT. NSA did the operational interception, and, if there was information that would be of interest to other intelligence agencies, the material was passed to them. Intercepted messages were disseminated to the FBI, CIA, Secret Service, Bureau of Narcotics and Dangerous Drugs (BNDD), and the Department of Defense. No court authorized the operation and there were no warrants."
			* [MLK and “Domestic Terrorism” - David Schmudde(2020)](https://schmud.de/posts/2020-06-02-mlk.html)
			* [Fairview (surveillance program) - Wikipedia](https://en.wikipedia.org/wiki/Fairview_(surveillance_program))
				* "Fairview is a secret program under which the National Security Agency cooperates with the American telecommunications company AT&T in order to collect phone, internet and e-mail data mainly of foreign countries' citizens at major cable landing stations and switching stations inside the United States. The FAIRVIEW program started in 1985, one year after the Bell breakup."
			* [After blowing $100m to snoop on Americans' phone call logs for four years, what did the NSA get? Just one lead - Kieren McCarthy(2020)](https://www.theregister.com/2020/02/26/nsa_calllogging_program/)
			* [What is known about NSA's PRISM program - Electrospaces(2014)](https://www.electrospaces.net/2014/04/what-is-known-about-nsas-prism-program.html)
			* [FAIRVIEW: Collecting foreign intelligence inside the US - Electrospaces(2015)](https://www.electrospaces.net/2015/08/fairview-collecting-foreign.html)
			* [NSA tapped German Chancellery for decades, WikiLeaks claims - Reuters in Berlin(2015)](https://www.theguardian.com/us-news/2015/jul/08/nsa-tapped-german-chancellery-decades-wikileaks-claims-merkel)
			* [The NSA tried to spy on Danish and other European targets via cable tapping in Denmark - Electrospaces(2020)](https://www.electrospaces.net/2020/11/via-cable-in-denmark-nsa-tried-to-spy.html)
			* [NSA documents and cover names from the book Dark Mirror - Electrospaces(2020)](https://www.electrospaces.net/2020/06/nsa-documents-and-cover-names-from-book.html)
			* [Inside the NSA’s Secret Tool for Mapping Your Social Network - Barton Gellman(2020)](https://www.wired.com/story/inside-the-nsas-secret-tool-for-mapping-your-social-network/)
				* "Edward Snowden revealed the agency’s phone-record tracking program. But thanks to “precomputed contact chaining,” that database was much more powerful than anyone knew."
		* **Secret Service**
			* [Secret Service bought location data pulled from common apps - Christine Fisher(2020)](https://www.engadget.com/secret-service-bought-location-data-locate-x-165531624.html)
				* "Normally, law enforcement would need a warrant or court order to access that data."
			* [Secret Service Paid to Get Americans' Location Data Without a Warrant, Documents Show - Rhett Jones(2020)](https://gizmodo.com/secret-service-bought-access-to-americans-location-data-1844752501)
		* **States**
			* [DNA Data From California Newborn Blood Samples Stored, Sold To 3rd Parties - Julie Watts(2015)](https://sanfrancisco.cbslocal.com/2015/11/09/dna-data-from-california-newborn-blood-samples-stored-sold-to-3rd-parties/)
			* [DMVs Are Selling Your Data to Private Investigators - Joseph Cox(Vice)](https://www.vice.com/en_us/article/43kxzq/dmvs-selling-data-private-investigators-making-millions-of-dollars)
		* **USPS**
			* [Outcry over US Postal Service reportedly tracking social media posts - Coral Murphy Marcos(2021)](https://www.theguardian.com/business/2021/apr/23/usps-covert-program-postal-service-social-media)
			* "Report obtained by Yahoo says USPS surveilling via covert program social media activity it describes as ‘inflammatory’"
		* [Indoor Location Accuracy Benchmarks - FCC](https://www.fcc.gov/public-safety-and-homeland-security/policy-and-licensing-division/911-services/general/location-accuracy-indoor-benchmarks)
			* In January 2015, the Commission adopted new Enhanced 911 (E911) location accuracy rules and information collection requirements in the Fourth Report and Order in PS Docket No. 07-114.  The new rules became effective on April 3, 2015, except for rules containing information collection provisions, which became effective on August 3, 2015 upon approval by the Office of Management and Budget. Below is a summary timeline of compliance deadlines for Commercial Mobile Radio Service (CMRS) providers established by the Fourth Report and Order.
	* **UAE**
		* [Project Raven: Inside the UAE’s secret hacking team of American mercenaries - Christopher Bing, Joel Schectman(Reuters))](https://www.reuters.com/article/us-usa-spying-raven-specialreport/special-report-inside-the-uaes-secret-hacking-team-of-u-s-mercenaries-idUSKCN1PO19O)
* **Corporate**
	* [Jumpshot Knows What You're Buying, Browsing, Searching - Erika Morphy](https://www.cmswire.com/digital-marketing/jumpshot-knows-what-youre-buying-browsing-searching/)
* **License Plate Tracking**
	* **Articles**
		* [Private companies know where you've been, thanks to license plate cameras - syracuse.com](https://www.syracuse.com/news/index.ssf/2015/01/private_companies_know_where_youve_been_thanks_to_license_plate_cameras.html)
* **Non-Modern Surveillance**
	* **Photocopiers**
		* [Spies in the Xerox machine: how an engineer helped the CIA snoop on Soviet diplomats. - Dan Stover(Popular Science1997)](https://electricalstrategies.com/about/in-the-news/spies-in-the-xerox-machine/)
		* [For Your Eyes Only: The Soviet Union and The Photocopier - Dan Motta](https://discover.cobbtechnologies.com/blog/the-soviet-union-and-the-photocopier)
* **Things**
	* [RF-Capture](http://rfcapture.csail.mit.edu/)
		* RF-Capture is a device that captures a human figure through walls and occlusions. It transmits wireless signals and reconstructs a human figure by analyzing the signals' reflections. RF-Capture does not require the person to wear any sensor, and its transmitted power is 10,000 times lower than that of a standard cell-phone.
		* [Paper](http://rfcapture.csail.mit.edu/rfcapture-paper.pdf)
	* [grassland.network](https://www.grassland.network)
		* Grassland is a self-organizing, self-correcting and self-financing, P2P network of robot vision software that efficiently scans any 2D video feed from any single-viewpoint camera to generate a compressed, searchable, timestamped, real-time, 3D simulation of the world. The network's game theory based mathematical framework exhibits positive sensitivity to stressors; e.g. censorship makes it stronger, trustlessly learning the socioeconomic and domestic behaviour of political rivals via a prisoner's dilemma. Grassland is open-source and isn't owned or controlled by anyone. It's politically stateless and anyone can take part. Every node in the network has a permissionless and public API giving any external application or computer free access to Grassland data across the entire network, letting any internet connected object trustlessly internalize, understand and interact intuitively with both past and present states of the real world, digitally recreate or respond to even the tiniest changes taking place around the globe, from a butterfly flapping its wings in Calgary, to the lip-read conversations of pedestrians in Buenos Aires, to understanding that a motorcycle is signaling a left turn in Beijing all at zero cost and in real-time. While the combined work of the network makes it computationally intractable for nodes to submit fake data (see proof-of-work description below).	
	* [Tactical Surveillance: Look at me now! - Chris Nickerson(Derbycon2012)](https://vimeo.com/62278798)
		* As pentesters we have long attacked large surfaces and attempted to follow the path of least resistance, but what happens when you only have 1 target? This talk will cover the Vast Field of tactical surveillance and show the audience how to go after individual targets. Low and slow, high and low, physical to electronic� This talk will show the many tips and tricks of how to find the information you want, when you want it. Monitoring cellphones without a rootkit, easy ways to take surveillance photos, GPS tracing, Physical access, finding the juicy info, creating moles and intel leaks through blackmail� and more. This talk takes place in the real world with real examples. No 0day� just hard work and results.
	* [Surveillance using spare stuff - Matt Scheurer(Derbycon2015)](https://www.youtube.com/watch?v=4-Gy-SjmSRI)
		* This talk focuses on building your own robust surveillance system using items you either already own or may purchase inexpensively. The information presented demonstrates how to build full featured security systems on a shoestring budget. Topics covered include video and audio surveillance, configuring motion detection alarms, monitoring defined hot zones, remote notification and alerting, recording archival, and more.
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### <a name="commercial"></a> Commercial Surveillance
* **101**
* **Articles/Blogposts/Writeups**
	* [The Marketer’s Guide To ACR Tech In Smart TVs - Sarah Sluis(2019)](https://www.adexchanger.com/ad-exchange-news/the-marketers-guide-to-acr-tech-in-smart-tvs/)
 	* ['It's a free-for-all': how hi-tech spyware ends up in the hands of Mexico's cartels - Cecile Schilis-Gallego, Nina Lakhani(2020)](https://www.theguardian.com/world/2020/dec/07/mexico-cartels-drugs-spying-corruption)
 		* "Mexico has become a major importer of spying kit but officials are accused of colluding with criminal groups – and innocent individuals are often targeted"
 	* [Exclusive: Israeli Surveillance Companies Are Siphoning Masses Of Location Data From Smartphone Apps - Thomas Brewster(2020)](https://www.forbes.com/sites/thomasbrewster/2020/12/11/exclusive-israeli-surveillance-companies-are-siphoning-masses-of-location-data-from-smartphone-apps/)
	* [Almost 17,000 Protesters Had No Idea A Tech Company Was Tracing Their Location - Caroline Haskins(2020)](https://www.buzzfeednews.com/article/carolinehaskins1/protests-tech-company-spying)
		* "Data company Mobilewalla used cellphone information to estimate the demographics of protesters. Sen. Elizabeth Warren says it’s “shady” and concerning."
	* [Exclusive: Obscure Indian cyber firm spied on politicians, investors worldwide - Jack Stubbs, Raphael Satter, Christopher Bing(2020)](https://www.reuters.com/article/us-india-cyber-mercenaries-exclusive/exclusive-obscure-indian-cyber-firm-spied-on-politicians-investors-worldwide-idUSKBN23G1GQ)
* **Aerial Surveillance**
	* [Eye in the Sky - Radiolab](https://www.wnycstudios.org/podcasts/radiolab/articles/eye-sky)
		* In 2004, when casualties in Iraq were rising due to roadside bombs, Ross McNutt and his team came up with an idea. With a small plane and a 44 mega-pixel camera, they figured out how to watch an entire city all at once, all day long. Whenever a bomb detonated, they could zoom onto that spot and then, because this eye in the sky had been there all along, they could scroll back in time and see - literally see - who planted it. After the war, Ross McNutt retired from the airforce, and brought this technology back home with him. Manoush Zomorodi and Alex Goldmark from the podcast “Note to Self” give us the low-down on Ross’s unique brand of persistent surveillance, from Juarez, Mexico to Dayton, Ohio. Then, once we realize what we can do, we wonder whether we should.
* **Surveillance-Focused Companies**
	* [Shady Data Brokers Are Selling Online Dating Profiles by the Millions - Samantha Cole(2018)](https://www.vice.com/en/article/59vbp5/shady-data-brokers-are-selling-online-dating-profiles-by-the-millions)
		* "Tactical Tech and artist Joana Moll bought one million dating profiles for $153."
	* [Spy companies using Channel Islands to track phones around the world - Crofton Black(2020)](https://www.thebureauinvestigates.com/stories/2020-12-16/spy-companies-using-channel-islands-to-track-phones-around-the-world)
* **Tech Company-related**
	* [NYPD, Microsoft Launch All-Seeing “Domain Awareness System” With Real-Time CCTV, License Plate Monitoring [Updated] - Neal Ungerleider(2012)](https://www.fastcompany.com/3000272/nypd-microsoft-launch-all-seeing-domain-awareness-system-real-time-cctv-license-plate-monito)
	* [Clubhouse Is Recording Your Conversations. That's Not Even Its Worst Privacy Problem - Jason Aten(2021)](https://www.inc.com/jason-aten/clubhouse-is-recording-your-conversations-thats-not-even-its-worst-privacy-problem.html)
	* [Secret Amazon Reports Expose the Company’s Surveillance of Labor and Environmental Groups - Lauren Kaori Gurley(2020)](https://www.vice.com/en/article/5dp3yn/amazon-leaked-reports-expose-spying-warehouse-workers-labor-union-environmental-groups-social-movements)
	* [Facebook paid for a 0-day to help FBI unmask child predator - Lisa Vaas(2020)](https://nakedsecurity.sophos.com/2020/06/12/facebook-paid-for-a-0-day-to-help-fbi-unmask-child-predator/)
		* "Facebook paid a cybersecurity firm six figures to develop a zero-day in a Tor-reliant operating system in order to unmask a man who spent years sextorting hundreds of young girls, threatening to shoot or blow up their schools if they didn’t comply, Motherboard’s Vice has learned."
	* [The Data Big Tech Companies Have On You - Aliza Vigderman, Gabe Turner(2021)](https://www.security.org/resources/data-tech-companies-have/)		
* **Specific Companies**
	* **Apple**
		* [Exclusive: Apple dropped plan for encrypting backups after FBI complained - sources - Joseph Menn/Reuters(2020)](https://www.reuters.com/article/us-apple-fbi-icloud-exclusive/exclusive-apple-dropped-plan-for-encrypting-backups-after-fbi-complained-sources-idUSKBN1ZK1CT?feedType=RSS&feedName=technologyNews)
	* **Bytedance**
		* [I helped build ByteDance's censorship machine - Shen Lu(2021)](https://www.protocol.com/china/i-built-bytedance-censorship-machine)
	* **Circle**
	 	* [Running in Circles Uncovering the Clients of Cyberespionage Firm Circles - Bill Marczak, John Scott-Railton, Siddharth Prakash Rao1, Siena Anstis, Ron Deibert(2020)](https://citizenlab.ca/2020/12/running-in-circles-uncovering-the-clients-of-cyberespionage-firm-circles/)
	* **Clearview**
		* [Clearview AI CEO says ‘over 2,400 police agencies’ are using its facial recognition software - Elizabeth Lopatto(2020)](https://www.theverge.com/2020/8/26/21402978/clearview-ai-ceo-interview-2400-police-agencies-facial-recognition)
		* [Clearview’s Facial Recognition App Has Been Used By The Justice Department, ICE, Macy’s, Walmart, And The NBA - Ryan Mac, Caroline Haskins, Logan McDonald(2020)](https://www.buzzfeednews.com/article/ryanmac/clearview-ai-fbi-ice-global-law-enforcement)
		* [Surveillance Nation - Ryan Mac, Brianna Sacks, Caroline Haskins, Logan McDonald(2021)](https://www.buzzfeednews.com/article/ryanmac/clearview-ai-local-police-facial-recognition)
			* "A BuzzFeed News investigation has found that employees at law enforcement agencies across the US ran thousands of Clearview AI facial recognition searches — often without the knowledge of the public or even their own departments."
	* **Dark Basin**
		* [Dark Basin: Uncovering a Massive Hack-For-Hire Operation - John Scott-Railton, Adam Hulcoop, Bahr Abdul Razzak, Bill Marczak, Siena Anstis, Ron Deibert(2020)](https://citizenlab.ca/2020/06/dark-basin-uncovering-a-massive-hack-for-hire-operation/)
	* **Discord**
		* [Spyware.neocities - Discord](https://spyware.neocities.org/articles/discord.html)
	* **FinFisher**
		* [FinFisher Filleted 🐟a triage of the FinSpy (macOS) malware - Patrick Wardle(2020)](https://objective-see.com/blog/blog_0x4F.html)
	* **Gravy Analytics**
		* [Through apps, not warrants, ‘Locate X’ allows federal law enforcement to track phones - Charles Levinson(2020)](https://www.protocol.com/government-buying-location-data)
	* **Google**
		* [Will Google Drive Snoop Inside Your Data? Google Needs to Be Clearer - Matt Peckham(2012)](https://techland.time.com/2012/04/26/will-google-drive-snoop-inside-your-data-google-needs-to-be-clearer/)	
		* [Leaked Emails Show Google Expected Lucrative Military Drone AI Work to Grow Exponentially - Lee Fang(2018)](https://theintercept.com/2018/05/31/google-leaked-emails-drone-ai-pentagon-lucrative/)
			* "Google reportedly played down the size of the contract in discussions with uneasy employees, but leaked emails show the company expected revenue to grow rapidly."
		* [Tracking Phones, Google Is a Dragnet for the Police - Jennifer Valentino-DeVries(2019)](https://www.nytimes.com/interactive/2019/04/13/us/google-location-tracking-police.html)
			* "The tech giant records people’s locations worldwide. Now, investigators are using it to find suspects and witnesses near crimes, running the risk of snaring the innocent."
		* [Google's Sensorvault Can Tell Police Where You've Been - Jennifer Lynch(2019)](https://www.eff.org/deeplinks/2019/04/googles-sensorvault-can-tell-police-where-youve-been)
		* [WhatsApp Data on Google Drive Won't Be Encrypted - Lucian Armasu(2018)](https://www.tomshardware.com/news/whatsapp-google-drive-backups-plaintext,37718.html)
		* [This is what happens when ICE asks Google for your user information - Johana Bhuiyan(2021)](https://finance.yahoo.com/news/happens-ice-asks-google-user-120018014.html)
		* [Google misled consumers about the collection and use of location data - Australian Competition & Consumer Commission(2021)](https://www.accc.gov.au/media-release/google-misled-consumers-about-the-collection-and-use-of-location-data)
		* ['Apple is eating our lunch': Google employees admit in lawsuit that the company made it nearly impossible for users to keep their location private - Tyler Sonnemaker(2021)](https://www.businessinsider.com/unredacted-google-lawsuit-docs-detail-efforts-to-collect-user-location-2021-5)
	* **Hawk Analytics**
		* [Powerful Mobile Phone Surveillance Tool Operates in Obscurity Across the Country - Sam Richards(2020)](https://theintercept.com/2020/12/23/police-phone-surveillance-dragnet-cellhawk/)
			* "CellHawk helps law enforcement visualize large quantities of information collected by cellular towers and providers."
	* **Huawei**
		* [Huawei tested AI software that could recognize Uighur minorities and alert police, report says - Drew Harwell, Eva Dou(2020)]
			* "An internal report claims the face-scanning system could trigger a ‘Uighur alarm,’ sparking concerns that the software could help fuel China’s crackdown on the mostly Muslim minority group"
	* **Microsoft**
		* Windows Telemetry
		* [Microsoft Says It Won't Sell Facial Recognition To The Police. These Documents Show How It Pitched That Technology To The Federal Government. - Ryan Mac(2020)](https://www.buzzfeednews.com/article/ryanmac/microsoft-pitched-facial-recognition-dea-drug-enforcement)
		* [Microsoft Teams and Skype Logging Privacy Issue - Reegun Jayapaul(2021)](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/microsoft-teams-and-skype-logging-privacy-issue/)
			* "This blog post focuses on the privacy issues that Microsoft Teams & Skype desktop clients pose. The log database in both clients stores all the chats and images as plain non-encrypted data. The chats are encrypted via network as mentioned here https://docs.microsoft.com/en-us/microsoftteams/teams-security-guide but not encrypted at rest in local storage."
		* [.NET core should not SPY on users by default - Github Issues](https://github.com/dotnet/sdk/issues/6145)
	* **Nintendo**
		* [Nintendo Conducted Invasive Surveillance Operation Against Homebrew Hacker - Andy Maxwell(2020)](https://torrentfreak.com/nintendo-conducted-invasive-surveillance-operation-against-homebrew-hacker-201223/)
			* "Leaked Nintendo documents have revealed a frightening surveillance operation carried out against a hacker who was researching exploits for the 3DS handheld. In addition to monitoring his private life, including aspects of his education, when he left the house and where he went, the company followed its target from his place of work in order to pressure him into stopping his activities."
	* **NSO Group**
		* [Moroccan Journalist Targeted With Network Injection Attacks Using NSO Group’s Tools - Amnesty International(2020)](https://www.amnesty.org/en/latest/research/2020/06/moroccan-journalist-targeted-with-network-injection-attacks-using-nso-groups-tools/)
		* [NSO Group Pitched Phone Hacking Tech to American Police - Joseph Cox(2020)](https://www.vice.com/en/article/8899nz/nso-group-pitched-phone-hacking-tech-american-police)
			* "A brochure and emails obtained by Motherboard show how Westbridge, the U.S. arm of NSO, wanted U.S. cops to buy a tool called Phantom."
		* [Facebook Wanted NSO Spyware to Monitor Users, NSO CEO Claims - Joseph Cox(2020)](https://www.vice.com/en/article/pke9k9/facebook-wanted-nso-spyware-to-monitor-users)
			* "In a court-filed declaration, NSO Group’s CEO says Facebook tried to buy an Apple spying tool in 2017."
		* [NSO Group Impersonated Facebook to Help Clients Hack Targets - Joseph Cox(2020)](https://www.vice.com/en/article/qj4p3w/nso-group-hack-fake-facebook-domain)
			* "Motherboard uncovered more evidence that NSO Group ran hacking infrastructure in the United States."
	* **Oracle**
		* [How Oracle Sells Repression in China - Mara Hvistendahl(2021)](https://theintercept.com/2021/02/18/oracle-china-police-surveillance/)
			* In its bid for TikTok, Oracle was supposed to prevent data from being passed to Chinese police. Instead, it’s been marketing its own software for their surveillance work.
	* **Palantir**
		* [Controversial Data-Mining Firm Palantir Vanishes From Biden Adviser’s Biography After She Joins Campaign - Murtaza Hussain(2020)](https://theintercept.com/2020/06/26/biden-adviser-avril-haines-palantir/)
			* Within a few days of joining the Biden campaign, the biography of former top intelligence official Avril Haines no longer listed her work for Palantir.
		* [Palantir’s God’s-Eye View of Afghanistan - Wired(2021)](https://www.wired.com/story/palantirs-gods-eye-view-of-afghanistan/)
	* **Stripe**
		* [Stripe is Silently Recording Your Movements On its Customers' Websites - Michael Lynch(2020)](https://mtlynch.io/stripe-recording-its-customers/)
			* "Among startups and tech companies, Stripe seems to be the near-universal favorite for payment processing. When I needed paid subscription functionality for my new web app, Stripe felt like the natural choice. After integration, however, I discovered that Stripe’s official JavaScript library records all browsing activity on my site and reports it back to Stripe."
	* **Tencent**
		* [We Chat, They Watch How International Users Unwittingly Build up WeChat’s Chinese Censorship Apparatus - Jeffrey Knockel, Christopher Parsons, Lotus Ruan, Ruohan Xiong, Jedidiah Crandall, Ron Deibert(2020)](https://citizenlab.ca/2020/05/we-chat-they-watch/)
			* "We present results from technical experiments which reveal that WeChat communications conducted entirely among non-China-registered accounts are subject to pervasive content surveillance that was previously thought to be exclusively reserved for China-registered accounts."
	* **Zoom**
		* [China-Based Executive at U.S. Telecommunications Company Charged with Disrupting Video Meetings Commemorating Tiananmen Square Massacre - US DoJ(2020)](https://www.justice.gov/opa/pr/china-based-executive-us-telecommunications-company-charged-disrupting-video-meetings)
		* [Move Fast and Roll Your Own Crypto - Bill Marczak, John Scott-Railton(2020)](https://citizenlab.ca/2020/04/move-fast-roll-your-own-crypto-a-quick-look-at-the-confidentiality-of-zoom-meetings/)
		* [Foreign Spies Are Targeting Americans on Zoom and Other Video Chat Platforms, U.S. Intel Officials Say - John Walcott(2020)](https://time.com/5818851/spies-target-americans-zoom-others/)
			* "An Apr. 3 report by The Citizen Lab, a research organization at the University of Toronto, found a number of shortcomings in Zoom’s security, including some that made it particularly vulnerable to China. It found that Zoom’s encryption scheme “has significant weaknesses,” including routing some encryption keys through Chinese servers, and that its ownership structure and reliance on Chinese labor could “make Zoom responsive to pressure from Chinese authorities.”"
* **Talks/Presentations/Videos**
	* [Commercial Spyware-Detecting the Undetectable - Fidelis Cybersecurity(BHUSA2015)](https://www.blackhat.com/docs/us-15/materials/us-15-Dalman-Commercial-Spyware-Detecting-The-Undetectable-wp.pdf)
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### <a name="mobile"></a> Mobile Device Surveillance
* **101**
* **Articles/Blogposts/Writeups**
	* **General**
		* [Smartphones share our data every four and a half minutes, says study - Ciara O'Brien(2021)](https://www.irishtimes.com/business/technology/smartphones-share-our-data-every-four-and-a-half-minutes-says-study-1.4521267)
		* "Research claims there is little difference between Apple and Google when it comes to collecting certain data"
	* **Android**
		* [Nearby Threats: Reversing, Analyzing, and Attacking Google’s ‘Nearby Connections’ on Android - D. Antonioli, N. O. Tippenhauer, K. Rasmussen(2019)](https://francozappa.github.io/publication/rearby/)
	* **Application-Specific**
		* [(Can’t) Picture This: An Analysis of Image Filtering on WeChat Moments - Jeffrey Knockel, Lotus Ruan, Masashi Crete-Nishihata, and Ron Deibert](https://citizenlab.ca/2018/08/cant-picture-this-an-analysis-of-image-filtering-on-wechat-moments/)
		* [(Can’t) Picture This 2: An Analysis of WeChat’s Realtime Image Filtering in Chats - Jeffrey Knockel and Ruohan Xiong](https://citizenlab.ca/2019/07/cant-picture-this-2-an-analysis-of-wechats-realtime-image-filtering-in-chats/)
* **Presentations/Talks/Videos**
	* [Activity Recognition using Cell Phone Accelerometers - Jennifer R. Kwapisz, Gary M. Weiss, Samuel A. Moore](http://www.cis.fordham.edu/wisdm/includes/files/sensorKDD-2010.pdf)
* **Papers**
	* [SENSORID: Sensor Calibration Fingerprinting for Smartphones - Jiexin Zhang, Alastair R. Beresford, Ian Sheret(2019)](https://www.ieee-security.org/TC/SP2019/papers/405.pdf)
-----------------------------------------------------------------------------------------------------------------------------


-----------------------------------------------------------------------------------------------------------------------------
### <a name="web"></a> Network/Web Based Surveillance
* **101**
	* [Panopticlick](https://panopticlick.eff.org/)
		* Panopticlick will analyze how well your browser and add-ons protect you against online tracking techniques. We’ll also see if your system is uniquely configured—and thus identifiable—even if you are using privacy-protective software.
	* [AmIUnique](https://amiunique.org)
		* This website aims at studying the diversity of browser fingerprints and providing developers with data to help them design good defenses. Contribute to the efforts by viewing your own browser fingerprint or consult the current statistics of data provided by users around the world!
	* [Does a generalization of tracking data cover up our traces on the internet? - helpnetsecurity(2020)](https://www.helpnetsecurity.com/2020/06/22/generalization-of-tracking-data/)
* **Articles/Blogposts/Writeups**
	* **Application Specific**
		* [Behavior Change in Chrome’s Download Protection Service Affecting Privacy - nightwatchcyber](https://wwws.nightwatchcybersecurity.com/2020/01/12/behavior-change-in-chromes-download-protection-service/)
			* Apparently, this has been changed recently. As per information provided from a recent bug report (https://crbug.com/1039128), Chrome now checks ALL extensions except for the ones on the whitelist. That means when you download almost any file, the checksum and some other information about the file are sent back to Google. It is not clear how this impacts privacy.
		* [Venmo Transaction Dataset](https://github.com/sa7mon/venmo-data)
			* This is a dataset of over 7,000,000 transactions scraped from the Venmo public API. Venmo is an app which allows users to easily send and receive money. This data was collected as part of a data analysis project and was scraped during the following date ranges: July 2018 - September 2018; October 2018; Jan 2019 - Feb 2019. I am releasing this dataset in order to bring attention to Venmo users that all of this data is publicly available for anyone to grab without even an API key. There is some very valuable data here for any attacker conducting OSINT research.
	* **Browser Fingerprinting**
		* [tracking without cookies - arctic.org(2003)](http://www.arctic.org/%7Edean/tracking-without-cookies.html)
		* [Cookieless cookies(2013)](https://github.com/lucb1e/cookielesscookies)
			* Demo of tracking using etags instead of cookies (or localstorage or anything else) 
		* [Browser Fingerprinting: An Introduction and the Challenges Ahead - gk(2019)](https://blog.torproject.org/browser-fingerprinting-introduction-and-challenges-ahead)
		* [fingerprintjs2](https://github.com/Valve/fingerprintjs2)
			* Modern & flexible browser fingerprinting library 
		* [Leaked Documents Expose the Secretive Market for Your Web Browsing Data - Joseph Cox(Vice 2020)](https://www.vice.com/en_us/article/qjdkq7/avast-antivirus-sells-user-browsing-data-investigation)
			* An Avast antivirus subsidiary sells 'Every search. Every click. Every buy. On every site.' Its clients have included Home Depot, Google, Microsoft, Pepsi, and McKinsey.
		* [Confirmed: Browsing histories can be used to track users - Zeljka Zorz(2020)](https://www.helpnetsecurity.com/2020/08/27/browsing-histories-track-users/)
		* [Detecting Privacy Badger’s Canvas FP detection - adtechmadness(2020)](https://adtechmadness.wordpress.com/2020/03/27/detecting-privacy-badgers-canvas-fp-detection/)
		* [Should you self-host Google Fonts? - Barry Pollard(2020)](https://www.tunetheweb.com/blog/should-you-self-host-google-fonts/)
		* [No Cookies, No Problem — Using ETags For User Tracking - Nicolas Hinternesch(2020)](https://levelup.gitconnected.com/no-cookies-no-problem-using-etags-for-user-tracking-3e745544176b)
	* **Browser Technologies**
		* [Novel Techniques for User Deanonymization Attacks - Ahmed Elsobky](https://0xsobky.github.io/novel-deanonymization-techniques/)
		* [A Cross browser Exploit to Deanonymize Web Users - Ahmed Elsobky](https://github.com/0xsobky/HackVault/wiki/A-Cross-browser-Exploit-to-Deanonymize-Web-Users)
		* [Invasion of Privacy - HackerFactor](http://www.hackerfactor.com/blog/index.php?/archives/703-Invasion-of-Privacy.html)
		* [Cookies – what does ‘good’ look like? - UK Information Comissioner's Office - Ali Shah](https://ico.org.uk/about-the-ico/news-and-events/news-and-blogs/2019/07/blog-cookies-what-does-good-look-like/)
		* [Evercookie](https://github.com/samyk/evercookie)
			* Produces persistent, respawning "super" cookies in a browser, abusing over a dozen techniques. Its goal is to identify users after they've removed standard cookies and other privacy data such as Flash cookies (LSOs), HTML5 storage, SilverLight storage, and others.
		* [Chrome allows silent enumeration of USB devices - henriquez(2018)](https://www.obsessivefacts.com/blog/2018-10-20-chrome-allows-enumeration-of-usb-devices.html)
		* **Protocol Handlers**
			* [external-protocol-flooding](https://github.com/fingerprintjs/external-protocol-flooding)
				*  Scheme flooding vulnerability: how it works and why it is a threat to anonymous browsing 
			* [Leaking Browser URL/Protocol Handlers - Rotem Kerner(2020)](https://www.fortinet.com/blog/threat-research/leaking-browser-url-protocol-handlers)
	* **Network**
		* [Did you know that IPv6 may include your MAC address? Here’s how to stop it. - kronos(SuperUser community blog)](https://blog.superuser.com/2011/02/11/did-you-know-that-ipv6-may-include-your-mac-address-heres-how-to-stop-it/)
		* [Windows IPv6 Privacy Extentions - computer-outlines.over-blog.com](http://computer-outlines.over-blog.com/article-windows-ipv6-privacy-addresses-118018020.html)
	* [DNS May Be Hazardous to Your Health - Robert Stucke](https://www.youtube.com/watch?v=ZPbyDSvGasw)
		* Great talk on attacking DNS
	* [Recommendations on Anonymization Processes for Source IP Addresses Submitted for Future Analysis - ICANN(2018)](https://www.icann.org/en/system/files/files/rssac-040-07aug18-en.pdf)
		* This is an Advisory to the Internet Corporation for Assigned Names and Numbers (ICANN) Board of Directors and more broadly to the Internet community from the ICANN Root Server System Advisory Committee (RSSAC). In this report, the RSSAC conducted a technical analysis of harmonizing anonymization procedures for DNS data
	* **Sales**
		* [Google and Mastercard Cut a Secret Ad Deal to Track Retail Sales - Mark Bergan, Jennifer Surane](https://www.bloomberg.com/news/articles/2018-08-30/google-and-mastercard-cut-a-secret-ad-deal-to-track-retail-sales)
* **Presentations/Talks/Videos**
	* **Pixel Tracking**
		* [Pixel Tracking: How it’s used and abused - Barry Kimball(OISF19)](http://www.irongeek.com/i.php?page=videos/oisf2019/oisf-2019-05-pixel-tracking-how-its-used-and-abused-barry-kimball)
	* **User-Profiling**
		* [Browser fingerprints for a more secure web - Julien Sobrier & Ping Yan(OWASP AppSecCali2019)](https://www.youtube.com/watch?v=P_nYYsaVi1w&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=30&t=0s)
	* **WiFi**<a name="wifi"></a>
		* [Wifi Tracking: Collecting the (probe) Breadcrumbs - David Switzer](https://www.youtube.com/watch?v=HzQHWUM8cNo)
			* Wifi probes have provided giggles via Karma and Wifi Pineapples for years, but is there more fun to be had? Like going from sitting next to someone on a bus, to knowing where they live and hang out? Why try to MITM someone’s wireless device in an enterprise environment where they may notice — when getting them at their favorite burger joint is much easier. In this talk we will review ways of collecting and analyzing probes. We’ll use the resulting data to figure out where people live, their daily habits, and discuss uses (some nice, some not so nice) for this information. We’ll also dicuss how to make yourself a little less easy to track using these methods. Stingrays are price prohibitive, but for just tracking people’s movements.. this is cheap and easy.
* **Papers**
	* **Browsers**
		* [Discovering Browser Extensions via Web Accessible Resources - Chalmers security lab](http://www.cse.chalmers.se/research/group/security/publications/2017/extensions/codaspy-17-full.pdf)
		* [Cookieless Monster: Exploring the Ecosystem of Web-based Device Fingerprinting](http://securitee.org/files/cookieless_sp2013.pdf)
		* [Client Identification Mechanisms](http://www.chromium.org/Home/chromium-security/client-identification-mechanisms)
		* [Technical analysis of client identification mechanisms](http://www.chromium.org/Home/chromium-security/client-identification-mechanisms) 
		* [What Happens Next Will Amaze You](http://idlewords.com/talks/what_happens_next_will_amaze_you.htm#six_fixes)
			* In this paper, we examine how web-based device fingerprinting currently works on the Internet. By analyzing the code of three popular browser-fingerprinting code providers, we reveal the techniques that allow websites to track users without the need of client-side identifiers. Among these techniques, we show how current commercial fingerprinting approaches use questionable practices, such as the circumvention of HTTP proxies to discover a user’s real IP address and the installation of intrusive browser plugins. At the same tim e, we show how fragile the browser ecosystem is against fingerprinting through the use of novel browser- identifying techniques. With so many different vendors involved in browser development, we demonstrate how one can use diversions in the browsers’ implementation to distinguish successfully not only the browser-family, but also specific major and minor versions. Browser extensions that help users spoof the user-agent of their browsers are also evaluated. We show that current commercial approaches can bypass the extensions, and, in addition, take advantage of their shortcomings by using them as additional fingerprinting features.
		* [Touching from a Distance: Website Fingerprinting Attacks and Defenses - Xiang Cai, Xin Cheng Zhang, Brijesh Joshi, Rob Johnson](http://www3.cs.stonybrook.edu/~xcai/fp.pdf)
			* We present a novel web page fingerprinting attack that is able to defeat several recently proposed defenses against traffic analysis attacks, including the application-level defenses HTTPOS [15] and randomized pipelining over Tor [18]. Regardless of the defense scheme, our attack was able to guess which of 100 web pages a victim was visiting at least 50% of the time and, with some defenses, over 90% of the time. Our attack is based on a simple model of network behavior and out-performs previously proposed ad hoc attacks. We then build a web site fingerprinting attack that is able to identify whether a victim is visiting a particular web site with over 90% accuracy in our experiments. Our results strongly suggest that ad hoc defenses against traffic analysis are not likely to succeed. Consequently, we describe a defense scheme that provides provable security properties, albeit with potentially higher overheads
		* [Browsing Unicity: On the Limits of Anonymizing Web Tracking Data - Clemens Deußer, Steffen Passmann, Thorsten Strufe(2020)](https://ieeexplore.ieee.org/document/9152774)
	* **IP Addresses**
		* [Don’t Count Me Out: On the Relevance of IP Address in the Tracking Ecosystem - Vikas Mishra, Pierre Laperdrix, Antoine Vaste, Walter Rudametkin, Romain Rouvoy, Martin Lopatka(2020)](https://hal.inria.fr/hal-02435622/document)
			* "We present an analysis of 34,488 unique public IP addressescollected from 2,230 users over a period of 111 days and we showthat IP addresses remain a prime vector for online tracking. 87 % ofparticipants retain at least one IP address for more than a monthand 45 % of ISPs in our dataset allow keeping the same IP addressfor more than 30 days. Furthermore, we also detect the presenceof cycles of IP addresses in a user’s history and highlight theirpotential to be abused to infer traits of the user behaviour, as wellas mobility traces. Our findings paint a bleak picture of the currentstate of online tracking at a time where IP addresses are overlookedcompared to other techniques like cookies or fingerprinting."
	* **VPNs**
		* [A Glance through the VPN Looking Glass: IPv6 Leakage and DNS Hijacking in Commercial VPN clients - Vasile C. Perta, Marco V. Barbera, Gareth Tyson, Hamed Haddadi, and Alessandro Mei(2/2015)](https://www.petsymposium.org/2015/papers/02_Perta.pdf)
* **Tools**
	* **Browser Fingerprinting**
		* [TorZillaPrint](https://github.com/ghacksuserjs/TorZillaPrint)
			* TZP is only designed for Firefox [v60+] and the Tor Browser [v8+]. [Here are additonal tests](https://ghacksuserjs.github.io/TorZillaPrint/extra.html), and [here is the repo](https://github.com/ghacksuserjs/TorZillaPrint) [feel free to drop in]. When re-testing sections, be aware that some pref/option changes may require a page refresh [F5] or even a new browser session.
		* [Panopticlick](https://panopticlick.eff.org/)
			* Panopticlick will analyze how well your browser and add-ons protect you against online tracking techniques. We’ll also see if your system is uniquely configured—and thus identifiable—even if you are using privacy-protective software.
		* [AmIUnique](https://amiunique.org)
			* This website aims at studying the diversity of browser fingerprints and providing developers with data to help them design good defenses. Contribute to the efforts by viewing your own browser fingerprint or consult the current statistics of data provided by users around the world!
	* **Browsers**
		* [chrome-private](https://github.com/atomontage/chrome-private)
			* Isolated, optionally ephemeral profiles for Google Chrome 
----------------------------------------------------------------------------------------------------


----------------------------------------------------------------------------------------------------
### OPSEC(Specifically)<a name="opsec"></a>
* **Articles/Blogposts/Writeups**
	* [Operational Security and the Real World - The Grugq](https://medium.com/@thegrugq/operational-security-and-the-real-world-3c07e7eeb2e8)
	* [CIA Vault7 Development Tradecraft DOs and DON'Ts](https://wikileaks.org/ciav7p1/cms/page_14587109.html)
	* [Campaign Information Security In Theory and Practice](https://medium.com/@thegrugq/campaign-information-security-ff6ac49966e1)
	* [Reminder: Oh, Won't You Please Shut Up? - USA](https://www.popehat.com/2011/12/01/reminder-oh-wont-you-please-shut-up/)
	* [Underground Tradecraft Rules of Clandestine Operation](https://grugq.tumblr.com/post/60463307186/rules-of-clandestine-operation)
	* [I know places we can hide Opsec tips from Taylor Swift](https://medium.com/@flamsmark/i-know-places-we-can-hide-3a84b1f79963)
	* [Operational Security and the Real World - The Grugq](https://medium.com/@thegrugq/operational-security-and-the-real-world-3c07e7eeb2e8)
	* [Managing Pseudonyms with Compartmentalization: Identity Management of Personas](https://www.alienvault.com/blogs/security-essentials/managing-pseudonyms-with-compartmentalization-identity-management-of-personas)
	* [The Need for Identity Management - alienvault](https://www.alienvault.com/blogs/security-essentials/managing-pseudonyms-with-compartmentalization-identity-management-of-personas)
	* [Researchers Say They Uncovered Uzbekistan Hacking Operations Due to Spectacularly Bad OPSEC - Kim Zetter(Vice)](https://www.vice.com/en_us/article/3kx5y3/uzbekistan-hacking-operations-uncovered-due-to-spectacularly-bad-opsec)
		* A new threat actor Kaspersky calls SandCat, believed to be Uzbekistan’s intelligence agency, is so bad at operational security, researchers have found multiple zero-day exploits used by the group, and even caught malware the group was still developing.
	* [OPSEC in The After Life - rastating(2019)](https://rastating.github.io/opsec-in-the-after-life/)
	* [dropgangs, or the future of darknet markets - Jonathan Logan](https://opaque.link/post/dropgang/)
		* The Internet is full of commercial activity and it should come at no surprise that even illegal commercial activity is widespread as well. In this article we would like to describe the current developments - from where we came, where we are now, and where it might be going - when it comes to technologies used for digital black market activity. We will refrain from any legal, moral or ethical judgment on these activities but focus on the technical and operational security aspects. What is illegal and unethical trade for one is perfectly legal for another. Judge for yourself.
	* [Russia Convention on International Information Security](http://cryptome.org/2014/05/ru-international-infosec.htm)
		* Basic documents on domestic and foreign policy
	* [The OPSEC of Protesting - Ochaun Marshall(2020)](https://secureideas.com/blog/2020/08/the-opsec-of-protesting.html)
	* [Who is “n3td3v”? - Hacker Factor Solutions(2006)](https://www.hackerfactor.com/papers/who_is_n3td3v.pdf)
* **Talks/Presentations/Videos**
	* [Because Jail is for WUFTPD - TheGrugq](https://www.youtube.com/watch?v=9XaYdCdwiWU)
	* [OPSEC In the Age of The Egotistical Giraffe](https://conference.hitb.org/hitbsecconf2014kul/materials/D1T1%20-%20The%20Grugq%20-%20OPSEC%20in%20the%20Age%20of%20Egotistical%20Giraffe.pdf)
	* [OPSEC Concerns in Using Crypto](https://www.slideshare.net/JohnCABambenek/defcon-crypto-village-opsec-concerns-in-using-crypto)
	* [You're Leaking Trade Secrets - Defcon22 Michael Schrenk](https://www.youtube.com/watch?v=JTd5TL6_zgY)
		* Networks don't need to be hacked for information to be compromised. This is particularly true for organizations that are trying to keep trade secrets. While we hear a lot about personal privacy, little is said in regard to organizational privacy. Organizations, in fact, leak information at a much greater rate than individuals, and usually do so with little fanfare. There are greater consequences for organizations when information is leaked because the secrets often fall into the hands of competitors. This talk uses a variety of real world examples to show how trade secrets are leaked online, and how organizational privacy is compromised by seemingly innocent use of The Internet.
	* [OpSec 101 - NotMyNick(Disobey2017)](https://www.youtube.com/watch?v=kzxWUuwBLWk&list=PLLvAhAn5sGfj05ej8QG0DEl1WRgJYmXMs&index=15)
	* [A DECEPTICON and AUTOBOT walk into a bar: Python for enhanced OPSEC - Joe Gray(x33fcon2020)](https://www.youtube.com/watch?v=k7W7PC22d3Y&list=PL7ZDZo2Xu330gMHAoeGvH9QkCJMC-qgeK&index=17)
		* "The DECEPTICON bot is a python-based tool that connects to social media & determines patterns of behavior then takes over to autonomously post for the user. This is for people who are trying to enhance their OPSEC & abandon social media accounts without setting off alarms to their adversaries."
	* [How to test Network Investigative Techniques(NITs) used by the FBI - Dr Matthew Miller(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/track-1-09-how-to-test-network-investigative-techniquesnits-used-by-the-fbi-dr-matthew-miller)
		* Network Investigative Techniques are used to investigate cyber criminal activities. These techniques have been used to unmask users of TOR whom are downloading illegal content from the Tor network. This talk will discuss such techniques, discuss ethical and legal issues and describe a methodology to test and verify such techniques.
	* [Everything you wanted to know about OPSEC, and some more… - xorl %eax, %eax(2020)](https://xorl.wordpress.com/2020/03/29/everything-you-wanted-to-know-about-opsec-and-some-more/)
	* [Don't Talk to the Police - James Duane](https://www.youtube.com/watch?v=d-7o9xYp7eE)
		* Regent Law Professor James Duane gives viewers startling reasons why they should always exercise their 5th Amendment rights when questioned by government officials.
	* [When Cybercriminals with Good OpSec Attack - Ryan MacFarlane, Liam O'Murchu(2020)](https://www.youtube.com/watch?v=zXmZnU2GdVk)
		* Investigating career cybercriminals is hard, especially when their paranoia has fostered strong OpSec? The FBI and Symantec spent 10 years investigating such a gang eventually finding cracks just large enough to end the gangs crime spree. This case study will show how to investigate when strong OpSec exists.Pre-Requisites: General knowledge of cyber crimes investigations, minimal traffic analysis and malware analysis.
	* [CrimeOps: The operational art of cybercrime - The Grugq(vOPCDE #8)](https://www.youtube.com/watch?v=E9F7WCO-pZM)
		* Cybercrime rewards innovative organisations. Groups can innovate at the tactical level (e.g. new or updated TTP), the strategic level (e.g. new monetisation methods), or at the operational level -- the management of resources and personnel to achieve strategic objectives. The operational level is seldom analyzed because it is rarely visible to information security researchers. Changes in TTP are discovered quickly on the ground, and new strategies emerge by monitoring major shifts and trends. The operational glue that enables a group to execute well is almost never apparent to an outside observer.
----------------------------------------------------------------------------------------------------



### To sort
* [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
	* Scuttlebutt is a protocol for building decentralized applications that work well offline and that no one person can control. Because there is no central server, Scuttlebutt clients connect to their peers to exchange information. This guide describes the protocols used to communicate within the Scuttlebutt network. Scuttlebutt is a flexible protocol, capable of supporting many different types of applications. One of its first applications was as a social network, and it has also become one of the most compelling because the people who hang out there are not jerks. This guide has a slight focus on how to use Scuttlebutt for social networking, but many of the explanations will still be useful if want to use it for something completely different, or are just curious how it works.
* [Serval](http://www.servalproject.org)
	* Serval is a telecommunications system comprised of at least two mobile phones that are able to work outside of regular mobile phone tower range due thanks to the Serval App and Serval Mesh.
* [VSCodium](https://github.com/VSCodium/vscodium/)
	* This is not a fork. This is a repository of scripts to automatically build Microsoft's vscode repository into freely-licensed binaries with a community-driven default configuration.
* [ungoogled-chromium](https://github.com/Eloston/ungoogled-chromium)
	* ungoogled-chromium is Google Chromium, sans dependency on Google web services. It also features some tweaks to enhance privacy, control, and transparency (almost all of which require manual activation or enabling).




--------------------------
### <a name="anonymity"></a>Anonymity
* **Articles**	
	* [Opting Out Like A Boss - The OSINT Way (Part 1) - learnallthethings.net](https://www.learnallthethings.net/blog/2018/1/23/opting-out-like-a-boss-the-osint-way)












