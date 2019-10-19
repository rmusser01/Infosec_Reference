## Anonymity, Opsec & Privacy

### Table of Contents
- [General](#general)
- [Android/iOS/Mobile](#mobile)
- [Browser Related](#browser)
- [Communications Security](#comsec)
- [Data Collection](#dcollect)
- [De-anonymization](#de-anon)
- [Documents/Writing](#writing)
- [Facial Identification](#face)
- [Informative/Educational](#informative)
- [Journalism & Media Publishing](#media)
- [Network Obfuscation](#obfuscation)
- [Operational Security - OPSEC](#opsec)
- [References/Resources](#ref)
- [Wireless Radios](#)
- [Tor](#tor)
- [Traveling](#travel)
- [Miscellaneous Stuff](#misc)
- [Miscellaneous Tools](#misc-tools)
- [Counter-Surveillance](#counter)
	- [Writeups](#cwriteup)
	- [Videos/Talks](#cvideos)
	- [Papers](#cpapers)
- [Emissions Security](#emissions)
	- [Papers](#papers)
- [Modern Surveillance](#modern)
	- [China](#china)
	- [United States](#usa)
- [Disinformation](#disinfo)








--------------
### <a name="general"></a>General
* **101**
	* [A Guide to Law Enforcement Spying Technology - EFF](https://www.eff.org/sls)
	* [Anonymity](https://en.wikipedia.org/wiki/Anonymity)
	* [Operations Security - Wikipedia](https://en.wikipedia.org/wiki/Operations_security)
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
* **Android/iOS/Mobile**<a name="mobile"></a>
	* [Click and Dragger: Denial and Deception on Android mobile](https://www.slideshare.net/grugq/mobile-opsec/34-WHAT_ARETHEY_GOOD_FOR_Threat)
	* [DEFCON 20: Can You Track Me Now? Government And Corporate Surveillance Of Mobile Geo-Location Data](https://www.youtube.com/watch?v=NjuhdKUH6U4)
	* [Can you track me now? - Defcon20](https://wEww.youtube.com/watch?v=DxIF66Tcino)
	* [Phones and Privacy for Consumers - Matt Hoy (mattrix) and David Khudaverdyan (deltaflyer)](http://www.irongeek.com/i.php?page=videos/grrcon2015/submerssion-therapy05-phones-and-privacy-for-consumers-matt-hoy-mattrix-and-david-khudaverdyan-deltaflyerhttps://ritter.vg/blog-deanonymizing_amm.html)
	* [Hacking FinSpy - a Case Study - Atilla Marosi - Troopers15](https://www.youtube.com/watch?v=Mb4mfBi06K4)
* **Browser Related**<a name="browser"></a>
	* [Panopticlick](https://panopticlick.eff.org/)
		* Panopticlick will analyze how well your browser and add-ons protect you against online tracking techniques. We’ll also see if your system is uniquely configured—and thus identifiable—even if you are using privacy-protective software.
	* [Discovering Browser Extensions via Web Accessible Resources - Chalmers security lab](http://www.cse.chalmers.se/research/group/security/publications/2017/extensions/codaspy-17-full.pdf)
	* [Cookieless Monster: Exploring the Ecosystem of Web-based Device Fingerprinting](http://securitee.org/files/cookieless_sp2013.pdf)
	* [Client Identification Mechanisms](http://www.chromium.org/Home/chromium-security/client-identification-mechanisms)
	* [Technical analysis of client identification mechanisms](http://www.chromium.org/Home/chromium-security/client-identification-mechanisms) 
	* [What Happens Next Will Amaze You](http://idlewords.com/talks/what_happens_next_will_amaze_you.htm#six_fixes)
		* In this paper, we examine how web-based device fingerprinting currently works on the Internet. By analyzing the code of three popular browser-fingerprinting code providers, we reveal the techniques that allow websites to track users without the need of client-side identifiers. Among these techniques, we show how current commercial fingerprinting approaches use questionable practices, such as the circumvention of HTTP proxies to discover a user’s real IP address and the installation of intrusive browser plugins. At the same tim e, we show how fragile the browser ecosystem is against fingerprinting through the use of novel browser- identifying techniques. With so many different vendors involved in browser development, we demonstrate how one can use diversions in the browsers’ implementation to distinguish successfully not only the browser-family, but also specific major and minor versions. Browser extensions that help users spoof the user-agent of their browsers are also evaluated. We show that current commercial approaches can bypass the extensions, and, in addition, take advantage of their shortcomings by using them as additional fingerprinting features.
	* [Invasion of Privacy - HackerFactor](http://www.hackerfactor.com/blog/index.php?/archives/703-Invasion-of-Privacy.html)
* **Communication Security**<a name="comsec"></a>
	* [A Study of COMINT Personnel Security Standards and Practices](https://www.cia.gov/library/readingroom/document/cia-rdp82s00527r000100060014-6)
	* [COMSEC Beyond Encryption](https://grugq.github.io/presentations/COMSEC%20beyond%20encryption.pdf)
	* [NSA operation ORCHESTRA: Annual Status Report(2014) - Poul-Henning Kamp - FOSDEM14](https://www.youtube.com/watch?v=fwcl17Q0bpk&feature=youtu.be)
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
* **Documents**<a name="writing"></a>
	* **Authorship Analysis/Identification**
		* [anonymouth](https://github.com/psal/anonymouth)
			* Document Anonymization Tool, Version 0.5
		* [F⁠ingerprinting documents​ with steganography​](http://blog.fastforwardlabs.com/2017/06/23/fingerprinting-documents-with-steganography.html)
		* [Text Authorship Verification through Watermarking - Stefano Giovanni Rizzo, Flavio Bertini, Danilo Montesi](https://pdfs.semanticscholar.org/4028/f904da8e2c50672e6037168bf2bd72bc4cb9.pdf)
	* **Obfuscation/Making it harder to OCR/Redaction Tactics and Methods**
		* [Redaction of PDF Files Using Adobe Acrobat Professional X - NSA](https://www.cs.columbia.edu/~smb/doc/Redaction-of-PDF-Files-Using-Adobe-Acrobat-Professional-X.pdf)
		* [Why Government Agencies Use Ugly, Difficult to Use Scanned PDFs - There's More Than Meets the Eye - circleid.com](http://www.circleid.com/posts/20180720_why_government_agencies_use_ugly_difficul_to_use_scanned_pdfs/)
	* **Stegonagraphy**
		* [steganos](https://github.com/fastforwardlabs/steganos)
			* This is a library to encode bits into text.... steganography in text!
		* [Content-preserving Text Watermarking through Unicode Homoglyph Substitution](https://www.researchgate.net/publication/308044170_Content-preserving_Text_Watermarking_through_Unicode_Homoglyph_Substitution)
			* Digital watermarking has become crucially important in authentication and copyright protection of the digital contents, since more and more data are daily generated and shared online through digital archives, blogs and social networks. Out of all, text watermarking is a more difficult task in comparison to other media watermarking. Text cannot be always converted into image, it accounts for a far smaller amount of data (eg. social network posts) and the changes in short texts would strongly affect the meaning or the overall visual form. In this paper we propose a text watermarking technique based on homoglyph characters substitution for latin symbols1. The proposed method is able to efficiently embed a password based watermark in short texts by strictly preserving the content. In particular, it uses alternative Unicode symbols to ensure visual indistinguishability and length preservation, namely content-preservation. To evaluate our method, we use a real dataset of 1.8 million New York articles. The results show the effectiveness of our approach providing an average length of 101 characters needed to embed a 64bit password based watermark.
* **Facial Identification**<a name="facial"></a>
	* [Achie­ving an­ony­mi­ty against major face re­co­gni­ti­on al­go­rith­ms -  Be­ne­dikt Dries­sen, Mar­kus Dür­muth](http://www.mobsec.rub.de/forschung/veroeffentlichungen/driessen-13-face-rec/)
	* [IBM Used NYPD Surveillance Footage to Develop Technology That Lets Police Search by Skin Color](https://theintercept.com/2018/09/06/nypd-surveillance-camera-skin-tone-search/)
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
* **OPSEC(Specifically)**<a name="opsec"></a>
	* [Operational Security and the Real World - The Grugq](https://medium.com/@thegrugq/operational-security-and-the-real-world-3c07e7eeb2e8)
	* [CIA Vault7 Development Tradecraft DOs and DON'Ts](https://wikileaks.org/ciav7p1/cms/page_14587109.html)
	* [Campaign Information Security In Theory and Practice](https://medium.com/@thegrugq/campaign-information-security-ff6ac49966e1)
	* [Reminder: Oh, Won't You Please Shut Up? - USA](https://www.popehat.com/2011/12/01/reminder-oh-wont-you-please-shut-up/)
	* [Underground Tradecraft Rules of Clandestine Operation](https://grugq.tumblr.com/post/60463307186/rules-of-clandestine-operation)
	* [I know places we can hide Opsec tips from Taylor Swift](https://medium.com/@flamsmark/i-know-places-we-can-hide-3a84b1f79963)
	* [Operational Security and the Real World - The Grugq](https://medium.com/@thegrugq/operational-security-and-the-real-world-3c07e7eeb2e8)
	* [Managing Pseudonyms with Compartmentalization: Identity Management of Personas](https://www.alienvault.com/blogs/security-essentials/managing-pseudonyms-with-compartmentalization-identity-management-of-personas)
	* [Because Jail is for WUFTPD - Legendary talk, a must watch.](https://www.youtube.com/watch?v=9XaYdCdwiWU)
	* [OPSEC In the Age of The Egotistical Giraffe](https://conference.hitb.org/hitbsecconf2014kul/materials/D1T1%20-%20The%20Grugq%20-%20OPSEC%20in%20the%20Age%20of%20Egotistical%20Giraffe.pdf)
	* [OPSEC Concerns in Using Crypto](https://www.slideshare.net/JohnCABambenek/defcon-crypto-village-opsec-concerns-in-using-crypto)
	* [You're Leaking Trade Secrets - Defcon22 Michael Schrenk](https://www.youtube.com/watch?v=JTd5TL6_zgY)
		* Networks don't need to be hacked for information to be compromised. This is particularly true for organizations that are trying to keep trade secrets. While we hear a lot about personal privacy, little is said in regard to organizational privacy. Organizations, in fact, leak information at a much greater rate than individuals, and usually do so with little fanfare. There are greater consequences for organizations when information is leaked because the secrets often fall into the hands of competitors. This talk uses a variety of real world examples to show how trade secrets are leaked online, and how organizational privacy is compromised by seemingly innocent use of The Internet.
	* [The Need for Identity Management - alienvault](https://www.alienvault.com/blogs/security-essentials/managing-pseudonyms-with-compartmentalization-identity-management-of-personas)
* **Reference/Resources**<a name="ref"></a>
	* [The Paranoid's Bible: An anti-dox effort.](https://paranoidsbible.tumblr.com/)
	* [Debian-Privacy-Server-Guide](https://github.com/drduh/Debian-Privacy-Server-Guide)
		* This is a step-by-step guide to configuring and managing a domain, remote server and hosted services, such as VPN, a private and obfuscated Tor bridge, and encrypted chat, using the Debian GNU/Linux operating system and other free software.
	* [Anonymous’s Guide to OpSec](http://www.covert.io/research-papers/security/Anonymous%20Hacking%20Group%20--%20OpNewblood-Super-Secret-Security-Handbook.pdf)
* **WiFi**<a name="wifi"></a>
	* [Wifi Tracking: Collecting the (probe) Breadcrumbs - David Switzer](https://www.youtube.com/watch?v=HzQHWUM8cNo)
		* Wifi probes have provided giggles via Karma and Wifi Pineapples for years, but is there more fun to be had? Like going from sitting next to someone on a bus, to knowing where they live and hang out? Why try to MITM someone’s wireless device in an enterprise environment where they may notice — when getting them at their favorite burger joint is much easier. In this talk we will review ways of collecting and analyzing probes. We’ll use the resulting data to figure out where people live, their daily habits, and discuss uses (some nice, some not so nice) for this information. We’ll also dicuss how to make yourself a little less easy to track using these methods. Stingrays are price prohibitive, but for just tracking people’s movements.. this is cheap and easy.
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
		* [Nipe](https://github.com/GouveaHeitor/nipe)
			* Nipe is a script to make Tor Network your default gateway.
	* **Papers**
		* [SkypeMorph: Protocol Obfuscation for Tor Bridges](https://www.cypherpunks.ca/~iang/pubs/skypemorph-ccs.pdf)
			* The Tor network is designed to provide users with low- latency anonymous communications. Tor clients build circuits with publicly listed relays to anonymously reach their destinations. However, since the relays are publicly listed, they can be easily blocked by censoring adversaries. Consequently, the Tor project envisioned the possibility of unlisted entry points to the Tor network, commonly known as bridges. We address the issue of preventing censors from detecting the bridges by observing the communications between them and nodes in their network. We propose a model in which the client obfuscates its messages to the bridge in a widely used protocol over the Inter- net. We investigate using Skype video calls as our target protocol and our goal is to make it difficult for the censor- ing adversary to distinguish between the obfuscated bridge connections and actual Skype calls using statistical compar- isons. We have implemented our model as a proof-of-concept pluggable transport for Tor, which is available under an open-source licence. Using this implementation we observed the obfuscated bridge communications and compared it with those of Skype calls and presented the results.
		* [StegoTorus: A Camouflage Proxy for the Tor Anonymity System](https://research.owlfolio.org/pubs/2012-stegotorus.pdf)
			* Internet censorship by governments is an increasingly common practice worldwide. Internet users and censors are locked in an arms race: as users find ways to evade censorship schemes, the censors develop countermeasures for the evasion tactics. One of the most popular and effective circumvention tools, Tor, must regularly adjust its network traffic signature to remain usable. We present StegoTorus, a tool that comprehensively disguises Tor from protocol analysis. To foil analysis of packet contents, Tor’s traffic is steganographed to resemble an innocuous cover protocol, such as HTTP. To foil analysis at the transport level, the Tor circuit is distributed over many shorter-lived connections with per-packet characteristics that mimic cover-protocol traffic. Our evaluation demonstrates that StegoTorus improves the resilience of Tor to fingerprinting attacks and delivers usable performance.
		* [Spoiled Onions](https://www.cs.kau.se/philwint/spoiled_onions/)
			* In this research project, we were monitoring all exit relays for several months in order to expose, document, and thwart malicious or misconfigured relays. In particular, we monitor exit relays with two scanners we developed specifically for that purpose: exitmap and HoneyConnector. Since September 2013, we discovered 65 malicious or misconfigured exit relays which are listed in Table 1 and Table 2 in our research paper. These exit relays engaged in various attacks such as SSH and HTTPS MitM, HTML injection, SSL stripping, and traffic sniffing. We also found exit relays which were unintentionally interfering with network traffic because they were subject to DNS censorship. 
* **Travel**<a name="travel"></a>
	* [China travel laptop setup](https://mricon.com/i/travel-laptop-setup.html?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&iid=88d246896d384d5292f51df954a2c8ba&uid=150127534&nid=244+272699400)
* **Misc/Unsorted**
	* [Cat Videos and the Death of Clear Text](https://citizenlab.org/2014/08/cat-video-and-the-death-of-clear-text/)
	* [You Are Being Tracked: How License Plate Readers Are Being Used to Record Americans' Movements - ACLU](https://www.aclu.org/other/you-are-being-tracked-how-license-plate-readers-are-being-used-record-americans-movements?redirect=technology-and-liberty/you-are-being-tracked-how-license-plate-readers-are-being-used-record)
	* [A Technical Description of Psiphon](https://psiphon.ca/en/blog/psiphon-a-technical-description)
	* **Papers**
		* [Deep-Spying: Spying using Smartwatch and Deep Learning - Tony Beltramelli](https://arxiv.org/pdf/1512.05616v1.pdf)
* **Miscellaneous Tools**<a name="tools-misc"></a>
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
	* [Decentraleyes](https://addons.mozilla.org/en-US/firefox/addon/decentraleyes/)
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





--------------------------
## <a name="counter"></a>Counter Surveillance
* **Articles**
* **Writeups**<a name="cwriteup"></a>
	* Detecting Surveillance - Spiderlabs blog
		* [1 Hardware Implants](http://blog.spiderlabs.com/2014/03/detecting-surveillance-state-surveillance-part-1-hardware-impants.html)
		* [2 Radio Frequency Exfiltration](http://blog.spiderlabs.com/2014/03/detecting-a-surveillance-state-part-2-radio-frequency-exfiltration.html)
		* [3 Infected Firmware](http://blog.spiderlabs.com/2014/04/detecting-a-surveillance-state-part-3-infected-firmware.html)
	* [A Simple Guide to TSCM Sweeps](http://www.international-intelligence.co.uk/tscm-sweep-guide.html)
	* [Dutch-Russian cyber crime case reveals how police tap the internet - ElectroSpaces](http://electrospaces.blogspot.de/2017/06/dutch-russian-cyber-crime-case-reveals.html?m=1)
* **Presentations/Talks/Videos**<a name="cvideos"></a>
	* [PISSED: Privacy In a Surveillance State Evading Detection - Joe Cicero - CYPHERCON11 ](https://www.youtube.com/watch?v=keA3WcKwZwA)
	* [Fuck These Guys: Practical Countersurveillance Lisa Lorenzin - BsidesSF15](http://www.irongeek.com/i.php?page=videos/bsidessf2015/201-fck-these-guys-practical-countersurveillance-lisa-lorenzin)
		* We've all seen the steady stream of revelations about the NSA's unconstitutional, illegal mass surveillance. Seems like there's a new transgression revealed every week! I'm getting outrage fatigue. So I decided to fight back... by looking for practical, realistic, everyday actions I can take to protect my privacy and civil liberties on the Internet, and sharing them with my friends. Join me in using encryption and privacy technology to resist eavesdropping and tracking, and to start to opt out of the bulk data collection that the NSA has unilaterally decided to secretly impose upon the world. Let's take back the Internet, one encrypted bit at a time.
	* [Dr. Philip Polstra - Am I Being Spied On?](https://www.youtube.com/watch?v=Bc7WoDXhcjM)
		* Talk on cheap/free counter measures
	* [DNS May Be Hazardous to Your Health - Robert Stucke](https://www.youtube.com/watch?v=ZPbyDSvGasw)
		* Great talk on attacking DNS
	* [Blinding The Surveillance State - Christopher Soghoian - DEF CON 22](https://www.youtube.com/watch?v=pM8e0Dbzopk)
	* [CounterStrike Lawful Interception](https://www.youtube.com/watch?v=7HXLaRWk1SM)
		* This short talk will cover the standards, devices and implementation of a mandatory part of our western Internet infrastructure. The central question is whether an overarching interception functionality might actually put national Internet infrastructure at a higher risk of being attacked successfully. The question is approached in this talk from a purely technical point of view, looking at how LI functionality is implemented by a major vendor and what issues arise from that implementation. Routers and other devices may get hurt in the process.
		* [Slides](http://phenoelit.org/stuff/CSLI.pdf)
	* [Detecting and Defending Against a Surveillance State - Robert Rowley - DEF CON 22](https://www.youtube.com/watch?v=d5jqV06Yijw)
	* [Retail Surveillance / Retail Countersurveillance 50 most unwanted retail surveillance technologies / 50 most wanted countersurveillance technologies](https://media.ccc.de/v/33c3-8238-retail_surveillance_retail_countersurveillance#video&t=1993)
	* [Masquerade: How a Helpful Man-in-the-Middle Can Help You Evade Monitoring** - Defcon22](https://www.youtube.com/watch?v=_KyfJW2lHtk&spfreload=1)
		* Sometimes, hiding the existence of a communication is as important as hiding the contents of that communication. While simple network tunneling such as Tor or a VPN can keep the contents of communications confidential, under active network monitoring or a restrictive IDS such tunnels are red flags which can subject the user to extreme scrutiny. Format-Transforming Encryption FTE can be used to tunnel traffic within otherwise innocuous protocols, keeping both the contents and existence of the sensitive traffic hidden.  However, more advanced automated intrusion detection, or moderately sophisticated manual inspection, raise other red flags when a host reporting to be a laser printer starts browsing the web or opening IM sessions, or when a machine which appears to be a Mac laptop sends network traffic using Windows-specific network settings.  We present Masquerade: a system which combines FTE and host OS profile selection to allow the user to emulate a user-selected operating system and application-set in network traffic and settings, evading both automated detection and frustrating after-the-fact analysis.
		* [Slides](https://www.portalmasq.com/portal-defcon.pdf)
	* [The NSA: Capabilities and Countermeasures** - Bruce Schneier - ShmooCon 2014](https://www.youtube.com/watch?v=D5JA8Ytk9EI)
		* Edward Snowden has given us an unprecedented window into the NSA's surveillance activities. Drawing from both the Snowden documents and revelations from previous whistleblowers, I will describe the sorts of surveillance the NSA does and how it does it. The emphasis is on the technical capabilities of the NSA, not the politics of their actions. This includes how it conducts Internet surveillance on the backbone, but is primarily focused on their offensive capabilities: packet injection attacks from the Internet backbone, exploits against endpoint computers and implants to exfiltrate information, fingerprinting computers through cookies and other means, and so on. I will then talk about what sorts of countermeasures are likely to frustrate the NSA. Basically, these are techniques to raise the cost of wholesale surveillance in favor of targeted surveillance: encryption, target hardening, dispersal, and so on.
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
	* [Ghostbuster: Detecting the Presence of Hidden Eavesdroppers]()https://synrg.csl.illinois.edu/papers/ghostbuster-mobicom18.pdf)]
* **Misc**
	* [Laser Surveillance Defeater - Shomer-Tec](https://www.shomer-tec.com/laser-surveillance-defeater.html)



--------------------------
### <a name="emissions"></a> Emissions Security 
* **101**
* **Articles/Blogposts/Writeups**
* **Presentations/Talks/Videos**
* **Papers**
	* [Com­pro­mi­sing Re­flec­tions - or - How to Read LCD Mo­ni­tors Around the Cor­ner- Micha­el Ba­ckes, Mar­kus Dür­muth, Do­mi­ni­que Unruh](https://kodu.ut.ee/~unruh/publications/reflections.pdf)
		* We present a novel eavesdropping technique for spying at a distance on data that is displayed on an arbitrary computer screen, including the currently prevalent LCD monitors. Our technique exploits reflections of the screen’s optical emanations in various objects that one commonly finds in close proximity to the screen and uses those reflections to recover the original screen content. Such objects include eyeglasses, tea pots, spoons, plastic bottles,  and even the eye of the user. We have demonstrated that this attack can be successfully mounted to spy on even small fonts using inexpensive, off-the-shelf equipment (less than 1500 dollars) from a distance of up to 10 meters. Relying on more expensive equipment allowed us to conduct this attack from over 30 meters away, demonstrating that similar at- tacks are feasible from the other side of the street or from a close-by building. We additionally establish theoretical limitations of the attack; these limitations may help to estimate the risk that this attack can be successfully mounted in a given environment.
	* [Acoustic Side-Channel Attacks on Printers -Michael Backes,Markus Drmuth,Sebastian Gerling,Manfred Pinkal,Caroline Sporleder](http://www.usenix.net/legacy/events/sec10/tech/full_papers/Backes.pdf)
		* We examine the problem of acoustic emanations of printers. We present a novel attack that recovers what a dot- matrix printer processing English text is printing based on a record of the sound it makes, if the microphone is close enough to the printer. In our experiments, the attack recovers up to 72% of printed  words, and up to 95% if we assume contextual knowledge about the text, with a microphone at a distance of 10 cm from the printer. After an upfront training phase, the attack is fully automated and uses a combination of machine learning, audio processing, and speech recognition techniques, including spectrum features, Hidden Markov Models and linear classification; moreover, it allows for feedback-based incremental learning. We evaluate the effectiveness of countermeasures, and we describe how we successfully mounted the attack in-field (with appropriate privacy protections) in a doctor’s practice to recover the content of medical prescriptions.
	* [Tempest in a Teapot: Compromising Reflections Revisited](http://www.mia.uni-saarland.de/Publications/backes-sp09.pdf)
		* Reflecting objects such as tea pots and glasses, but also diffusely reflecting objects such as a user’s shirt, can be used to spy on confidential data displayed on a monitor. First, we show how reflections in the user’s eye can be exploited for spying  on  confidential data. Second, we investigate to what extent monitor images can be reconstructed from the diffuse reflections on a wall or the user’s clothes, and provide information- theoretic bounds limiting this type of attack. Third, we evaluate the effectiveness of several countermeasures
	* [GSMem: Data Exfiltration from Air-Gapped Computers over GSM Frequencies - usenix conference](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-guri-update.pdf)
* **Tools**
* **Miscellaneous**


-------------------------
### <a name="modern"></a> Modern Surveillance
* **Vendors**
	* [buggedplanet.info](https://buggedplanet.info/index.php?title=Main_Page)
* **Articles**
	* [Understanding & Improving Privacy "Audits" under FTC Orders](https://cyberlaw.stanford.edu/blog/2018/04/understanding-improving-privacy-audits-under-ftc-orders)
		* This new white paper, entitled “Understanding and Improving Privacy ‘Audits’ under FTC Orders,” carefully parses the third-party audits that Google and Facebook are required to conduct under their 2012 Federal Trade Commission consent orders.  Using only publicly available documents, the article contrasts the FTC’s high expectations for the audits with what the FTC actually received (as released to the public in redacted form).   These audits, as a practical matter, are often the only “tooth” in FTC orders to protect consumer privacy.  They are critically important to accomplishing the agency’s privacy mission.  As such, a failure to attend to their robust enforcement can have unintended consequences, and arguably, provide consumers with a false sense of security. The paper shows how the audits are not actually audits as commonly understood.  Instead, because the FTC order language only requires third-party “assessments,” the companies submit reports that are termed “attestations.”  Attestations fundamentally rely on a few vague privacy program aspects that are self-selected by the companies themselves.  While the FTC could reject attestation-type assessments, the agency could also insist the companies bolster certain characteristics of the attestation assessments to make them more effective and replicate audit attributes.  For example, the FTC could require a broader and deeper scope for the assessments.  The agency could also require that assessors evaluate Fair Information Practices, data flows, notice/consent effectiveness, all company privacy assurances, and known order violations.
	* **China**<a name="china"></a>
		* [ China's Xinjiang Region A Surveillance State Unlike Any the World Has Ever Seen - Spiegel.de](http://www.spiegel.de/international/world/china-s-xinjiang-province-a-surveillance-state-unlike-any-the-world-has-ever-seen-a-1220174.html)
		* [China's 5 Steps for Recruiting Spies - Wired](https://www.wired.com/story/china-spy-recruitment-us/)
	* **France**
	* **Germany**
	* **United States**<a name="usa"></a>
	* **Japan**
		* [The Untold Story of Japan’s Secret Spy Agency - TheIntercept](https://theintercept.com/2018/05/19/japan-dfs-surveillance-agency/)
* **License Plate Tracking**
	* [Private companies know where you've been, thanks to license plate cameras - syracuse.com](https://www.syracuse.com/news/index.ssf/2015/01/private_companies_know_where_youve_been_thanks_to_license_plate_cameras.html)
* **Things**
	* [RF-Capture](http://rfcapture.csail.mit.edu/)
		* RF-Capture is a device that captures a human figure through walls and occlusions. It transmits wireless signals and reconstructs a human figure by analyzing the signals' reflections. RF-Capture does not require the person to wear any sensor, and its transmitted power is 10,000 times lower than that of a standard cell-phone.
		* [Paper](http://rfcapture.csail.mit.edu/rfcapture-paper.pdf)
















-----
### <a name="talks">General
* **General**
	* [Russia Convention on International Information Security](http://cryptome.org/2014/05/ru-international-infosec.htm)
	* [The Gentleperson’s Guide to Forum Spies](cryptome.org/2012/07/gent-forum-spies.htm)
	* [A Digital World Full of Ghost Armies](http://www.cigtr.info/2015/02/a-digital-world-full-of-ghost-armies.html)
* **Articles/BlogPosts/Writeups**
	* [25 Rules of Disinformation](http://vigilantcitizen.com/latestnews/the-25-rules-of-disinformation/)
	* [8 Traits of the Disinformationalist](https://calloutjoe.wordpress.com/psyop/eight-traits-of-the-disinformationalist/)
	* [Attribution As A Weapon & Marketing Tool: Hubris In INFOSEC & NATSEC](https://krypt3ia.wordpress.com/2014/12/30/attribution-as-a-weapon-marketing-tool-hubris-in-infosec-natsec/)
	* [Disinformation of Charlie Hebdo and The Fake BBC Website](http://thetrendythings.com/read/18256)
	* [Counterintelligence, False Flags, Disinformation, and Network Defense - krypt3ia](https://krypt3ia.wordpress.com/2012/10/17/counterintelligence-false-flags-disinformation-and-network-defense/)
	* [PsyOps and Socialbots](http://resources.infosecinstitute.com/psyops-and-socialbots/)
	* [IRA Code Words Spell Real Threat](https://articles.latimes.com/1997-04-19/news/mn-50393_1_code-words)
	* [‘A man who’s seen society's black underbelly’ Meduza meets ‘Anonymous International’](https://meduza.io/en/feature/2015/02/02/a-man-who-s-seen-society-s-black-underbelly)
	* [Down the Memory Hole: NYT Erases CIA’s Efforts to Overthrow Syria’s Government](https://web.archive.org/web/20150921054800id_/http://fair.org/home/down-the-memory-hole-nyt-erases-cias-efforts-to-overthrow-syrias-government/)
* **Talks**
	* [Governments and UFOs: A Historical Analysis of Disinformation and Deception - Richard Thieme](http://www.irongeek.com/i.php?page=videos/bsideslasvegas2013/1-2-7-governments-and-ufos-a-historical-analysis-of-disinformation-and-deception-richard-thieme)
	* [[TROOPERS15] Azhar Desai, Marco Slaviero - Weapons of Mass Distraction](https://www.youtube.com/watch?v=jdaPJLJCK1M)









### Sort

* [Pixel Tracking: How it’s used and abused - Barry Kimball(OISF19)](http://www.irongeek.com/i.php?page=videos/oisf2019/oisf-2019-05-pixel-tracking-how-its-used-and-abused-barry-kimball)
* [SyTech’s FSB Document Dump: Owning The Information Space and Disconnecting It - Krytp3ia](https://krypt3ia.wordpress.com/2019/08/03/sytechs-fsb-document-dump-owning-the-information-space-and-disconnecting-it/)
https://www.vice.com/en_us/article/3kx5y3/uzbekistan-hacking-operations-uncovered-due-to-spectacularly-bad-opsec
https://rastating.github.io/opsec-in-the-after-life/

https://github.com/VSCodium/vscodium/
http://tscm.com/
https://dat.foundation/
https://ssbc.github.io/scuttlebutt-protocol-guide/
http://www.servalproject.org/

* [DMVs Are Selling Your Data to Private Investigators - Joseph Cox(Vice)](https://www.vice.com/en_us/article/43kxzq/dmvs-selling-data-private-investigators-making-millions-of-dollars)

* [Create a Reusable Burner OS with Docker, Part 1: Making an Ubuntu Hacking Container - EvilToddler](https://null-byte.wonderhowto.com/how-to/create-reusable-burner-os-with-docker-part-1-making-ubuntu-hacking-container-0175328/)
	* [Part 2](https://null-byte.wonderhowto.com/how-to/create-reusable-burner-os-with-docker-part-2-customizing-our-hacking-container-0175353/)

https://citizenlab.ca/2019/07/cant-picture-this-2-an-analysis-of-wechats-realtime-image-filtering-in-chats/
https://citizenlab.ca/2018/08/cant-picture-this-an-analysis-of-image-filtering-on-wechat-moments/

Remove hidden data and personal information by inspecting documents, presentations, or workbooks
https://support.office.com/en-us/article/remove-hidden-data-and-personal-information-by-inspecting-documents-presentations-or-workbooks-356b7b5d-77af-44fe-a07f-9aa4d085966f

https://www.fcc.gov/public-safety-and-homeland-security/policy-and-licensing-division/911-services/general/location-accuracy-indoor-benchmarks
https://www.wsj.com/articles/SB105546175751598400
https://opaque.link/post/dropgang/
https://github.com/ctrlaltdev/LMGTFY-queries

* [A DC Think Tank Used Fake Social Media Accounts, A Bogus Expert, And Fancy Events To Reach The NSA, FBI, And White House - Craig Silverman(BuzzFeed News)](https://www.buzzfeednews.com/article/craigsilverman/icit-james-scott-think-tank-fake-twitter-youtube#.dnqv2lQJr)

* [Opting Out Like A Boss - The OSINT Way (Part 1) - learnallthethings.net](https://www.learnallthethings.net/blog/2018/1/23/opting-out-like-a-boss-the-osint-way)
https://electricalstrategies.com/about/in-the-news/spies-in-the-xerox-machine/
https://discover.cobbtechnologies.com/blog/the-soviet-union-and-the-photocopier

https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/privacy/manage-windows-1809-endpoints.md

* [Creating Your Own Citizen Database -  Aiganysh Aidarbekova](https://www.bellingcat.com/resources/how-tos/2019/02/14/creating-your-own-citizen-database/)

	* [Manage connections from Windows operating system components to Microsoft services - docs.ms](https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
* [Cookies – what does ‘good’ look like? - UK Information Comissioner's Office - Ali Shah](https://ico.org.uk/about-the-ico/news-and-events/news-and-blogs/2019/07/blog-cookies-what-does-good-look-like/)





https://www.eff.org/nsa-spying/nsadocs
https://www.freehaven.net/anonbib/
http://computer-outlines.over-blog.com/article-windows-ipv6-privacy-addresses-118018020.html

https://blog.superuser.com/2011/02/11/did-you-know-that-ipv6-may-include-your-mac-address-heres-how-to-stop-it/

https://www.bloomberg.com/news/articles/2018-08-30/google-and-mastercard-cut-a-secret-ad-deal-to-track-retail-sales

* [Ghostbuster: Detecting the Presence of Hidden Eavesdroppers](https://synrg.csl.illinois.edu/papers/ghostbuster-mobicom18.pdf)

* Propaganda
	* [Project Feels: How USA Today, ESPN and The New York Times are targeting ads to mood - digiday](https://digiday.com/media/project-feels-usa-today-espn-new-york-times-targeting-ads-mood/)
	* [The New York Times Advertising & Marketing Solutions Group Introduces ‘nytDEMO’: A Cross-Functional Team Focused on Bringing Insights and Data Solutions to Brands(2018)](https://investors.nytco.com/press/press-releases/press-release-details/2018/The-New-York-Times-Advertising--Marketing-Solutions-Group-Introduces-nytDEMO-A-Cross-Functional-Team-Focused-on-Bringing-Insights-and-Data-Solutions-to-Brands/default.aspx)

* [A DC Think Tank Used Fake Social Media Accounts, A Bogus Expert, And Fancy Events To Reach The NSA, FBI, And White House - Craig Silverman](https://www.buzzfeednews.com/article/craigsilverman/icit-james-scott-think-tank-fake-twitter-youtube#.dnqv2lQJr)

* [Toward an Information Operations Kill Chain - Bruce Schneier](https://www.lawfareblog.com/toward-information-operations-kill-chain)

* [Attacks on applications of k-anonymity for password retrieval - Jack Cable](https://cablej.io/blog/k-anonymity/)
* [Project Raven: Inside the UAE’s secret hacking team of American mercenaries(Christopher Bing, Joel Schectman)]

* [How to Purge Google and Start Over – Part 2 - Mike Felch](https://www.blackhillsinfosec.com/how-to-purge-google-and-start-over-part-2/)

* [Of Moles and Molehunters: A Review of Counterintelligence Literature, 1977-92](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/books-and-monographs/U-Oct%20%201993-%20Of%20Moles%20-%20Molehunters%20-%20A%20Review%20of%20Counterintelligence%20Literature-%201977-92%20-v2.pdf)

* [Salamandra](https://github.com/eldraco/Salamandra)
	* Salamandra is a tool to detect and locate spy microphones in closed environments. It find microphones based on the strength of the signal sent by the microphone and the amount of noise and overlapped frequencies. Based on the generated noise it can estimate how close or far away you are from the microphone.

* [zwsp-steg](https://github.com/offdev/zwsp-steg-js)
	* Zero-Width Space Steganography. Encodes and decodes hidden messages as non printable/readable characters. [A demo can be found here](https://offdev.net/demos/zwsp-steg-js).
* [DEDA](https://github.com/dfd-tud/deda)
	* DEDA - tracking Dots Extraction, Decoding and Anonymisation toolkit; Document Colour Tracking Dots, or yellow dots, are small systematic dots which encode information about the printer and/or the printout itself. This process is integrated in almost every commercial colour laser printer. This means that almost every printout contains coded information about the source device, such as the serial number.
	* https://dfd.inf.tu-dresden.de/
* [The Spy and the Traitor: The Greatest Espionage Story of the Cold War - cia.gov](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/csi-studies/studies/vol-63-no-1/spy_and_traitor.html)
* [How a Bitcoin Evangelist Made Himself Vanish, in 15 (Not So Easy) Steps - Nathaniel Popper](https://www.nytimes.com/2019/03/12/technology/how-to-disappear-surveillance-state.html)

* [A Glance through the VPN Looking Glass: IPv6 Leakage and DNS Hijacking in Commercial VPN clients - Vasile C. Perta, Marco V. Barbera, Gareth Tyson, Hamed Haddadi, and Alessandro Mei(2/2015)](https://www.petsymposium.org/2015/papers/02_Perta.pdf)

* [Forensic Analysis and Anonymisation of Printed Documents](https://dl.acm.org/citation.cfm?doid=3206004.3206019)
	* Contrary to popular belief, the paperless office has not yet established itself. Printer forensics is therefore still an important field today to protect the reliability of printed documents or to track criminals. An important task of this is to identify the source device of a printed document. There are many forensic approaches that try to determine the source device automatically and with commercially available recording devices. However, it is difficult to find intrinsic signatures that are robust against a variety of influences of the printing process and at the same time can identify the specific source device. In most cases, the identification rate only reaches up to the printer model. For this reason we reviewed document colour tracking dots, an extrinsic signature embedded in nearly all modern colour laser printers. We developed a refined and generic extraction algorithm, found a new tracking dot pattern and decoded pattern information. Through out we propose to reuse document colour tracking dots, in combination with passive printer forensic methods. From privacy perspective we additional investigated anonymization approaches to defeat arbitrary tracking. Finally we propose our toolkitdeda which implements the entire workflow of extracting, analysing and anonymisation of a tracking dot pattern.

* [NCCA Polygraph Countermeasure Course Files Leaked](https://antipolygraph.org/blog/2018/06/09/ncca-polygraph-countermeasure-course-files-leaked/)


* [Fooling automated surveillance cameras: adversarial patches to attack person detection - Simen Thys, Wiebe Van Ranst, Toon Goedemé](https://arxiv.org/abs/1904.08653)
	* Adversarial attacks on machine learning models have seen increasing interest in the past years. By making only subtle changes to the input of a convolutional neural network, the output of the network can be swayed to output a completely different result. The first attacks did this by changing pixel values of an input image slightly to fool a classifier to output the wrong class. Other approaches have tried to learn "patches" that can be applied to an object to fool detectors and classifiers. Some of these approaches have also shown that these attacks are feasible in the real-world, i.e. by modifying an object and filming it with a video camera. However, all of these approaches target classes that contain almost no intra-class variety (e.g. stop signs). The known structure of the object is then used to generate an adversarial patch on top of it. In this paper, we present an approach to generate adversarial patches to targets with lots of intra-class variety, namely persons. The goal is to generate a patch that is able successfully hide a person from a person detector. An attack that could for instance be used maliciously to circumvent surveillance systems, intruders can sneak around undetected by holding a small cardboard plate in front of their body aimed towards the surveillance camera. From our results we can see that our system is able significantly lower the accuracy of a person detector. Our approach also functions well in real-life scenarios where the patch is filmed by a camera. To the best of our knowledge we are the first to attempt this kind of attack on targets with a high level of intra-class variety like persons. 