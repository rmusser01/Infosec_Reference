# Exfiltration

## Table of Contents

* [General](#general)
* [Methodologies](#methods)
* [Writeups](#writeups)
* [Tools](#tools)
* [Papers](#papers)
* Stenography

##### Sort

Sort tools into categories of type, i.e. physical network, wireless(types thereof) etc.

* [SneakyCreeper](https://strikersecurity.com/blog/sneaky-creeper-data-exfiltration-overview/)
	* A Framework for Data Exfiltration
	* [Github](https://github.com/DakotaNelson/sneaky-creeper)
* [PacketWhisper](https://github.com/TryCatchHCF/PacketWhisper?mc_cid=065d80dbfd&mc_eid=f956a0c5ca)
	* Stealthily Transfer Data & Defeat Attribution Using DNS Queries & Text-Based Steganography, without the need for attacker-controlled Name Servers or domains; Evade DLP/MLS Devices; Defeat Data- & DNS Name Server Whitelisting Controls. Convert any file type (e.g. executables, Office, Zip, images) into a list of Fully Qualified Domain Names (FQDNs), use DNS queries to transfer data. Simple yet extremely effective.
* [GSMem: Data Exfiltration from Air-Gapped Computers over GSM Frequencies - usenix conference](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-guri-update.pdf)
https://github.com/moloch--/wire-transfer
##### End Sort
https://github.com/TarlogicSecurity/Arecibo
* [Secure WebDav Egress: AMZ EC2, Apache, and Let's Encrypt - Chris Patten](http://rift.stacktitan.com/alternate-unc-webdav-ssl-and-lets-encrypt/)
https://github.com/alcor/itty-bitty/



-----
### <a name="general">General</a>
* **General**
	* [HowTo: Data Exfiltration - windowsir.blogspot](https://windowsir.blogspot.com/2013/07/howto-data-exfiltration.html)
	* [Covert Channels in TCP/IP Protocol Stack - extended version-](https://eprints.ugd.edu.mk/10284/1/surveyAMBPselfArc.pdf)
	* [A Survey of Covert Channels and Countermeasures in Computer Network Protocols](http://caia.swin.edu.au/cv/szander/publications/szander-ieee-comst07.pdf)
		* Covert channels are used for the secret transfer of information. Encryption only protects communication from being decoded by unauthorised parties, whereas covert channels aim to hide the very existence of the communication. Initially, covert channels were identified as a security threat on monolithic systems i.e. mainframes. More recently focus has shifted towards covert channels in computer network protocols. The huge amount of data and vast number of different protocols in the Internet seems ideal as a high-bandwidth vehicle for covert communication. This article is a survey of the existing techniques for creating covert channels in widely deployed network and application protocols. We also give an overview of common methods for their detection, elimination, and capacity limitation, required to improve security in future computer networks. 
	* [Covert Timing Channels Based on HTTP Cache Headers - Video Presentation](https://www.youtube.com/watch?v=DOAG3mtz7H4)
		* [Covert Timing Channels Based on HTTP Cache Headers - Paper](https://scholarworks.rit.edu/cgi/viewcontent.cgi?filename=0&article=1784&context=other&type=additional)
* **Talks & Presentations**
	* [Boston BSides - Simple Data Exfiltration in a Secure Industry Environment - Phil Cronin](https://www.youtube.com/watch?v=IofUpzYZNko)
		* This presentaion explores the top 10 data exfiltration methods that can be accomplished with only ‘user-level’ privileges and that are routinely overlooked in security-conscious industries.
	* [Emanate Like A Boss: Generalized Covert Data Exfiltration With Funtenna](https://www.youtube.com/watch?v=-YXkgN2-JD4)
		* Funtenna is a software-only technique which causes intentional compromising emanation in a wide spectrum of modern computing hardware for the purpose of covert, reliable data exfiltration through secured and air-gapped networks. We present a generalized Funtenna technique that reliably encodes and emanates arbitrary data across wide portions of the electromagnetic spectrum, ranging from the sub-acoustic to RF and beyond. The Funtenna technique is hardware agnostic, can operate within nearly all modern computer systems and embedded devices, and is specifically intended to operate within hardware not designed to to act as RF transmitters. We believe that Funtenna is an advancement of current state-of-the-art covert wireless exfiltration technologies. Specifically, Funtenna offers comparable exfiltration capabilities to RF-based retro-reflectors, but can be realized without the need for physical implantation and illumination. We first present a brief survey of the history of compromising emanation research, followed by a discussion of the theoretical mechanisms of Funtenna and intentionally induced compromising emanation in general. Lastly, we demonstrate implementations of Funtenna as small software implants within several ubiquitous embedded devices, such as VoIP phones and printers, and in common computer peripherals, such as hard disks, console ports, network interface cards and more.
	* [Data Exfiltration: Secret Chat Application Using Wi-Fi Covert Channel by Yago Hansen at the BSidesMunich 2017](https://www.youtube.com/watch?v=-cSu63s4zPY)
	* [Itzik Kotler | Goodbye Data, Hello Exfiltration - BSides Orlando](https://www.youtube.com/watch?v=GwaIvm2HJKc)
		* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.
	* [In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HiTB2016](https://www.youtube.com/watch?v=T6PscV43C0w)
		* In this session, we will reveal and demonstrate perfect exfiltration via indirect covert channels (i.e. the communicating parties don’t directly exchange network packets). This is a family of techniques to exfiltrate data (low throughput) from an enterprise in a manner indistinguishable from genuine traffic. Using HTTP and exploiting a byproduct of how some websites choose to cache their pages, we will demonstrate how data can be leaked without raising any suspicion. These techniques are designed to overcome even perfect knowledge and analysis of the enterprise network traffic.
	* [Can You Hear Me Now?!? Thoery of SIGTRAN Stego. BSidesPHX 2012](https://www.youtube.com/watch?v=vzpzL-UlpdA)
		* Ever wanted to know how to communicate with someone and not be heard? As many know, the internal cellular network uses SS7 and SIGTRAN to communicate via out-of-band signalling. What many don't know is what can be done with this. CC-MSOBS (Covert Channel via Multi-Streaming Out of Band Signalling) is a new form of covert communication which can be utilized by taking advantage of the multi-streaming aspects of SCTP and the using it with the out-of-band signalling capabilities of SIGTRAN. Come explore this developing covert channel as Drew Porter covers not only his idea but also his current research on this new covert channel. 
	* [Ma­gne­tic Side- and Co­vert-Chan­nels using Smart­pho­ne Ma­gne­tic Sen­sors](https://www.youtube.com/watch?v=-LZJqRXZ2OM)
		* Side- and co­vert-chan­nels are un­in­ten­tio­nal com­mu­ni­ca­ti­on chan­nels that can leak in­for­ma­ti­on about ope­ra­ti­ons being per­for­med on a com­pu­ter, or serve as means of secre­te com­mi­na­ti­on bet­ween at­ta­ckers, re­spec­tive­ly. This pre­sen­ta­ti­on will di­s­cuss re­cent, new side- and co­vert-chan­nels uti­li­zing smart­pho­ne ma­gne­tic sen­sors. In par­ti­cu­lar, our work on these chan­nels has shown that sen­sors outside of a com­pu­ter hard drive can pick up the ma­gne­tic fields due to the mo­ving hard disk head. With these me­a­su­re­ments, we are able to de­du­ce pat­terns about on­go­ing ope­ra­ti­ons, such as de­tect what type of the ope­ra­ting sys­tem is boo­ting up or what ap­p­li­ca­ti­on is being star­ted. Mo­re­over, by in­du­cing elec­tro­ma­gne­tic si­gnals from a com­pu­ter in a con­trol­led way, at­ta­ckers can mo­du­la­te and trans­mit ar­bi­tra­ry bi­na­ry data over the air. We show that mo­dern smart­pho­nes are able to de­tect dis­tur­ban­ces in the ma­gne­tic field at a dis­tan­ce of dozen or more cm from the com­pu­ter, and can act as re­cei­vers of the trans­mit­ted in­for­ma­ti­on. Our me­thods do not re­qui­re any ad­di­tio­nal equip­ment, firm­ware mo­di­fi­ca­ti­ons or pri­vi­le­ged ac­cess on eit­her the com­pu­ter (sen­der) or the smart­pho­ne (re­cei­ver). Based on the thre­ats, po­ten­ti­al coun­ter-me­a­su­res will be pre­sen­ted that can miti­ga­te some of the chan­nels.
	* [[DS15] Bridging the Air Gap Data Exfiltration from Air Gap Networks - Mordechai Guri & Yisroel Mirsky](https://www.youtube.com/watch?v=bThJEX4l_Ks)
		* Air-gapped networks are isolated, separated both logically and physically from public networks. Although the feasibility of invading such systems has been demonstrated in recent years, exfiltration of data from air-gapped networks is still a challenging task. In this talk we present GSMem, a malware that can exfiltrate data through an air-gap over cellular frequencies. Rogue software on an infected target computer modulates and transmits electromagnetic signals at cellular frequencies by invoking specific memory-related instructions and utilizing the multichannel memory architecture to amplify the transmission. Furthermore, we show that the transmitted signals can be received and demodulated by a rootkit placed in the baseband firmware of a nearby cellular phone. We present crucial design issues such as signal generation and reception, data modulation, and transmission detection. We implement a prototype of GSMem consisting of a transmitter and a receiver and evaluate its performance and limitations. Our current results demonstrate its efficacy and feasibility, achieving an effective transmission distance of 1-5.5 meters with a standard mobile phone. When using a dedicated, yet affordable hardware receiver, the effective distance reached over 30 meters.
	* [Inter-VM Data Exfiltration: The Art of Cache Timing Covert Channel on x86 Multi-Core - Etienne Martineau](https://www.youtube.com/watch?v=SGqUGHh3UZM)
		* On x86 multi-core covert channels between co-located Virtual Machine (VM) are real and practical thanks to the architecture that has many imperfections in the way shared resources are isolated. This talk will demonstrate how a non-privileged application from one VM can ex-filtrate data or even establish a reverse shell into a co-located VM using a cache timing covert channel that is totally hidden from the standard access control mechanisms while being able to offer surprisingly high bps at a low error rate. In this talk you’ll learn about the various concepts, techniques and challenges involve in the design of a cache timing covert channel on x86 multi-core such as: X86 shared resources and fundamental concept behind cache line encoding / decoding. Getting around the hardware pre-fetching logic ( without disabling it from the BIOS! ) Abusing the X86 ‘clflush’ instruction. Bi-directional handshake for free! Data persistency and noise. What can be done? Guest to host page table de-obfuscation. The easy way, the VM’s vendors defense and another way to get around it. Phase Lock Loop and high precision inter-VM synchronization. All about timers. At the end of this talk we will go over a working VM to VM reverse shell example as well as some surprising bandwidth measurement results. We will also cover the detection aspect and the potential countermeasure to defeat such a communication channel.
	* [Bridging the Air Gap Data Exfiltration from Air Gap Networks - DS15](https://www.youtube.com/watch?v=bThJEX4l_Ks)
	* [Covert Timing Channels Based on HTTP Cache Headers](https://www.youtube.com/watch?v=DOAG3mtz7H4)
	* [In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HITB16](https://www.youtube.com/watch?v=T6PscV43C0w)
* **Tools**
	* [iodine](https://github.com/yarrick/iodine)
		* This is a piece of software that lets you tunnel IPv4 data through a DNS server. This can be usable in different situations where internet access is firewalled, but DNS queries are allowed.
	* [dnscat2](https://github.com/iagox86/dnscat2)
		* Welcome to dnscat2, a DNS tunnel that WON'T make you sick and kill you!  This tool is designed to create a command-and-control (C&C) channel over the DNS protocol, which is an effective tunnel out of almost every network.
	* [fraud-bridge](https://github.com/stealth/fraud-bridge) 
		* fraud-bridge allows to tunnel TCP connections through ICMP, ICMPv6, DNS via UDP or DNS via UDP6. Project, not stable
	* [PyExfil](https://ytisf.github.io/PyExfil/)
		* Exfiltration tools inspired by Regin. Alpha Status.
	* [Exfil - Modular tool to test exfiltration techniques](https://github.com/averagesecurityguy/exfil)
		* Exfil is a tool designed to exfiltrate data using various techniques, which allows a security team to test whether its monitoring system can effectively catch the exfiltration. The idea for Exfil came from a Twitter conversation between @averagesecguy, @ChrisJohnRiley, and @Ben0xA and was sparked by the TrustWave POS malware whitepaper available at https://gsr.trustwave.com/topics/placeholder-topic/point-of-sale-malware/.
	* [Multitun](https://github.com/covertcodes/multitun) 
		* Efficiently and securely tunnel everything over a harmless looking WebSocket!
	* [Data Exfiltration Toolkit(DET)](https://github.com/sensepost/det)
		* DET (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time. This is a Proof of Concept aimed at identifying possible DLP failures. This should never be used to exfiltrate sensitive/live data (say on an assessment) The idea was to create a generic toolkit to plug any kind of protocol/service to test implmented Network Monitoring and Data Leakage Prevention (DLP) solutions configuration, against different data exfiltration techniques.
	* [canisrufus](https://github.com/maldevel/canisrufus)
		* A stealthy Python based Windows backdoor that uses Github as a command and control server
	* [Stunnel](https://www.stunnel.org/index.html)
		* [Stunnel TLS Proxy](https://www.stunnel.org/static/stunnel.html)
	* [dnsftp](https://github.com/breenmachine/dnsftp)
		* Client/Server scripts to transfer files over DNS. Client scripts are small and only use native tools on the host OS.
	* [tcpovericmp](https://github.com/Maksadbek/tcpovericmp)
		* TCP implementation over ICMP protocol to bypass firewalls
	* [icmptunnel](https://github.com/DhavalKapil/icmptunnel)
		* Transparently tunnel your IP traffic through ICMP echo and reply packets.
	* [Outgoing port tester - http://letmeoutofyour.net/](http://letmeoutofyour.net/)	
		* [Outgoing port tester - portquiz.net](http://portquiz.net/)
		*  This server listens on all TCP ports, allowing you to test any outbound TCP port.
	* [CloakifyFactory](https://github.com/TryCatchHCF/Cloakify)
		* CloakifyFactory & the Cloakify Toolset - Data Exfiltration & Infiltration In Plain Sight; Evade DLP/MLS Devices; Social Engineering of Analysts; Defeat Data Whitelisting Controls; Evade AV Detection. Text-based steganography usings lists. Convert any file type (e.g. executables, Office, Zip, images) into a list of everyday strings. Very simple tools, powerful concept, limited only by your imagination.
	* [QRCode-Video-Data-Exfiltration](https://github.com/Neohapsis/QRCode-Video-Data-Exfiltration)
		* Exfiltrate data with QR code videos generated from files by HTML5/JS.
	* [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator)
		* DNSExfiltrator allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel.
	* [system-bus-radio](https://github.com/fulldecent/system-bus-radio)
		* Transmits AM radio on computers without radio transmitting hardware.
	* [Data Exfiltration Toolkit(DET)](https://github.com/PaulSec/DET)
		* DET (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time. The idea was to create a generic toolkit to plug any kind of protocol/service to test implmented Network Monitoring and Data Leakage Prevention (DLP) solutions configuration, against different data exfiltration techniques.
	* [EGRESSION](https://github.com/danielmiessler/egression)
		* EGRESSION is a tool that provides an instant view of how easy it is to upload sensitive data from any given network.
	* [Data Exfil Toolkit](https://github.com/conix-security/DET)
		* DET (is provided AS IS), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time. The idea was to create a generic toolkit to plug any kind of protocol/service.
	* [PyExfil](https://github.com/ytisf/PyExfil)
		* This started as a PoC project but has later turned into something a bit more. Currently it's an Alpha-Alpha stage package, not yet tested (and will appriciate any feedbacks and commits) designed to show several techniques of data exfiltration is real world scenarios.
	* [pingfs - "True cloud storage" - Erin Ekman](https://github.com/yarrick/pingfs)
		*  pingfs is a filesystem where the data is stored only in the Internet itself, as ICMP Echo packets (pings) travelling from you to remote servers and back again. It is implemented using raw sockets and FUSE, so superuser powers are required. Linux is the only intended target OS, portability is not a goal. Both IPv4 and IPv6 remote hosts are supported.
	* [Egress-Assess](https://github.com/ChrisTruncer/Egress-Assess)
		* Egress-Assess is a tool used to test egress data detection capabilities.
		* [Egress-Assess – Testing your Egress Data Detection Capabilities](https://www.christophertruncer.com/egress-assess-testing-egress-data-detection-capabilities/)
		* [Egress-Assess in Action via Powershell](https://www.christophertruncer.com/egress-assess-action-via-powershell/)
	* [QRXfer](https://github.com/leonjza/qrxfer)
		* Transfer files from Air gapped machines using QR codes
	* [icmptunnel](https://github.com/DhavalKapil/icmptunnel)
		* 'icmptunnel' works by encapsulating your IP traffic in ICMP echo packets and sending them to your own proxy server. The proxy server decapsulates the packet and forwards the IP traffic. The incoming IP packets which are destined for the client are again encapsulated in ICMP reply packets and sent back to the client. The IP traffic is sent in the 'data' field of ICMP packets. [RFC 792](http://www.ietf.org/rfc/rfc792.txt), which is IETF's rules governing ICMP packets, allows for an arbitrary data length for any type 0 (echo reply) or 8 (echo message) ICMP packets. So basically the client machine uses only the ICMP protocol to communicate with the proxy server. Applications running on the client machine are oblivious to this fact and work seamlessly.
	* [org.quietmodem.Quiet](https://github.com/quiet/org.quietmodem.Quiet)
		* org.quietmodem.Quiet allows you to pass data through the speakers on your Android device. This library can operate either as a raw frame layer or as a UDP/TCP stack.
* **Articles/Papers/Writeups**
	* [Self-Exfiltration: The Dangers of Browser-Enforced Information Flow Control](http://ericchen.me/self_exfiltration.pdf)
		* Abstract —Since the early days of Netscape, browser vendors and web security researchers have restricted out-going data based on its destination. The security argument accompanying these mechanisms is that they prevent sensitive user data from being sent to the attacker’s domain. However, in this paper, we show that regulating web information flow based on its destination server is an inherently flawed security practice. It is vulnerable to self-exfiltration attacks, where an adversary stashes stolen information in the database of a whitelisted site, then later independently connects to the whitelisted site to retrieve the information. We describe eight existing browser security mechanisms that are vulnerable to these “self-exfiltration” attacks. Furthermore, we discovered at least one exfiltration channel for each of the Alexa top 100 websites. None of the existing information flow control mechanisms we surveyed are sufficient to protect data from being leaked to the attacker. Our goal is to prevent browser vendors and researchers from falling into this trap by designing more systems that are vulnerable to self-exfiltration.
	* [GSMem: Data Exfiltration from Air-Gapped Computers over GSM Frequencies](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-guri-update.pdf)
	* [Covert Channels in the TCP/IP Protocol Suite](http://ojphi.org/ojs/index.php/fm/article/view/528/449)
	* [Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](http://cs.unc.edu/~fabian/course_papers/PtacekNewsham98.pdf)
	* [Covert Channels - Communicating over TCP without the initial 3-way handshake](https://securitynik.blogspot.ca/2014/04/covert-channels-communicating-over-tcp.html)
	* [Covert Channels - Part 2 - exfiltrating data through TCP Sequence Number field](https://securitynik.blogspot.com/2015/12/covert-channels-part-2-exfiltrating.html)
	* [Data Exfiltration (Tunneling) Attacks against Corporate Network](https://pentest.blog/data-exfiltration-tunneling-attacks-against-corporate-network/)
	* [Using DNS to Break Out of Isolated Networks in a AWS Cloud Environment](https://dejandayoff.com/using-dns-to-break-out-of-isolated-networks-in-a-aws-cloud-environment/)
		* Customers can utilize AWS' DNS infrastructure in VPCs (enabled by default). Traffic destined to the AmazonProvidedDNS is traffic bound for AWS management infrastructure and does not egress via the same network links as standard customer traffic and is not evaluated by Security Groups. Using DNS exfiltration, it is possible to exfiltrate data out of an isolated network.
	* [Evasions used by The Shadow Brokers' Tools DanderSpritz and DoublePulsar (Part 2 of 2) - forcepoint](https://blogs.forcepoint.com/security-labs/evasions-used-shadow-brokers-tools-danderspritz-and-doublepulsar-part-2-2)
	* [Self-Exfiltration: The Dangers of Browser-Enforced Information Flow Control](http://ericchen.me/self_exfiltration.pdf)
		* Abstract —Since the early days of Netscape, browser vendors and web security researchers have restricted out-going data based on its destination. The security argument accompanying these mechanisms is that they prevent sensitive user data from being sent to the attacker’s domain. However, in this paper, we show that regulating web information flow based on its destination server is an inherently flawed security practice. It is vulnerable to self-exfiltration attacks, where an adversary stashes stolen information in the database of a whitelisted site, then later independently connects to the whitelisted site to retrieve the information. We describe eight existing browser security mechanisms that are vulnerable to these “self-exfiltration” attacks. Furthermore, we discovered at least one exfiltration channel for each of the Alexa top 100 websites. None of the existing information flow control mechanisms we surveyed are sufficient to protect data from being leaked to the attacker. Our goal is to prevent browser vendors and researchers from falling into this trap by designing more systems that are vulnerable to self-exfiltration.
* **Stenography**
    * [imagejs](https://github.com/jklmnn/imagejs)
	   * imagejs is a small tool to hide javascript inside a valid image file. The image file is recognized as one by content checking software, e.g. the file command you might now from Linux or other Unix based operation systems.
    * [Real-time Steganography with RTP](http://uninformed.org/?v=all&a=36&t=sumry)
	   * Real-time Transfer Protocol (RTP) is used by nearly all Voice-over-IP systems to provide the audio channel for calls. As such, it provides ample opportunity for the creation of a covert communication channel due to its very nature. While use of steganographic techniques with various audio cover-medium has been extensively researched, most applications of such have been limited to audio cover-medium of a static nature such as WAV or MP3 file audio data. This paper details a common technique for the use of steganography with audio data cover-medium, outlines the problem issues that arise when attempting to use such techniques to establish a full-duplex communications channel within audio data transmitted via an unreliable streaming protocol, and documents solutions to these problems. An implementation of the ideas discussed entitled SteganRTP is included in the reference materials.
	* [Stegano](https://github.com/cedricbonhomme/Stegano)
		* Steganography is the art and science of writing hidden messages in such a way that no one, apart from the sender and intended recipient, suspects the existence of the message, a form of security through obscurity. Consequently, functions provided by Stéganô only hide messages, without encryption. Steganography is often used with cryptography.