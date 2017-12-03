# Exfiltration

### TOC

* [General](#general)
* [Methodologies](#methods)
* [Writeups](#writeups)
* [Tools](#tools)
* [Papers](#papers)

### Cull

### General

* [HowTo: Data Exfiltration - windowsir.blogspot](https://windowsir.blogspot.com/2013/07/howto-data-exfiltration.html)
* [Covert Channels in TCP/IP Protocol Stack - extended version-](https://eprints.ugd.edu.mk/10284/1/surveyAMBPselfArc.pdf)
* [A Survey of Covert Channels and Countermeasures in Computer Network Protocols](http://caia.swin.edu.au/cv/szander/publications/szander-ieee-comst07.pdf)

  * Covert channels are used for the secret transfer of information. Encryption
    only protects communication from being decoded by unauthorised parties,
    whereas covert channels aim to hide the very existence of the communication.
    Initially, covert channels were identified as a security threat on
    monolithic systems i.e. mainframes. More recently focus has shifted towards
    covert channels in computer network protocols. The huge amount of data and
    vast number of different protocols in the Internet seems ideal as a
    high-bandwidth vehicle for covert communication. This article is a survey of
    the existing techniques for creating covert channels in widely deployed
    network and application protocols. We also give an overview of common
    methods for their detection, elimination, and capacity limitation, required
    to improve security in future computer networks.

* [Covert Timing Channels Based on HTTP Cache Headers - Video Presentation](https://www.youtube.com/watch?v=DOAG3mtz7H4)

  * [Covert Timing Channels Based on HTTP Cache Headers - Paper](https://scholarworks.rit.edu/cgi/viewcontent.cgi?filename=0&article=1784&context=other&type=additional)

### Talks & Presentations

* [Boston BSides - Simple Data Exfiltration in a Secure Industry Environment - Phil Cronin](https://www.youtube.com/watch?v=IofUpzYZNko)

  * This presentaion explores the top 10 data exfiltration methods that can be
    accomplished with only user-level privileges and that are routinely
    overlooked in security-conscious industries.

* [Emanate Like A Boss: Generalized Covert Data Exfiltration With Funtenna](https://www.youtube.com/watch?v=-YXkgN2-JD4)

  * Funtenna is a software-only technique which causes intentional compromising
    emanation in a wide spectrum of modern computing hardware for the purpose of
    covert, reliable data exfiltration through secured and air-gapped networks.
    We present a generalized Funtenna technique that reliably encodes and
    emanates arbitrary data across wide portions of the electromagnetic
    spectrum, ranging from the sub-acoustic to RF and beyond. The Funtenna
    technique is hardware agnostic, can operate within nearly all modern
    computer systems and embedded devices, and is specifically intended to
    operate within hardware not designed to to act as RF transmitters. We
    believe that Funtenna is an advancement of current state-of-the-art covert
    wireless exfiltration technologies. Specifically, Funtenna offers comparable
    exfiltration capabilities to RF-based retro-reflectors, but can be realized
    without the need for physical implantation and illumination. We first
    present a brief survey of the history of compromising emanation research,
    followed by a discussion of the theoretical mechanisms of Funtenna and
    intentionally induced compromising emanation in general. Lastly, we
    demonstrate implementations of Funtenna as small software implants within
    several ubiquitous embedded devices, such as VoIP phones and printers, and
    in common computer peripherals, such as hard disks, console ports, network
    interface cards and more.

* [Data Exfiltration: Secret Chat Application Using Wi-Fi Covert Channel by Yago Hansen at the BSidesMunich 2017](https://www.youtube.com/watch?v=-cSu63s4zPY)
* [Itzik Kotler | Goodbye Data, Hello Exfiltration - BSides Orlando](https://www.youtube.com/watch?v=GwaIvm2HJKc)

  * Penetration testing isnt about getting in, its also about getting out with
    the goodies. In this talk, you will learn how leverage commonly installed
    software (not Kali Linux!) to exfiltrate data from networks. Moving on to
    more advanced methods that combines encryption, obfuscation, splitting (and
    Python). Last but not least, Ill address data exfiltration via physical
    ports and demo one out-of-the-box method to do it.

* [In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HiTB2016](https://www.youtube.com/watch?v=T6PscV43C0w)

  * In this session, we will reveal and demonstrate perfect exfiltration via
    indirect covert channels (i.e. the communicating parties dont directly
    exchange network packets). This is a family of techniques to exfiltrate data
    (low throughput) from an enterprise in a manner indistinguishable from
    genuine traffic. Using HTTP and exploiting a byproduct of how some websites
    choose to cache their pages, we will demonstrate how data can be leaked
    without raising any suspicion. These techniques are designed to overcome
    even perfect knowledge and analysis of the enterprise network traffic.

* [Can You Hear Me Now?!? Thoery of SIGTRAN Stego. BSidesPHX 2012](https://www.youtube.com/watch?v=vzpzL-UlpdA)

  * Ever wanted to know how to communicate with someone and not be heard? As
    many know, the internal cellular network uses SS7 and SIGTRAN to communicate
    via out-of-band signalling. What many don't know is what can be done with
    this. CC-MSOBS (Covert Channel via Multi-Streaming Out of Band Signalling)
    is a new form of covert communication which can be utilized by taking
    advantage of the multi-streaming aspects of SCTP and the using it with the
    out-of-band signalling capabilities of SIGTRAN. Come explore this developing
    covert channel as Drew Porter covers not only his idea but also his current
    research on this new covert channel.

* [Magnetic Side- and Covert-Channels using Smartphone Magnetic Sensors](https://www.youtube.com/watch?v=-LZJqRXZ2OM)

  * Side- and covert-channels are unintentional communication channels that can
    leak information about operations being performed on a computer, or serve as
    means of secrete commination between attackers, respectively. This
    presentation will discuss recent, new side- and covert-channels utilizing
    smartphone magnetic sensors. In particular, our work on these channels has
    shown that sensors outside of a computer hard drive can pick up the magnetic
    fields due to the moving hard disk head. With these measurements, we are
    able to deduce patterns about ongoing operations, such as detect what type
    of the operating system is booting up or what application is being started.
    Moreover, by inducing electromagnetic signals from a computer in a
    controlled way, attackers can modulate and transmit arbitrary binary data
    over the air. We show that modern smartphones are able to detect
    disturbances in the magnetic field at a distance of dozen or more cm from
    the computer, and can act as receivers of the transmitted information. Our
    methods do not require any additional equipment, firmware modifications or
    privileged access on either the computer (sender) or the smartphone
    (receiver). Based on the threats, potential counter-measures will be
    presented that can mitigate some of the channels.

* [[DS15] Bridging the Air Gap Data Exfiltration from Air Gap Networks - Mordechai Guri & Yisroel Mirsky](https://www.youtube.com/watch?v=bThJEX4l_Ks)

  * Air-gapped networks are isolated, separated both logically and physically
    from public networks. Although the feasibility of invading such systems has
    been demonstrated in recent years, exfiltration of data from air-gapped
    networks is still a challenging task. In this talk we present GSMem, a
    malware that can exfiltrate data through an air-gap over cellular
    frequencies. Rogue software on an infected target computer modulates and
    transmits electromagnetic signals at cellular frequencies by invoking
    specific memory-related instructions and utilizing the multichannel memory
    architecture to amplify the transmission. Furthermore, we show that the
    transmitted signals can be received and demodulated by a rootkit placed in
    the baseband firmware of a nearby cellular phone. We present crucial design
    issues such as signal generation and reception, data modulation, and
    transmission detection. We implement a prototype of GSMem consisting of a
    transmitter and a receiver and evaluate its performance and limitations. Our
    current results demonstrate its efficacy and feasibility, achieving an
    effective transmission distance of 1-5.5 meters with a standard mobile
    phone. When using a dedicated, yet affordable hardware receiver, the
    effective distance reached over 30 meters.

* [Inter VM Data Exfiltration: The Art of Cache Timing Covert Channel on x86 Multi-Core - Etienne Martineau](https://www.youtube.com/watch?v=SGqUGHh3UZM)

  * On x86 multi-core covert channels between co-located Virtual Machine (VM)
    are real and practical thanks to the architecture that has many
    imperfections in the way shared resources are isolated. This talk will
    demonstrate how a non-privileged application from one VM can ex-filtrate
    data or even establish a reverse shell into a co-located VM using a cache
    timing covert channel that is totally hidden from the standard access
    control mechanisms while being able to offer surprisingly high bps at a low
    error rate. In this talk youll learn about the various concepts, techniques
    and challenges involve in the design of a cache timing covert channel on x86
    multi-core such as: X86 shared resources and fundamental concept behind
    cache line encoding / decoding. Getting around the hardware pre-fetching
    logic ( without disabling it from the BIOS! ) Abusing the X86 clflush
    instruction. Bi-directional handshake for free! Data persistency and noise.
    What can be done? Guest to host page table de-obfuscation. The easy way, the
    VMs vendors defense and another way to get around it. Phase Lock Loop and
    high precision inter-VM synchronization. All about timers. At the end of
    this talk we will go over a working VM to VM reverse shell example as well
    as some surprising bandwidth measurement results. We will also cover the
    detection aspect and the potential countermeasure to defeat such a
    communication channel.

* [Bridging the Air Gap Data Exfiltration from Air Gap Networks - DS15](https://www.youtube.com/watch?v=bThJEX4l_Ks)
* [Covert Timing Channels Based on HTTP Cache Headers](https://www.youtube.com/watch?v=DOAG3mtz7H4)
* [In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HITB16](https://www.youtube.com/watch?v=T6PscV43C0w)

### Writeups

* [Data Exfiltration (Tunneling) Attacks against Corporate Network](https://pentest.blog/data-exfiltration-tunneling-attacks-against-corporate-network/)

### Tools

* [iodine](https://github.com/yarrick/iodine)

  * This is a piece of software that lets you tunnel IPv4 data through a DNS
    server. This can be usable in different situations where internet access is
    firewalled, but DNS queries are allowed.

* [dnscat2](https://github.com/iagox86/dnscat2)

  * Welcome to dnscat2, a DNS tunnel that WON'T make you sick and kill you! This
    tool is designed to create a command-and-control (C&C) channel over the DNS
    protocol, which is an effective tunnel out of almost every network.

* [fraud-bridge](https://github.com/stealth/fraud-bridge)

  * fraud-bridge allows to tunnel TCP connections through ICMP, ICMPv6, DNS via
    UDP or DNS via UDP6. Project, not stable

* [PyExfil](https://ytisf.github.io/PyExfil/)

  * Exfiltration tools inspired by Regin. Alpha Status.

* [Exfil - Modular tool to test exfiltration techniques](https://github.com/averagesecurityguy/exfil)

  * Exfil is a tool designed to exfiltrate data using various techniques, which
    allows a security team to test whether its monitoring system can effectively
    catch the exfiltration. The idea for Exfil came from a Twitter conversation
    between @averagesecguy, @ChrisJohnRiley, and @Ben0xA and was sparked by the
    TrustWave POS malware whitepaper available at
    https://gsr.trustwave.com/topics/placeholder-topic/point-of-sale-malware/.

* [Multitun](https://github.com/covertcodes/multitun)

  * Efficiently and securely tunnel everything over a harmless looking
    WebSocket!

* [Data Exfiltration Toolkit(DET)](https://github.com/sensepost/det)

  * DET (is provided AS IS), is a proof of concept to perform Data Exfiltration
    using either single or multiple channel(s) at the same time. This is a Proof
    of Concept aimed at identifying possible DLP failures. This should never be
    used to exfiltrate sensitive/live data (say on an assessment) The idea was
    to create a generic toolkit to plug any kind of protocol/service to test
    implmented Network Monitoring and Data Leakage Prevention (DLP) solutions
    configuration, against different data exfiltration techniques.

* [canisrufus](https://github.com/maldevel/canisrufus)

  * A stealthy Python based Windows backdoor that uses Github as a command and
    control server

* [Stunnel](https://www.stunnel.org/index.html)

  * [Stunnel TLS Proxy](https://www.stunnel.org/static/stunnel.html)

* [dnsftp](https://github.com/breenmachine/dnsftp)

  * Client/Server scripts to transfer files over DNS. Client scripts are small
    and only use native tools on the host OS.

* [tcpovericmp](https://github.com/Maksadbek/tcpovericmp)

  * TCP implementation over ICMP protocol to bypass firewalls

* [icmptunnel](https://github.com/DhavalKapil/icmptunnel)

  * Transparently tunnel your IP traffic through ICMP echo and reply packets.

* [Outgoing port tester - http://letmeoutofyour.net/](http://letmeoutofyour.net/)

  * [Outgoing port tester - portquiz.net](http://portquiz.net/)
  * This server listens on all TCP ports, allowing you to test any outbound TCP
    port.

* [CloakifyFactory](https://github.com/TryCatchHCF/Cloakify)

  * CloakifyFactory & the Cloakify Toolset - Data Exfiltration & Infiltration In
    Plain Sight; Evade DLP/MLS Devices; Social Engineering of Analysts; Defeat
    Data Whitelisting Controls; Evade AV Detection. Text-based steganography
    usings lists. Convert any file type (e.g. executables, Office, Zip, images)
    into a list of everyday strings. Very simple tools, powerful concept,
    limited only by your imagination.

### Papers

* [Self-Exfiltration: The Dangers of Browser-Enforced Information Flow Control](http://ericchen.me/self_exfiltration.pdf)

  * Abstract Since the early days of Netscape, browser vendors and web security
    researchers have restricted out-going data based on its destination. The
    security argument accompanying these mechanisms is that they prevent
    sensitive user data from being sent to the attackers domain. However, in
    this paper, we show that regulating web information flow based on its
    destination server is an inherently flawed security practice. It is
    vulnerable to self-exfiltration attacks, where an adversary stashes stolen
    information in the database of a whitelisted site, then later independently
    connects to the whitelisted site to retrieve the information. We describe
    eight existing browser security mechanisms that are vulnerable to these
    self-exfiltration attacks. Furthermore, we discovered at least one
    exfiltration channel for each of the Alexa top 100 websites. None of the
    existing information flow control mechanisms we surveyed are sufficient to
    protect data from being leaked to the attacker. Our goal is to prevent
    browser vendors and researchers from falling into this trap by designing
    more systems that are vulnerable to self-exfiltration.
