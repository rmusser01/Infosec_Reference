##Interesting Things

[Coming War on General Computation](https://www.youtube.com/watch?v=HUEvRyemKSg)

[Timeline/List of low-level attacks/persistence techniques.  HIGHLY RECOMMENDED!](http://timeglider.com/timeline/5ca2daa6078caaf4)

[Timeline of Software/Timing Attestation papers](http://timeglider.com/timeline/be11d685a7c4374d)

http://www.securitywizardry.com/radar.htm

[Website detailing various crypto laws around world](http://www.cryptolaw.org/)

[They clapped](http://www.econlib.org/library/Columns/y2007/Mungergouging.html)

###CULL

[Postcards from a Post-XSS World - Michael Zalewski](http://lcamtuf.coredump.cx/postxss/#dangling-markup-injection)
* This page is a rough collection of notes on some of the fundamental alternatives to direct script injection that would be available to attackers following the universal deployment of CSP or other security mechanisms designed to prevent the execution of unauthorized scripts. I hope to demonstrate that in many cases, the capabilities offered by these alternative methods are highly compatible with the goals of contemporary XSS attacks. 

[You're Leaking Trade Secrets - Defcon22 Michael Schrenk](https://www.youtube.com/watch?v=JTd5TL6_zgY)
* Networks don't need to be hacked for information to be compromised. This is particularly true for organizations that are trying to keep trade secrets. While we hear a lot about personal privacy, little is said in regard to organizational privacy. Organizations, in fact, leak information at a much greater rate than individuals, and usually do so with little fanfare. There are greater consequences for organizations when information is leaked because the secrets often fall into the hands of competitors. This talk uses a variety of real world examples to show how trade secrets are leaked online, and how organizational privacy is compromised by seemingly innocent use of The Internet.

[ZeroMQ](http://zguide.zeromq.org/page:all)
[Underhanded C contest](http://underhanded-c.org/)
Regex for credit cards
http://www.regular-expressions.info/creditcard.html
^(?:4[0-9]{12}(?:[0-9]{3})?          # Visa
 |  5[1-5][0-9]{14}                  # MasterCard
 |  3[47][0-9]{13}                   # American Express
 |  3(?:0[0-5]|[68][0-9])[0-9]{11}   # Diners Club
 |  6(?:011|5[0-9]{2})[0-9]{12}      # Discover
 |  (?:2131|1800|35\d{3})\d{11}      # JCB
)$

QR Code interesting
http://datagenetics.com/blog/november12013/index.html

http://blog.qartis.com/decoding-small-qr-codes-by-hand/

###Interesting Videos


[You and Your Research - Haroon Meer](https://www.youtube.com/watch?v=JoVx_-bM8Tg)
* What does it take to do quality research? What stops you from being a one-hit wonder? Is there an age limit to productive hackery? What are the key ingredients needed and how can you up your chances of doing great work? In a talk unabashedly stolen from far greater minds we hope to answer these questions and discuss their repercussions.

[A talk about (info-sec) talks - Haroon Meer ](https://www.youtube.com/watch?v=BlVjdUkrSFY)
* Last year there was an Information Security conference taking place for almost every day of the year. This translates to about 15 information security talks per day, every day. The question is, is this a bad thing? Even niche areas of the info-sec landscape have their own dedicated conference these days. Is this a good thing?

[Paypals War on Terror - Chaos Communication Congress 31](http://ccc2.mirror.xt0.org/congress/2014/webm-hd/31c3-6377-en-de-Paypals_War_on_Terror_webm-hd.webm)

[CompSci in the DPRK](http://us2.1und1.c3voc.de/congress/2014/webm-hd/31c3-6253-en-de-Computer_Science_in_the_DPRK_webm-hd.webm)


###Interesting Attacks
[VM as injection payload ](http://infiltratecon.com/downloads/python_deflowered.pdf)
[Breaking IPMI/BMC](http://fish2.com/ipmi/how-to-break-stuff.html)





###Interesting Papers

[The Eavesdropper’s Dillemma](http://www.crypto.com/papers/internet-tap.pdf)

[Mov is turing ocmplete](http://www.cl.cam.ac.uk/~sd601/papers/mov.pdf)

[The Evolution of Protected Processes Part 1: Pass-the-Hash Mitigations in Windows 8.1](http://www.alex-ionescu.com/?p=97)

[Thousands of MongoDB installations on the net unprotected](http://cispa.saarland/wp-content/uploads/2015/02/MongoDB_documentation.pdf)

[Why Qubes doesn’t work on Windows.](http://www.invisiblethingslab.com/resources/2014/A%20crack%20on%20the%20glass.pdf)

[Towards Optimization-Safe Systems: Analyzing the Impact of Undefined Behavior](http://pdos.csail.mit.edu/~xi/papers/stack-sosp13.pdf)
* This paper studies an emerging class of software bugs called optimization-unstable code: code that is unexpectedly discarded by compiler optimizations due to undefined behavior in the program. Unstable code is present in many systems, including the Linux kernel and the Postgres database. The consequences of unstable code range from incorrect functionality to missing security checks. To reason about unstable code, this paper proposes a novel model, which views unstable code in terms of optimizations that leverage undefined behavior. Using this model, we introduce a new static checker called Stack that precisely identifies unstable code. Applying Stack to widely used systems has uncovered 160 new bugs that have been confirmed and fixed by developers

[The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86)](https://cseweb.ucsd.edu/~hovav/dist/geometry.pdf)
* We present new techniques that allow a return-into-libc attack to be mounted on x86 executables that calls no functions at all. Our attack combines a large number of short instruction sequences to build gadgets that allow arbitrary computation. We show how to discover such instruction sequences by means of static analysis. We make use, in an essential way, of the properties of the x86 instruction set.

[A Practical Methodology for Measuring the Side-Channel Signal Available to the Attacker for Instruction-Level Event](http://users.ece.gatech.edu/~az30/Downloads/Micro14.pdf)
* Abstract: This paper presents a new metric, which we call Signal Available to Attacker (SAVAT), that measures the side channel signal created by a specific single-instruction difference in program execution, i.e. the amount of signal made available to a potential attacker who wishes to decide whether the program has executed instruction/event A or instruction/event B. We also devise a practical methodology for measuring SAVAT in real systems using only user-level access permissions and common measurement equipment. Finally, we perform a case study where we measure electromagnetic (EM) emanations SAVAT among 11 different instructions for three different laptop systems. Our findings from these experiments confirm key intuitive expectations, e.g. that SAVAT between on-chip instructions and off-chip memory accesses tends to be higher than between two on-chip instructions. However, we find that particular instructions, such as integer divide, have much higher SAVAT than other instructions in the same general category (integer arithmetic), and that last-level-cache hits and misses have similar (high) SAVAT. Overall, we confirm that our new metric and methodology can help discover the most vulnerable aspects of a processor architecture or a program, and thus inform decision-making about how to best manage the overall side channel vulnerability of a processor, a program, or a system.

[A Tale of Two Kernels: Towards Ending Kernel Hardening Wars with Split Kernel](http://split.kernel.build/papers/ccs14.pdf)
* Abstract: Software security practitioners are often torn between choosing per- formance or security. In particular, OS kernels are sensitive to the smallest performance regressions. This makes it difficult to develop innovative kernel hardening mechanisms: they may inevitably incur some run-time performance overhead. Here, we propose building each kernel function with and without hardening, within a single split kernel . In particular, this allows trusted processes to be run under unmodified kernel code, while system calls of untrusted pro- cesses are directed to the hardened kernel code. We show such trusted processes run with no overhead when compared to an un- modified kernel. This allows deferring the decision of making use of hardening to the run-time. This means kernel distributors, system administrators and users can selectively enable hardening accord- ing to their needs: we give examples of such cases. Although this approach cannot be directly applied to arbitrary kernel hardening mechanisms, we show cases where it can. Finally, our implementa- tion in the Linux kernel requires few changes to the kernel sources and no application source changes. Thus, it is both maintainable and easy to use


[Reflections on Trusting Trust](https://www.ece.cmu.edu/~ganger/712.fall02/papers/p761-thompson.pdf)

(A Practical Attack to De-Anonymize Social Network Users](https://www.iseclab.org/papers/sonda-TR.pdf)

[Virtual Ghost: Protecting Applications from Hostile Operating Systems](http://sva.cs.illinois.edu/pubs/VirtualGhost-ASPLOS-2014.pdf)

[Ceremony Design and Analysis](http://eprint.iacr.org/2007/399.pdf)
* Abstract: The concept of Ceremony is introduced as an extension of the concept of network protocol, with human nodes alongside computer nodes and with communication links that include UI, human-to-human communication and transfers of physical objects that carry data. What is out-of-band to a protocol is in-band to a ceremony, and therefore subject to design and analysis using variants of the same mature techniques used for the design and analysis of protocols. Ceremonies include all protocols, as well as all applications with a user interface, all workflow and all provisioning scenarios. A secure ceremony is secure against both normal attacks and social engineering. However, some secure protocols imply ceremonies that cannot be made secure. 

[It’s all about the timing. . . Blackhat talk](https://www.blackhat.com/presentations/bh-usa-07/Meer_and_Slaviero/Whitepaper/bh-usa-07-meer_and_slaviero-WP.pdf)
* Description: This paper is broken up into several distinct parts, all related loosely to timing and its role in information se- curity today. While timing has long been recognized as an important component in the crypt-analysts arse- nal, it has not featured very prominently in the domain of Application Security Testing. This paper aims at highlighting some of the areas in which timing can be used with great effect, where traditional avenues fail. In this paper, a brief overview of previous timing attacks is provided, the use of timing as a covert channel is examined and the effectiveness of careful timing during traditional web application and SQL injection attacks is demonstrated. The use of Cross Site Timing in bypass- ing the Same Origin policy is explored as we believe the technique has interesting possibilities for turning innocent browsers into bot-nets aimed at, for instance, brute-force attacks against third party web-sites

[Seven Months’ Worth of Mistakes: A Longitudinal Study of Typosquatting Abuse](https://lirias.kuleuven.be/bitstream/123456789/471369/3/typos-final.pdf)
* Abstract: Typosquatting is the act of purposefully registering a domain name that is a mistype of a popular domain name. It is a concept that has been known and studied for over 15 years, yet still thoroughly practiced up until this day. While previous typosquatting studies have always taken a snapshot of the typosquatting landscape or base their longitudinal results only on domain registration data, we present the first content- based , longitudinal study of typosquatting. We collected data about the typosquatting domains of the 500 most popular sites of the Internet every day, for a period of seven months, and we use this data to establish whether previously discovered typosquatting trends still hold today, and to provide new results and insights in the typosquatting landscape. In particular we reveal that, even though 95% of the popular domains we investigated are actively targeted by typosquatters, only few trademark owners protect themselves against this practice by proactively registering their own typosquatting domains. We take advantage of the longitudinal aspect of our study to show, among other results, that typosquatting domains change hands from typosquatters to legitimate owners and vice versa, and that typosquatters vary their monetization strategy by hosting different types of pages over time. Our study also reveals that a large fraction of typosquatting domains can be traced back to a small group of typosquatting page hosters and that certain top-level domains are much more prone to typosquatting than others

[RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis](http://www.tau.ac.il/~tromer/acoustic/)
* Here, we describe a new acoustic cryptanalysis key extraction attack, applicable to GnuPG's current implementation of RSA. The attack can extract full 4096-bit RSA decryption keys from laptop computers (of various models), within an hour, using the sound generated by the computer during the decryption of some chosen ciphertexts. We experimentally demonstrate that such attacks can be carried out, using either a plain mobile phone placed next to the computer, or a more sensitive microphone placed 4 meters away.

[Get Your Hands Off My Laptop: Physical Side-Channel Key-Extraction Attacks On PCs](http://www.tau.ac.il/~tromer/handsoff/)
* We demonstrated physical side-channel attacks on a popular software implementation of RSA and ElGamal, running on laptop computers. Our attacks use novel side channels and are based on the observation that the "ground" electric potential in many computers fluctuates in a computation-dependent way. An attacker can measure this signal by touching exposed metal on the computer's chassis with a plain wire, or even with a bare hand. The signal can also be measured at the remote end of Ethernet, VGA or USB cables. Through suitable cryptanalysis and signal processing, we have extracted 4096-bit RSA keys and 3072-bit ElGamal keys from laptops, via each of these channels, as well as via power analysis and electromagnetic probing. Despite the GHz-scale clock rate of the laptops and numerous noise sources, the full attacks require a few seconds of measurements using Medium Frequency signals (around 2 MHz), or one hour using Low Frequency signals (up to 40 kHz).


###Interesting Software

[ProcDOT](http://www.cert.at/downloads/software/procdot_en.html)
* This tool processes Sysinternals Process Monitor (Procmon) logfiles and PCAP-logs (Windump, Tcpdump) to generate a graph via the GraphViz suite. This graph visualizes any relevant activities (customizable) and can be interactively analyzed.


[Hachoir](https://bitbucket.org/haypo/hachoir/wiki/Home)
* Hachoir is a Python library that allows to view and edit a binary stream field by field

[Distributed File Storage Using JavaScript Botnets](https://github.com/seantmalone/HiveMind)

[Xmount](https://www.pinguin.lu/xmount)
* What is xmount? xmount allows you to convert on-the-fly between multiple input and output harddisk image types. xmount creates a virtual file system using FUSE (Filesystem in Userspace) that contains a virtual representation of the input image. The virtual representation can be in raw DD, DMG, VHD, VirtualBox's virtual disk file format or in VmWare's VMDK file format. Input images can be raw DD, EWF (Expert Witness Compression Format) or AFF (Advanced Forensic Format) files. In addition, xmount also supports virtual write access to the output files that is redirected to a cache file. This makes it possible to boot acquired harddisk images using QEMU, KVM, VirtualBox, VmWare or alike.

[FreeIPA]()
* FreeIPA is an integrated security information management solution combining Linux (Fedora), 389 Directory Server, MIT Kerberos, NTP, DNS, Dogtag (Certificate System). It consists of a web interface and command-line administration tools. FreeIPA is an integrated Identity and Authentication solution for Linux/UNIX networked environments. A FreeIPA server provides centralized authentication, authorization and account information by storing data about user, groups, hosts and other objects necessary to manage the security aspects of a network of computers. 



###Interesting Hardware Projects


[Digital Ding Dong Ditch](https://github.com/samyk/dingdong)
* Digital Ding Dong Ditch is a device to hack into and ring my best friend's wireless doorbell whenever I send a text message to the device. The best part of the device is that it causes my friend, without fail, to come outside, find no one, and go back in. In this project, we'll learn not only how to create this device, but how to reverse engineer radio frequencies we know nothing about using RTL-SDR (a ~$14 software defined radio), as well as creating hardware and software using Arduino, the Adafruit FONA (GSM/SMS/2G board), an RF (radio frequency) transmitter to transmit custom signals, and even how to reverse engineer a proprietary radio signal we know nothing about!


###Interesting Writeups
[Privilege Escalation Using Keepnote](http://0xthem.blogspot.com/2014/05/late-night-privilege-escalation-keepup.html)

[Door Control Systems: An Examination of Lines of Attack](https://www.nccgroup.com/en/blog/2013/09/door-control-systems-an-examination-of-lines-of-attack/)

[Code Execution In Spite Of BitLocker](https://cryptoservices.github.io/fde/2014/12/08/code-execution-in-spite-of-bitlocker.html)

[OSINT Through Sender Policy Framework Records](https://community.rapid7.com/community/infosec/blog/2015/02/23/osint-through-sender-policy-framework-spf-records)

