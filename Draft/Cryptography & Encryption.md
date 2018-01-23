# Cryptography

## Table of Contents

* [General Information](#general)
* Cryptocurrencies


### Sort

To Do:
* Add Books
* Add educational stuff

* [Toward Robust Hidden Volumes Using Write-Only Oblivious RAM](https://eprint.iacr.org/2014/344.pdf) 
    * With sensitive data being increasingly stored on mobile devices and laptops, hard disk encryption is more important than ever. In partic- ular, being able to plausibly deny that a hard disk contains certain information is a very useful and interesting research goal. However, it has been known for some time that existing “hidden volume” so- lutions, like TrueCrypt, fail in the face of an adversary who is able to observe the contents of a disk on multiple, separate occasions. In this work, we explore more robust constructions for hidden vol- umes and present HIVE, which is resistant to more powerful ad- versaries with multiple-snapshot capabilities. In pursuit of this, we propose the first security definitions for hidden volumes, and prove HIVE secure under these definitions. At the core of HIVE, we de- sign a new write-only Oblivious RAM. We show that, when only hiding writes, it is possible to achieve ORAM with optimal O (1) communication complexity and only poly-logarithmic user mem- ory.  This is a significant improvement over existing work and an independently interesting result.  We go on to show that our write- only ORAM is specially equipped to provide hidden volume func- tionality with low overhead and significantly increased security. Fi- nally, we implement HIVE as a Linux kernel block device to show both its practicality and usefulness on existing platforms.
* [Secrets and LIE-abilities: The State of Modern Secret Management (2017)](https://medium.com/on-docker/secrets-and-lie-abilities-the-state-of-modern-secret-management-2017-c82ec9136a3d)
* [Indistinguishability Obfuscation from the Multilinear Subgroup Elimination Assumption](https://eprint.iacr.org/2014/309)
    *  Abstract: We revisit the question of constructing secure general-purpose indistinguishability obfuscation (iO), with a security reduction based on explicit computational assumptions over multi- linear maps. Previous to our work, such reductions were only known to exist based on meta- assumptions and/or ad-hoc assumptions: In the original constructive work of Garg et al. (FOCS 2013), the underlying explicit computational assumption encapsulated an exponential family of assumptions for each pair of circuits to be obfuscated. In the more recent work of Pass et al. (Crypto 2014), the underlying assumption is a meta-assumption that also encapsulates an exponential family of assumptions, and this meta-assumption is invoked in a manner that captures the specific pair of circuits to be obfuscated. The assumptions underlying both these works substantially capture (either explicitly or implicitly) the actual structure of the obfuscation mechanism itself.  In our work, we provide the first construction of general-purpose indistinguishability obfuscation proven secure via a reduction to a natural computational assumption over multilinear maps, namely, the Multilinear Subgroup Elimination Assumption. This assumption does not depend on the circuits to be obfuscated (except for its size), and does not correspond to the underlying structure of our obfuscator. The technical heart of our paper is our reduction, which gives a new way to argue about the security of indistinguishability obfuscation. 

* [MASCAB: a Micro-Architectural Side-Channel Attack Bibliography](https://github.com/danpage/mascab/)
    * Cryptography is a fast-moving field, which is enormously exciting but also quite challenging: resources such as the IACR eprint archive and CryptoBib help, but even keeping track of new results in certain sub-fields can be difficult, let alone then making useful contributions. The sub-field of micro-architectural side-channel attacks is an example of this, in part as the result of it bridging multiple disciplines (e.g., cryptography and computer architecture). I've found this particularly challenging (and so frustrating) over say the last 5 years; the volume of papers has expanded rapidly, but the time I'd normally allocate to reading them has been eroded by other commitments (as evidenced by a pile of printed papers gathering dust on my desk). In the end, I decided to tackle this problem by progressively a) collating papers I could read, then b) reading them one-by-one, but in no particular order, and attempting to summarise their contribution (and so organise the sub-field as a whole in my head). MASCAB is the result: after starting to advise MSc and PhD students on how to navigate the sub-field, it seems likely to be of use to others as well.
From: https://www.reddit.com/r/securityengineering/comments/7o2uzy/a_collection_of_links_to_pdfs_of_papers_on/
```
    1973-10-01 "A note on the confinement problem" by Lampson https://www.cs.utexas.edu/~shmat/courses/cs380s_fall09/lampson73.pdf
    1994-??-?? - "Countermeasures and tradeoffs for a class of covert timing channels" by Ray https://pdfs.semanticscholar.org/5505/384390d0b0bf86de8804baeaf82254572363.pdf
    2003-09-08 - "Cryptanalysis of DES implemented on computers with cache" by Tsunoo et al. http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.135.1221&rep=rep1&type=pdf
    2005-04-14 - "Cache-timing attacks on AES" by Bernstein https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
    2005-05-13 - "CACHE MISSING FOR FUN AND PROFIT" by Percival http://css.csail.mit.edu/6.858/2014/readings/ht-cache.pdf
    2006-02-13 - "Cache attacks and countermeasures: the case of AES" by Osvik et al. https://www.cs.tau.ac.il/~tromer/papers/cache.pdf
    2006-08-23 - "Predicting Secret Keys via Branch Prediction" by Aciicmez et al. https://eprint.iacr.org/2006/288.pdf
    2007-03-20 - "On the Power of Simple Branch Prediction Analysis" by Acıi¸cmez1 et al. https://eprint.iacr.org/2006/351.pdf
    2007-12-18 - "New Branch Prediction Vulnerabilities in OpenSSL and Necessary Software Countermeasures" by Aciicmez et al. https://eprint.iacr.org/2007/039.pdf
    2010-11-22 - "Cache Games -- Bringing Access-Based Cache Attacks on AES to Practice" by Gullasch et al https://eprint.iacr.org/2010/594.pdf
    2012-03-08 - "Plugging Side-Channel Leaks with Timing Information Flow Control" by Ford https://arxiv.org/pdf/1203.3428.pdf
    2013-05-19 - "Practical Timing Side Channel Attacks against Kernel Space ASLR" by Hund et al. http://www.ieee-security.org/TC/SP2013/papers/4977a191.pdf
    2013-08-13 - "The Page-Fault Weird Machine: Lessons in Instruction-less Computation" by Bangert et al. https://www.usenix.org/system/files/conference/woot13/woot13-bangert.pdf
    2013-08-15 - "CacheAudit: A Tool for the Static Analysis of Cache Side Channels" by Doychev et al. https://eprint.iacr.org/2013/253.pdf
    2013-09-26 - "On the Prevention of Cache-Based Side-Channel Attacks in a Cloud Environment" Godfrey et al. https://pdfs.semanticscholar.org/6367/9824606b1b0deb4a44639a4e4b3e5eb49303.pdf
    2014-01-01 - "CACHE-BASED SIDE-CHANNEL ATTACKS IN MULTI-TENANT PUBLIC CLOUDS AND THEIR COUNTERMEASURES" by Zhang https://pdfs.semanticscholar.org/95a2/40ac8a7bbee77b32120081f00477e38776fe.pdf
    2014-11-03 - "The Last Mile An Empirical Study of Timing Channels on seL4" by Cock et al http://research.davidcock.fastmail.fm/papers/Cock_GMH_14.pdf
    2015-04-02 - "An Empirical Bandwidth Analysis of Interrupt-Related Covert Channels" by Gay e tal. http://www.mais.informatik.tu-darmstadt.de/WebBibPHP/papers/2013/2013-GayMantelSudbrock-EmpiricalIRCC.pdf
    2015-05-17 - "Last-Level Cache Side-Channel Attacks are Practical" by Liu et al http://palms.ee.princeton.edu/system/files/SP_vfinal.pdf
    2015-05-17 - "S$A: A Shared Cache Attack That Works across Cores and Defies VM Sandboxing -- and Its Application to AES" - by Irazoqui et al http://users.wpi.edu/~teisenbarth/pdf/SharedCacheAttackSnP2015.pdf
    2016-03-07 - "Rigorous Analysis of Software Countermeasures against Cache Attacks" by Doychev et al. https://arxiv.org/pdf/1603.02187.pdf
    2016-06-12 - "Flush+Flush: a fast and stealthy cache attack" by Gruss et al. https://gruss.cc/files/flushflush.pdf
    2016-08-10 - "Verifying Constant-Time Implementations" by Almeida & Barbosa https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_almeida.pdf
    2016-10-?? - "Jump over ASLR: Attacking branch predictors to bypass ASLR" by Evtyushkin et al. http://www.cs.wm.edu/~dmitry/assets/files/evtyushkin-micro16-camera.pdf
    2016-10-?? - "Breaking Kernel Address Space Layout Randomization with Intel TSX" by Jang et al. https://sslab.gtisc.gatech.edu/assets/papers/2016/jang:drk-ccs.pdf
    2016-10-?? - "A Survey of Microarchitectural Timing Attacks and Countermeasures on Contemporary Hardware" by Qian Ge et al http://eprint.iacr.org/2016/613
    2016-10-24 - "Prefetch Side-Channel Attacks: Bypassing SMAP and Kernel ASLR" by Gruss et al https://gruss.cc/files/prefetch.pdf
    2016-01-?? - "Attacking Cloud through cache based side channel in virtualized environment" by Teja et al. http://ijarcsee.org/index.php/IJARCSEE/article/download/301/267
    2017-02-27 - "ASLR on the Line: Practical Cache Attacks on the MMU" by Gras & Kaveh et al http://www.cs.vu.nl/~herbertb/download/papers/anc_ndss17.pdf
    2017-03-20 - "CacheZoom: How SGX Amplifies The Power of Cache Attacks" by Moghimi - https://arxiv.org/pdf/1703.06986.pdf
    2017-05-20 - "Leaky Cauldron on the Dark Land: Understanding Memory Side-Channel Hazards in SGX" by Wang et al https://arxiv.org/pdf/1705.07289.pdf
    2017-06-24 - "Kaslr is dead: long live kaslr", "the KAISER paper" by Gruss et al https://gruss.cc/files/kaiser.pdf
    2017-08-16 - "Prime+Abort: A Timer-Free High-Precision L3 Cache Attack using Intel TSX" by Disselkoen et al https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-disselkoen.pdf
    2017-10-?? - "LAZARUS: Practical Side-Channel Resilient Kernel-Space Randomization" by Gens et al http://jin.ece.ufl.edu/papers/RAID17.pdf
    2018-01-04 - "Spectre Attacks: Exploiting Speculative Execution" by Kocher et al https://spectreattack.com/spectre.pdf
    2018-01-04 - "Meltdown" by Lipp et al. https://meltdownattack.com/meltdown.pdf
```



* Monero
* Zcash

* crypto101
https://conversations.im/xeps/multi-end.html

### End Sort


-----
### <a name="general">General Information</a>
* **101**
    * [Primer on Zero-Knowledge Proofs](http://blog.cryptographyengineering.com/2014/11/zero-knowledge-proofs-illustrated-primer.html?m=1)
    * [Hyper-encryption - Wikipedia](https://en.wikipedia.org/wiki/Hyper-encryption)
    * [XOR Bitwise Operations Explained - Khan Academy](https://www.khanacademy.org/computing/computer-science/cryptography/ciphers/a/xor-bitwise-operation)
    * [Homomorphic encryption](https://en.wikipedia.org/wiki/Homomorphic_encryption)
    * [Differential Cryptanalysis for Dummies - Jon King](https://www.youtube.com/watch?v=xav-GUO_o4s&feature=youtu.be)
    * [Lifetimes of cryptographic hash functions](http://valerieaurora.org/hash.html)
* **Articles/Papers/Talks/Writeups**
* **Auditing**
    * [A Formal Security Analysis of the Signal Messaging Protocol - Oct2016](https://eprint.iacr.org/2016/1013.pdf)
    * [Top 10 Developer Crypto Mistakes](https://littlemaninmyhead.wordpress.com/2017/04/22/top-10-developer-crypto-mistakes/amp/)
    * [Why does cryptographic software fail? A case study and open problems](http://pdos.csail.mit.edu/papers/cryptobugs:apsys14.pdf)
        * Abstract: Mistakes in cryptographic software implementations often undermine the strong security guarantees offered by cryptography. This paper presents a systematic study of cryptographic vulnerabilities in practice, an examination of state-of-the-art techniques to prevent such vulnerabilities, and a discussion of open problems and possible future research directions. Our study covers 269 cryptographic vulnerabilities reported in the CVE database from January 2011 to May 2014. The results show that just 17% of the bugs are in cryptographic libraries (which often have devastating consequences), and the remaining 83% are misuses of cryptographic libraries by individual applications. We observe that preventing bugs in different parts of a system requires different techniques, and that no effective techniques exist to deal with certain classes of mistakes, such as weak key generation.
* **Books**
    * Cryptography Engineering
    * Applied Cryptography
* **CheatSheets**
    * [Quick'n easy gpg cheatsheet](http://irtfweb.ifa.hawaii.edu/%7Elockhart/gpg/)
* **Courses**
    * [Coursera Cryptography]()
    * [Matsano Crypto Challenges](https://www.Cryptopals.co)
        * Go through a series of increasingly difficult challenges while learning all about cryptography. Expected knowledge level: You passed 9th grade math and you have 0 knowledge of crypto.
    * [A Graduate Course in Applied Cryptography - Dan Boneh and Victor Shoup](http://toc.cryptobook.us/)
        * Version 0.3 - posted Dec. 9, 2016
* **Crypto Frameworks/Libraries/Protocols**
    * [OMEMO Multi-End Message and Object Encryption](https://conversations.im/omemo/)
       * OMEMO is an XMPP Extension Protocol (XEP) for secure multi-client end-to-end encryption. It is an open standard based on a Double Ratchet and PEP which can be freely used and implemented by anyone. The protocol has been audited by a third party.
    * [The Legion of the Bouncy Castle](https://www.bouncycastle.org/)
    * [The Noise Protocol Framework](http://noiseprotocol.org/noise.html)
        * Noise is a framework for crypto protocols based on Diffie-Hellman key agreement. Noise can describe protocols that consist of a single message as well as interactive protocols.
        * A Noise protocol begins with two parties exchanging handshake messages. During this handshake phase the parties exchange DH public keys and perform a sequence of DH operations, hashing the DH results into a shared secret key. After the handshake phase each party can use this shared key to send encrypted transport messages.
* **Don't Do**
    * [How to Implement Crypto Poorly - Sean Cassidy](https://github.com/cxxr/talks/blob/master/2016/grrcon/How%20to%20Implement%20Crypto%20Poorly.pdf)
* **Educational/Informative**
    * [Crypto.is Blog](https://crypto.is/blog/)
        * This blog series is intended to be a course on how remailers work, the theory behind them, and many of the choices that must be considered. Some of the topics we intended to dive deeply into in the future is how to have a directory of remailer nodes, how to handle messages that overflow the packet size, more details on Mixminion, as-yet-unimplemented Academic Papers (like Pynchon Gate and Sphinx), and more! Check out posts One, Two, Three, Four, and Five. The comments section should work, so please do leave comments if you have questions, insights, or corrections!
    * [Website detailing various crypto laws around world](http://www.cryptolaw.org/)
    * [SSL/TLS and PKI History ](https://www.feistyduck.com/ssl-tls-and-pki-history/)
        *  A comprehensive history of the most important events that shaped the SSL/TLS and PKI ecosystem. Based on Bulletproof SSL and TLS, by Ivan Ristić.
    * [Crypto: 48 Dirty Little Secrets Cryptographers Don’t Want You To Know - BlackHat2014](https://www.youtube.com/watch?v=mXdFHNJ6srY)
* **General**
    * [Snake Oil Crypto Competition](https://snakeoil.cr.yp.to/)
    * [Applied-Crypto-Hardening](https://github.com/BetterCrypto/Applied-Crypto-Hardening)
        * Best Current Practices regarding secure online communication and configuration of services using cryptography. https://bettercrypto.org
    * [cr.yp.to blog](http://blog.cr.yp.to/index.html)
* **Testing/Auditing**
    * [Hunting For Vulnerabilities In Signal - Markus Vervier - HITB 2017 AMS](https://www.youtube.com/watch?v=2n9HmllVftA)
        * Signal is the most trusted secure messaging and secure voice application, recommended by Edward Snowden and the Grugq. And indeed Signal uses strong cryptography, relies on a solid system architecture, and you’ve never heard of any vulnerability in its code base. That’s what this talk is about: hunting for vulnerabilities in Signal. We will present vulnerabilities found in the Signal Android client, in the underlying Java libsignal library, and in example usage of the C libsignal library. Our demos will show how these can be used to crash Signal remotely, to bypass the MAC authentication for certain attached files, and to trigger memory corruption bugs. Combined with vulnerabilities in the Android system it is even possible to remotely brick certain Android devices. We will demonstrate how to initiate a permanent boot loop via a single Signal message. We will also describe the general architecture of Signal, its attack surface, the tools you can use to analyze it, and the general threat model for secure mobile communication apps.
* **Miscellaneous**
    * [SHA2017 Conference Videos](https://www.youtube.com/channel/UCHmPMdU0O9P_W6I1hNyvBIQ/videos)
    * **SSH**
        * [SSH Bad Keys](https://github.com/rapid7/ssh-badkeys)
            * This is a collection of static SSH keys (host and authentication) that have made their way into software and hardware products. This was inspired by the Little Black Box project, but focused primarily on SSH (as opposed to TLS) keys.
        * [House of Keys](https://github.com/sec-consult/houseofkeys)
        * [Widespread Weak Keys in Network Devices](https://factorable.net/)

--------------------------------
### Specific Implementation Stuff

* **Android**
    * **101**
    * **Articles/Papers/Talks/Writeups**
        * [Encrypting Strings in Android: Let's make better mistakes](http://tozny.com/blog/encrypting-strings-in-android-lets-make-better-mistakes/)
        * [An Empirical Study of Cryptographic Misuse in Android Applications](https://www.cs.ucsb.edu/~chris/research/doc/ccs13_cryptolint.pdf)
    * **Tools**
* **iOS**
    * **101**
    * **Articles/Papers/Talks/Writeups**
    * **Tools**
* **Bitlocker**
    * **101**
    * **Articles/Papers/Talks/Writeups**
        * [Recovering BitLocker Keys on Windows 8.1 and 10](https://tribalchicken.io/recovering-bitlocker-keys-on-windows-8-1-and-10/)
    * **Tools**
* **Key Exchange**
    * [The SIGMA Family of Key-Exchange Protocols](http://webee.technion.ac.il/~hugo/sigma-pdf.pdf)
        * Summary: SIGMA is a family of cryptographic key-exchange protocols that provide perfect forward secrecy via a Diffie-Hellman exchange authenticated with digital signatures. SIGMA is designed to support a variety of features and trade-offs required in common practical scenarios (such as identity protection and reduced number of protocol rounds) as well as to enjoy sound cryptographic security. This design puts forth the "SIGn-and-MAc" (SIGMA, for short) approach that carefully combines the use of digital signatures and MAC functions to guarantee an authenticated binding between the Diffie-Hellman key and the identities of the parties to the exchange. This simple approach resolves security shortcomings found in previous protocols. The SIGMA protocols serve as the cryptographic basis for the signature-based modes of the standardized Internet Key Exchange (IKE) protocol, and its current revision IKE version 2. 
* **Signal**
    * [Demystifying the Signal Protocol for End-to-End Encryption (E2EE)](https://medium.com/@justinomora/demystifying-the-signal-protocol-for-end-to-end-encryption-e2ee-ad6a567e6cb4)
* **SSL/TLS**
    * **101**

    * **Articles/Talks/Writeups**
        * [Poor Man's Guide to Troubleshooting TLS Failures](http://blogs.technet.com/b/tspring/archive/2015/02/23/poor-man-s-guide-to-troubleshooting-tls-failures.aspx)
    * **Papers**
        * [A Messy State of the Union: Taming the Composite State Machines of TLS](https://www.smacktls.com/smack.pdf)
            * Abstract —Implementations of the Transport Layer Security (TLS) protocol must handle a variety of protocol versions and extensions, authentication modes and key exchange methods, where each combination may prescribe a different message sequence between the client and the server. We address the problem of designing a robust composite state machine that can correctly multiplex between these different protocol modes. We systematically test popular open-source TLS implementations for state machine bugs and discover several critical security vulnerabilities that have lain hidden in these libraries for years (they are now in the process of being patched). We argue that these vulnerabilities stem from incorrect compositions of individually correct state machines. We present the first verified implementation of a composite TLS state machine in C that can be embedded into OpenSSL and accounts for all its supported ciphersuites. Our attacks expose the need for the formal verifica- tion of core components in cryptographic protocol libraries; our implementation demonstrates that such mechanized proofs are within reach, even for mainstream TLS implementations.
    * **Tools**



----------------------
### Specific Attacks

* **CBC Bit-Flipping Attack**
    * [CBC Byte Flipping Attack—101 Approach](http://resources.infosecinstitute.com/cbc-byte-flipping-attack-101-approach/)

* **FREAK**
    * [Attack of the week: FREAK (or 'factoring the NSA for fun and profit')](http://blog.cryptographyengineering.com/2015/03/attack-of-week-freak-or-factoring-nsa.html)

* **Padding Oracle**
    * [Automated Padding Oracle Attacks with PadBuster](https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html)
    * [PadBuster v0.3 and the .NET Padding Oracle Attack](https://blog.gdssecurity.com/labs/2010/10/4/padbuster-v03-and-the-net-padding-oracle-attack.html)




---------------
### <a name="tools">Tools</a>
* **Helpful stuff**
    * [keyCzar](http://www.keyczar.org/)
        * Keyczar is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications. Keyczar supports authentication and encryption with both symmetric and asymmetric keys.
    * [Simple crypto tools](http://rumkin.com/tools/)
* **Encryption Software**
    * [VeraCrypt](https://www.veracrypt.fr/en/Home.html)
        * VeraCrypt is a free open source disk encryption software for Windows, Mac OSX and Linux. Brought to you by IDRIX (https://www.idrix.fr) and based on TrueCrypt 7.1a.
* **Key Managment**
    * [CONIKS](https://coniks.cs.princeton.edu/)
        * CONIKS is a key management system for end users capable of integration in end-to-end secure communication services. The main idea is that users should not have to worry about managing encryption keys when they want to communicate securely, but they also should not have to trust their secure communication service providers to act in their interest. 
* **Hash Identification**
    * [HashID](https://github.com/psypanda/hashID)
        * hashID is a tool written in Python 3 which supports the identification of over 220 unique hash types using regular expressions. It is able to identify a single hash, parse a file or read multiple files in a directory and identify the hashes within them. hashID is also capable of including the corresponding hashcat mode and/or JohnTheRipper format in its output. hashID works out of the box with Python 2 = 2.7.x or Python 3 = 3.3 on any platform.
    * [Hash-Algorithm-Identifier](https://github.com/AnimeshShaw/Hash-Algorithm-Identifier)
        * A python tool to identify different Hash Function Algorithms. Supports 160+ Hash Algorithms.
* **Attack Implementation/Testing**
    * **General**
        * [Cryptographic Implementations Analysis Toolkit (CIAT)](http://ciat.sourceforge.net/)
            * The Cryptographic Implementations Analysis Toolkit (CIAT) is compendium of command line and graphical tools whose aim is to help in the detection and analysis of encrypted byte sequences within files (executable and non-executable).
        * [Project Wycheproof](https://github.com/google/wycheproof)
            * Project Wycheproof tests crypto libraries against known attacks. It is developed and maintained by members of Google Security Team, but it is not an official Google product.
        * [FeatherDuster](https://github.com/nccgroup/featherduster)
            * FeatherDuster is a tool written by Daniel "unicornfurnace" Crowley of NCC Group for breaking crypto which tries to make the process of identifying and exploiting weak cryptosystems as easy as possible. Cryptanalib is the moving parts behind FeatherDuster, and can be used independently of FeatherDuster.
    * **Hash Collisions**
        * [Project HashClash](https://marc-stevens.nl/p/hashclash/)
            * Project HashClash is a Framework for MD5 & SHA-1 Differential Path Construction and Chosen-Prefix Collisions for MD5. It's goal is to further understanding and study of the weaknesses of MD5 and SHA-1. 
        * [CPC-MD5](https://github.com/dingelish/cpc-md5)
            * This project is forked from Marc Steven's Hashclash project hashclash and follows GPL.
    * **Hash Pump**
        * [HashPump](https://github.com/bwall/HashPump)
            * A tool to exploit the hash length extension attack in various hashing algorithms. Currently supported algorithms: MD5, SHA1, SHA256, SHA512.
    * **Padding Oracle**
        * [pypadbuster](https://github.com/escbar/pypadbuster)
            * A Python version of PadBuster.pl by Gotham Digital Security (GDSSecurity on Github)
        * [padex](https://github.com/szdavid92/padex)
            * The goal of this challenge is to find a flag contained in an encrypted message. A decryption oracle and the encrypted message is provided. The student should write an application that cracks the cyphertext by abusing the oracle which is vulnerable to the padding attack.
        * [Padding Oracle Exploit API](https://mwielgoszewski.github.io/python-paddingoracle/)
            * python-paddingoracle is an API that provides pentesters a customizable alternative to PadBuster and other padding oracle exploit tools that can't easily (without a heavy rewrite) be used in unique, per-app scenarios. Think non-HTTP applications, raw sockets, client applications, unique encodings, etc.
            * [tool](https://github.com/mwielgoszewski/python-paddingoracle)
        * [PadBuster](https://github.com/GDSSecurity/PadBuster)
            * PadBuster is a Perl script for automating Padding Oracle Attacks. PadBuster provides the capability to decrypt arbitrary ciphertext, encrypt arbitrary plaintext, and perform automated response analysis to determine whether a request is vulnerable to padding oracle attacks.
    * **MD5 Related**
        * [sheep-wolf](https://github.com/silentsignal/sheep-wolf/)
            * Some security tools still stick to MD5 when identifying malware samples years after practical collisions were shown against the algorithm. This can be exploited by first showing these tools a harmless sample (Sheep) and then a malicious one (Wolf) that have the same MD5 hash. Please use this code to test if the security products in your reach use MD5 internally to fingerprint binaries and share your results by issuing a pull request updating the contents of results/!
    * **SSL/TLS**
        * [TLS-Attacker](https://github.com/RUB-NDS/TLS-Attacker)
            * TLS-Attacker is a Java-based framework for analyzing TLS libraries. It is able to send arbitrary protocol messages in an arbitrary order to the TLS peer, and define their modifications using a provided interface. This gives the developer an opportunity to easily define a custom TLS protocol flow and test it against his TLS library.
* **Solver**
    * [quipqiup](http://quipqiup.com/)
            * quipqiup is a fast and automated cryptogram solver by Edwin Olson. It can solve simple substitution ciphers often found in newspapers, including puzzles like cryptoquips (in which word boundaries are preserved) and patristocrats (in which word boundaries aren't).
* **Toolkits**
    * [RELIC](https://github.com/relic-toolkit/relic)
        * RELIC is a modern cryptographic meta-toolkit with emphasis on efficiency and flexibility. RELIC can be used to build efficient and usable cryptographic toolkits tailored for specific security levels and algorithmic choices.
* **Misc**
    * [dislocker](https://github.com/Aorimn/dislocker)
        * FUSE driver to read/write Windows' BitLocker-ed volumes under Linux / Mac OSX
    * [HiVE — Hidden Volume Encryption](http://hive.ccs.neu.edu/#four)
    * [Decrypto](http://sourceforge.net/projects/decrypto/)
	   * In DeCrypto you will find a collection of scripts for helping decrypt messages.\
    * [xortool](https://github.com/hellman/xortool)
        * A tool to analyze multi-byte xor cipher


------------------
### Cryptocurrencies
* **General**
    * [cryptocurrency](https://github.com/kilimchoi/cryptocurrency)
        * Overview of top cryptocurrencies
    * [Blockchain Security research](https://gist.github.com/insp3ctre/403b8cb99eae2f52565874d8547fbc94)
        * Open-source blockchain security research (contributions welcome!)
    * [Blockchain Graveyard](https://magoo.github..io/Blockchain-Graveyard/)
* **Bitcoin**
    * [Bitcoin Paper](https://bitcoin.org/bitcoin.pdf)
        * [Bitcoin Paper Annotated - Genius](https://genius.com/2683753)
        * [Bitcoin Paper Annotated - Fermats Library](https://fermatslibrary.com/s/bitcoin)
    * [Bitcointalk](https://bitcointalk.org/)
    * [/r/bitcoin](https://reddit.com/r/bitcoin)
* **Ethereum**
    * [Ethereum 'White Paper'](https://github.com/ethereum/wiki/wiki/White-Paper)
    * [Cracking the Ethereum White Paper](https://medium.com/@FolusoOgunlana/cracking-the-ethereum-white-paper-e0e60c44126)
    * [The Ether Thief](https://www.bloomberg.com/features/2017-the-ether-thief/)
* **Shady Shit**
    * [The Problem with Calling Bitcoin a “Ponzi Scheme”](https://prestonbyrne.com/2017/12/08/bitcoin_ponzi/)
    * [Price Manipulation in the Bitcoin Ecosystem](https://www.sciencedirect.com/science/article/pii/S0304393217301666?via%3Dihub)
    * [Meet ‘Spoofy’. How a Single entity dominates the price of Bitcoin.](https://hackernoon.com/meet-spoofy-how-a-single-entity-dominates-the-price-of-bitcoin-39c711d28eb4)
    * [The Willy Report: proof of massive fraudulent trading activity at Mt. Gox, and how it has affected the price of Bitcoin](https://willyreport.wordpress.com/2014/05/25/the-willy-report-proof-of-massive-fraudulent-trading-activity-at-mt-gox-and-how-it-has-affected-the-price-of-bitcoin/)
* **Talks/Presentations**
    * [Deanonymisation of Clients in Bitcoin P2P Network](http://orbilu.uni.lu/bitstream/10993/18679/1/Ccsfp614s-biryukovATS.pdf)
        * We present an effcient method to deanonymize Bitcoin users, which allows to link user pseudonyms to the IP addresses where the transactions are generated. Our techniques work for the most common and the most challenging scenario when users are behind NATs or rewalls of their ISPs. They allow to link transactions of a user behind a NAT and to distinguish connections and transactions of different users behind the same NAT. We also show that a natural countermeasure of using Tor or other anonymity services can be cut-o by abusing anti-DoS countermeasures of the Bitcoin network. Our attacks require only a few machines and have been experimentally verifed. The estimated success rate is between 11% and 60% depending on how stealthy an attacker wants to be. We propose several countermeasures to mitigate these new attacks.