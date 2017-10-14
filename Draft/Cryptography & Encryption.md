## Cryptography

##### TOC

* [General Information](#general)
* [Learning/Courses](#learn)
* [Writeups](#write)
* [Blogposts/Misc](#blog)
* [Presentations](#presentation)
* [Papers](#papers)
* [Software](#soft)
* [Stenography](#steno)
* [Tools](#tools)
* [Books](#books)
* [Miscellaneous](#misc)


### Cull


https://conversations.im/xeps/multi-end.html

### End Cull



### <a name="general">General Information</a>



[Quick'n easy gpg cheatsheet](http://irtfweb.ifa.hawaii.edu/%7Elockhart/gpg/)

[Website detailing various crypto laws around world](http://www.cryptolaw.org/)

[Snake Oil Crypto Competition](https://snakeoil.cr.yp.to/)

[XOR Bitwise Operations Explained - Khan Academy](https://www.khanacademy.org/computing/computer-science/cryptography/ciphers/a/xor-bitwise-operation)

[Homomorphic encryption](https://en.wikipedia.org/wiki/Homomorphic_encryption)

[Differential Cryptanalysis for Dummies - Jon King](https://www.youtube.com/watch?v=xav-GUO_o4s&feature=youtu.be)

[Lifetimes of cryptographic hash functions](http://valerieaurora.org/hash.html)

[Top 10 Developer Crypto Mistakes](https://littlemaninmyhead.wordpress.com/2017/04/22/top-10-developer-crypto-mistakes/amp/)

[SSL/TLS and PKI History ](https://www.feistyduck.com/ssl-tls-and-pki-history/)
*  A comprehensive history of the most important events that shaped the SSL/TLS and PKI ecosystem. Based on Bulletproof SSL and TLS, by Ivan Ristić.





### <a name="learn">Courses</a>:
	Coursera Cryptography

[Matsano Crypto Challenges](https://www.Cryptopals.co)
* Go through a series of increasingly difficult challenges while learning all about cryptography. Expected knowledge level: You passed 9th grade math and you have 0 knowledge of crypto.

[A Graduate Course in Applied Cryptography - Dan Boneh and Victor Shoup](http://toc.cryptobook.us/)
* Version 0.3 - posted Dec. 9, 2016

[Primer on Zero-Knowledge Proofs](http://blog.cryptographyengineering.com/2014/11/zero-knowledge-proofs-illustrated-primer.html?m=1)

[Hyper-encryption - Wikipedia](https://en.wikipedia.org/wiki/Hyper-encryption)



### <a name="write">Writeups</a>
[Attack of the week: FREAK (or 'factoring the NSA for fun and profit')](http://blog.cryptographyengineering.com/2015/03/attack-of-week-freak-or-factoring-nsa.html)

[An Empirical Study of Cryptographic Misuse in Android Applications](https://www.cs.ucsb.edu/~chris/research/doc/ccs13_cryptolint.pdf)

[Widespread Weak Keys in Network Devices](https://factorable.net/)

[Secrets and LIE-abilities: The State of Modern Secret Management (2017)](https://medium.com/on-docker/secrets-and-lie-abilities-the-state-of-modern-secret-management-2017-c82ec9136a3d)

[How to Implement Crypto Poorly - Sean Cassidy](https://github.com/cxxr/talks/blob/master/2016/grrcon/How%20to%20Implement%20Crypto%20Poorly.pdf)

[CBC Byte Flipping Attack—101 Approach](http://resources.infosecinstitute.com/cbc-byte-flipping-attack-101-approach/)

[Demystifying the Signal Protocol for End-to-End Encryption (E2EE)](https://medium.com/@justinomora/demystifying-the-signal-protocol-for-end-to-end-encryption-e2ee-ad6a567e6cb4)

[A Formal Security Analysis of the Signal Messaging Protocol - Oct2016](https://eprint.iacr.org/2016/1013.pdf)

[Automated Padding Oracle Attacks with PadBuster](https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html)

[PadBuster v0.3 and the .NET Padding Oracle Attack](https://blog.gdssecurity.com/labs/2010/10/4/padbuster-v03-and-the-net-padding-oracle-attack.html)




### <a name="blogs">Blogposts/Misc(doesnt explicitly fit in other sections)</a>
[Encrypting Strings in Android: Let's make better mistakes](http://tozny.com/blog/encrypting-strings-in-android-lets-make-better-mistakes/)

[Poor Man's Guide to Troubleshooting TLS Failures](http://blogs.technet.com/b/tspring/archive/2015/02/23/poor-man-s-guide-to-troubleshooting-tls-failures.aspx)

[Top 10 Developer Crypto Mistakes](https://littlemaninmyhead.wordpress.com/2017/04/22/top-10-developer-crypto-mistakes/)

[cr.yp.to blog](http://blog.cr.yp.to/index.html)

[Recovering BitLocker Keys on Windows 8.1 and 10](https://tribalchicken.io/recovering-bitlocker-keys-on-windows-8-1-and-10/)

[Crypto.is Blog](https://crypto.is/blog/)
* This blog series is intended to be a course on how remailers work, the theory behind them, and many of the choices that must be considered. Some of the topics we intended to dive deeply into in the future is how to have a directory of remailer nodes, how to handle messages that overflow the packet size, more details on Mixminion, as-yet-unimplemented Academic Papers (like Pynchon Gate and Sphinx), and more! Check out posts One, Two, Three, Four, and Five. The comments section should work, so please do leave comments if you have questions, insights, or corrections!






### <a name="presentation">Presentations/Talks</a>
[Crypto: 48 Dirty Little Secrets Cryptographers Don’t Want You To Know - BlackHat2014](https://www.youtube.com/watch?v=mXdFHNJ6srY)

[SHA2017 Conference Videos](https://www.youtube.com/channel/UCHmPMdU0O9P_W6I1hNyvBIQ/videos)

[Hunting For Vulnerabilities In Signal - Markus Vervier - HITB 2017 AMS](https://www.youtube.com/watch?v=2n9HmllVftA)
* Signal is the most trusted secure messaging and secure voice application, recommended by Edward Snowden and the Grugq. And indeed Signal uses strong cryptography, relies on a solid system architecture, and you’ve never heard of any vulnerability in its code base. That’s what this talk is about: hunting for vulnerabilities in Signal. We will present vulnerabilities found in the Signal Android client, in the underlying Java libsignal library, and in example usage of the C libsignal library. Our demos will show how these can be used to crash Signal remotely, to bypass the MAC authentication for certain attached files, and to trigger memory corruption bugs. Combined with vulnerabilities in the Android system it is even possible to remotely brick certain Android devices. We will demonstrate how to initiate a permanent boot loop via a single Signal message. We will also describe the general architecture of Signal, its attack surface, the tools you can use to analyze it, and the general threat model for secure mobile communication apps.






### <a name="papers">Papers</a>

[Get Your Hands Off My Laptop: Physical Side-Channel Key-Extraction Attacks On PCs](http://www.tau.ac.il/~tromer/handsoff/)
* We demonstrated physical side-channel attacks on a popular software implementation of RSA and ElGamal, running on laptop computers. Our attacks use novel side channels and are based on the observation that the "ground" electric potential in many computers fluctuates in a computation-dependent way. An attacker can measure this signal by touching exposed metal on the computer's chassis with a plain wire, or even with a bare hand. The signal can also be measured at the remote end of Ethernet, VGA or USB cables. Through suitable cryptanalysis and signal processing, we have extracted 4096-bit RSA keys and 3072-bit ElGamal keys from laptops, via each of these channels, as well as via power analysis and electromagnetic probing. Despite the GHz-scale clock rate of the laptops and numerous noise sources, the full attacks require a few seconds of measurements using Medium Frequency signals (around 2 MHz), or one hour using Low Frequency signals (up to 40 kHz).


[Why does cryptographic software fail? A case study and open problems](http://pdos.csail.mit.edu/papers/cryptobugs:apsys14.pdf)
* Abstract: Mistakes in cryptographic software implementations often undermine the strong security guarantees offered by cryptography. This paper presents a systematic study of cryptographic vulnerabilities in practice, an examination of state-of-the-art techniques to prevent such vulnerabilities, and a discussion of open problems and possible future research directions. Our study covers 269 cryptographic vulnerabilities reported in the CVE database from January 2011 to May 2014. The results show that just 17% of the bugs are in cryptographic libraries (which often have devastating consequences), and the remaining 83% are misuses of cryptographic libraries by individual applications. We observe that preventing bugs in different parts of a system requires different techniques, and that no effective techniques exist to deal with certain classes of mistakes, such as weak key generation.

[RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis](http://www.tau.ac.il/~tromer/acoustic/)
* Here, we describe a new acoustic cryptanalysis key extraction attack, applicable to GnuPG's current implementation of RSA. The attack can extract full 4096-bit RSA decryption keys from laptop computers (of various models), within an hour, using the sound generated by the computer during the decryption of some chosen ciphertexts. We experimentally demonstrate that such attacks can be carried out, using either a plain mobile phone placed next to the computer, or a more sensitive microphone placed 4 meters away.

[Toward Robust Hidden Volumes Using Write-Only Oblivious RAM](https://eprint.iacr.org/2014/344.pdf) 
* With sensitive data being increasingly stored on mobile devices and laptops, hard disk encryption is more important than ever. In partic- ular, being able to plausibly deny that a hard disk contains certain information is a very useful and interesting research goal. However, it has been known for some time that existing “hidden volume” so- lutions, like TrueCrypt, fail in the face of an adversary who is able to observe the contents of a disk on multiple, separate occasions. In this work, we explore more robust constructions for hidden vol- umes and present HIVE, which is resistant to more powerful ad- versaries with multiple-snapshot capabilities. In pursuit of this, we propose the first security definitions for hidden volumes, and prove HIVE secure under these definitions. At the core of HIVE, we de- sign a new write-only Oblivious RAM. We show that, when only hiding writes, it is possible to achieve ORAM with optimal O (1) communication complexity and only poly-logarithmic user mem- ory.  This is a significant improvement over existing work and an independently interesting result.  We go on to show that our write- only ORAM is specially equipped to provide hidden volume func- tionality with low overhead and significantly increased security. Fi- nally, we implement HIVE as a Linux kernel block device to show both its practicality and usefulness on existing platforms.

[A Messy State of the Union: Taming the Composite State Machines of TLS](https://www.smacktls.com/smack.pdf)
* Abstract —Implementations of the Transport Layer Security (TLS) protocol must handle a variety of protocol versions and extensions, authentication modes and key exchange methods, where each combination may prescribe a different message sequence between the client and the server. We address the problem of designing a robust composite state machine that can correctly multiplex between these different protocol modes. We systematically test popular open-source TLS implementations for state machine bugs and discover several critical security vulnerabilities that have lain hidden in these libraries for years (they are now in the process of being patched). We argue that these vulnerabilities stem from incorrect compositions of individually correct state machines. We present the first verified implementation of a composite TLS state machine in C that can be embedded into OpenSSL and accounts for all its supported ciphersuites. Our attacks expose the need for the formal verifica- tion of core components in cryptographic protocol libraries; our implementation demonstrates that such mechanized proofs are within reach, even for mainstream TLS implementations.

[Indistinguishability Obfuscation from the Multilinear Subgroup Elimination Assumption](https://eprint.iacr.org/2014/309)
*  Abstract: We revisit the question of constructing secure general-purpose indistinguishability obfuscation (iO), with a security reduction based on explicit computational assumptions over multi- linear maps. Previous to our work, such reductions were only known to exist based on meta- assumptions and/or ad-hoc assumptions: In the original constructive work of Garg et al. (FOCS 2013), the underlying explicit computational assumption encapsulated an exponential family of assumptions for each pair of circuits to be obfuscated. In the more recent work of Pass et al. (Crypto 2014), the underlying assumption is a meta-assumption that also encapsulates an exponential family of assumptions, and this meta-assumption is invoked in a manner that captures the specific pair of circuits to be obfuscated. The assumptions underlying both these works substantially capture (either explicitly or implicitly) the actual structure of the obfuscation mechanism itself.  In our work, we provide the first construction of general-purpose indistinguishability obfuscation proven secure via a reduction to a natural computational assumption over multilinear maps, namely, the Multilinear Subgroup Elimination Assumption. This assumption does not depend on the circuits to be obfuscated (except for its size), and does not correspond to the underlying structure of our obfuscator. The technical heart of our paper is our reduction, which gives a new way to argue about the security of indistinguishability obfuscation. 

[RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis](http://www.tau.ac.il/~tromer/acoustic/)
* Here, we describe a new acoustic cryptanalysis key extraction attack, applicable to GnuPG's current implementation of RSA. The attack can extract full 4096-bit RSA decryption keys from laptop computers (of various models), within an hour, using the sound generated by the computer during the decryption of some chosen ciphertexts. We experimentally demonstrate that such attacks can be carried out, using either a plain mobile phone placed next to the computer, or a more sensitive microphone placed 4 meters away.

[The SIGMA Family of Key-Exchange Protocols ]()
* Summary: SIGMA is a family of cryptographic key-exchange protocols that provide perfect forward secrecy via a Diffie-Hellman exchange authenticated with digital signatures. SIGMA is designed to support a variety of features and trade-offs required in common practical scenarios (such as identity protection and reduced number of protocol rounds) as well as to enjoy sound cryptographic security. This design puts forth the "SIGn-and-MAc" (SIGMA, for short) approach that carefully combines the use of digital signatures and MAC functions to guarantee an authenticated binding between the Diffie-Hellman key and the identities of the parties to the exchange. This simple approach resolves security shortcomings found in previous protocols. The SIGMA protocols serve as the cryptographic basis for the signature-based modes of the standardized Internet Key Exchange (IKE) protocol, and its current revision IKE version 2. 














### <a name="software">Software</a>

[CONIKS](https://coniks.cs.princeton.edu/)
* CONIKS is a key management system for end users capable of integration in end-to-end secure communication services. The main idea is that users should not have to worry about managing encryption keys when they want to communicate securely, but they also should not have to trust their secure communication service providers to act in their interest. 

[The Noise Protocol Framework](http://noiseprotocol.org/noise.html)
* Noise is a framework for crypto protocols based on Diffie-Hellman key agreement. Noise can describe protocols that consist of a single message as well as interactive protocols.
* A Noise protocol begins with two parties exchanging handshake messages. During this handshake phase the parties exchange DH public keys and perform a sequence of DH operations, hashing the DH results into a shared secret key. After the handshake phase each party can use this shared key to send encrypted transport messages.

[VeraCrypt](https://www.veracrypt.fr/en/Home.html)
* VeraCrypt is a free open source disk encryption software for Windows, Mac OSX and Linux. Brought to you by IDRIX (https://www.idrix.fr) and based on TrueCrypt 7.1a.







### <a name="steno">Stenography</a>

[imagejs](https://github.com/jklmnn/imagejs)
* imagejs is a small tool to hide javascript inside a valid image file. The image file is recognized as one by content checking software, e.g. the file command you might now from Linux or other Unix based operation systems.

[Real-time Steganography with RTP](http://uninformed.org/?v=all&a=36&t=sumry)
* Real-time Transfer Protocol (RTP) is used by nearly all Voice-over-IP systems to provide the audio channel for calls. As such, it provides ample opportunity for the creation of a covert communication channel due to its very nature. While use of steganographic techniques with various audio cover-medium has been extensively researched, most applications of such have been limited to audio cover-medium of a static nature such as WAV or MP3 file audio data. This paper details a common technique for the use of steganography with audio data cover-medium, outlines the problem issues that arise when attempting to use such techniques to establish a full-duplex communications channel within audio data transmitted via an unreliable streaming protocol, and documents solutions to these problems. An implementation of the ideas discussed entitled SteganRTP is included in the reference materials. 


### Talks

[Hunting For Vulnerabilities In Signal - Markus Vervier - HITB 2017 AMS](https://www.youtube.com/watch?v=2n9HmllVftA)
* Signal is the most trusted secure messaging and secure voice application, recommended by Edward Snowden and the Grugq. And indeed Signal uses strong cryptography, relies on a solid system architecture, and you’ve never heard of any vulnerability in its code base. That’s what this talk is about: hunting for vulnerabilities in Signal. We will present vulnerabilities found in the Signal Android client, in the underlying Java libsignal library, and in example usage of the C libsignal library. Our demos will show how these can be used to crash Signal remotely, to bypass the MAC authentication for certain attached files, and to trigger memory corruption bugs. Combined with vulnerabilities in the Android system it is even possible to remotely brick certain Android devices. We will demonstrate how to initiate a permanent boot loop via a single Signal message. We will also describe the general architecture of Signal, its attack surface, the tools you can use to analyze it, and the general threat model for secure mobile communication apps.









### <a name="tools">Tools</a>

[Cryptographic Implementations Analysis Toolkit (CIAT)](http://ciat.sourceforge.net/)
* The Cryptographic Implementations Analysis Toolkit (CIAT) is compendium of command line and graphical tools whose aim is to help in the detection and analysis of encrypted byte sequences within files (executable and non-executable).

[Simple crypto tools](http://rumkin.com/tools/)

[keyCzar](http://www.keyczar.org/)
* Keyczar is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications. Keyczar supports authentication and encryption with both symmetric and asymmetric keys.

[Decrypto](http://sourceforge.net/projects/decrypto/)
* In DeCrypto you will find a collection of scripts for helping decrypt messages.\

[RELIC](https://github.com/relic-toolkit/relic)
* RELIC is a modern cryptographic meta-toolkit with emphasis on efficiency and flexibility. RELIC can be used to build efficient and usable cryptographic toolkits tailored for specific security levels and algorithmic choices.

[quipqiup](http://quipqiup.com/)
* quipqiup is a fast and automated cryptogram solver by Edwin Olson. It can solve simple substitution ciphers often found in newspapers, including puzzles like cryptoquips (in which word boundaries are preserved) and patristocrats (in which word boundaries aren't).

[HashID](https://github.com/psypanda/hashID)
* hashID is a tool written in Python 3 which supports the identification of over 220 unique hash types using regular expressions. It is able to identify a single hash, parse a file or read multiple files in a directory and identify the hashes within them. hashID is also capable of including the corresponding hashcat mode and/or JohnTheRipper format in its output. hashID works out of the box with Python 2 = 2.7.x or Python 3 = 3.3 on any platform.

[dislocker](https://github.com/Aorimn/dislocker)
* FUSE driver to read/write Windows' BitLocker-ed volumes under Linux / Mac OSX

[HiVE — Hidden Volume Encryption](http://hive.ccs.neu.edu/#four)

sheep-wolf](https://github.com/silentsignal/sheep-wolf/)
* Some security tools still stick to MD5 when identifying malware samples years after practical collisions were shown against the algorithm. This can be exploited by first showing these tools a harmless sample (Sheep) and then a malicious one (Wolf) that have the same MD5 hash. Please use this code to test if the security products in your reach use MD5 internally to fingerprint binaries and share your results by issuing a pull request updating the contents of results/!

[pypadbuster](https://github.com/escbar/pypadbuster)
* A Python version of PadBuster.pl by Gotham Digital Security (GDSSecurity on Github)

[padex](https://github.com/szdavid92/padex)
* The goal of this challenge is to find a flag contained in an encrypted message. A decryption oracle and the encrypted message is provided. The student should write an application that cracks the cyphertext by abusing the oracle which is vulnerable to the padding attack.

[Project HashClash](https://marc-stevens.nl/p/hashclash/)
* Project HashClash is a Framework for MD5 & SHA-1 Differential Path Construction and Chosen-Prefix Collisions for MD5. It's goal is to further understanding and study of the weaknesses of MD5 and SHA-1. 

[CPC-MD5](https://github.com/dingelish/cpc-md5)
* This project is forked from Marc Steven's Hashclash project hashclash and follows GPL.




### <a name="">Books</a>:
Books:
* Cryptography Engineering
* Applied Cryptography


### Crypto Libraries/Protocols

[OMEMO Multi-End Message and Object Encryption](https://conversations.im/omemo/)
* OMEMO is an XMPP Extension Protocol (XEP) for secure multi-client end-to-end encryption. It is an open standard based on a Double Ratchet and PEP which can be freely used and implemented by anyone. The protocol has been audited by a third party.






### Miscellaneous

[SSH Bad Keys](https://github.com/rapid7/ssh-badkeys)
* This is a collection of static SSH keys (host and authentication) that have made their way into software and hardware products. This was inspired by the Little Black Box project, but focused primarily on SSH (as opposed to TLS) keys.

[House of Keys](https://github.com/sec-consult/houseofkeys)
* Certificates including the matching private key and various private keys found in the firmware of embedded systems. Most certificates are used as HTTPS server certificates. Some private keys are used as SSH host keys. Other uses of these cryptographic keys were not analyzed yet. The names of products that contained the certificates/keys are included as well.



