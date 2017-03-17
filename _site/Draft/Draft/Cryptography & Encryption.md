##Cryptography



Learning/Courses
Books
Papers
Software
Writeups





###Cull

[Crypto: 48 Dirty Little Secrets Cryptographers Don’t Want You To Know - BlackHat2014](https://www.youtube.com/watch?v=mXdFHNJ6srY)


[HashID](https://github.com/psypanda/hashID)
* hashID is a tool written in Python 3 which supports the identification of over 220 unique hash types using regular expressions. It is able to identify a single hash, parse a file or read multiple files in a directory and identify the hashes within them. hashID is also capable of including the corresponding hashcat mode and/or JohnTheRipper format in its output. hashID works out of the box with Python 2 = 2.7.x or Python 3 = 3.3 on any platform.


[Attack of the week: FREAK (or 'factoring the NSA for fun and profit')](http://blog.cryptographyengineering.com/2015/03/attack-of-week-freak-or-factoring-nsa.html)



[quipqiup](http://quipqiup.com/)
* quipqiup is a fast and automated cryptogram solver by Edwin Olson. It can solve simple substitution ciphers often found in newspapers, including puzzles like cryptoquips (in which word boundaries are preserved) and patristocrats (inwhi chwor dboun darie saren t).









[Indistinguishability Obfuscation from the Multilinear Subgroup Elimination Assumption](https://eprint.iacr.org/2014/309)
*  Abstract: We revisit the question of constructing secure general-purpose indistinguishability obfuscation (iO), with a security reduction based on explicit computational assumptions over multi- linear maps. Previous to our work, such reductions were only known to exist based on meta- assumptions and/or ad-hoc assumptions: In the original constructive work of Garg et al. (FOCS 2013), the underlying explicit computational assumption encapsulated an exponential family of assumptions for each pair of circuits to be obfuscated. In the more recent work of Pass et al. (Crypto 2014), the underlying assumption is a meta-assumption that also encapsulates an exponential family of assumptions, and this meta-assumption is invoked in a manner that captures the specific pair of circuits to be obfuscated. The assumptions underlying both these works substantially capture (either explicitly or implicitly) the actual structure of the obfuscation mechanism itself.  In our work, we provide the first construction of general-purpose indistinguishability obfuscation proven secure via a reduction to a natural computational assumption over multilinear maps, namely, the Multilinear Subgroup Elimination Assumption. This assumption does not depend on the circuits to be obfuscated (except for its size), and does not correspond to the underlying structure of our obfuscator. The technical heart of our paper is our reduction, which gives a new way to argue about the security of indistinguishability obfuscation. 


[Decrypto](http://sourceforge.net/projects/decrypto/)
* In DeCrypto you will find a collection of scripts for helping decrypt messages.\

[A Messy State of the Union: Taming the Composite State Machines of TLS](https://www.smacktls.com/smack.pdf)
* Abstract —Implementations of the Transport Layer Security (TLS) protocol must handle a variety of protocol versions and extensions, authentication modes and key exchange methods, where each combination may prescribe a different message sequence between the client and the server. We address the problem of designing a robust composite state machine that can correctly multiplex between these different protocol modes. We systematically test popular open-source TLS implementations for state machine bugs and discover several critical security vulnerabilities that have lain hidden in these libraries for years (they are now in the process of being patched). We argue that these vulnerabilities stem from incorrect compositions of individually correct state machines. We present the first verified implementation of a composite TLS state machine in C that can be embedded into OpenSSL and accounts for all its supported ciphersuites. Our attacks expose the need for the formal verifica- tion of core components in cryptographic protocol libraries; our implementation demonstrates that such mechanized proofs are within reach, even for mainstream TLS implementations.




[RELIC](https://github.com/relic-toolkit/relic)
* RELIC is a modern cryptographic meta-toolkit with emphasis on efficiency and flexibility. RELIC can be used to build efficient and usable cryptographic toolkits tailored for specific security levels and algorithmic choices.


[Website detailing various crypto laws around world](http://www.cryptolaw.org/)

[Get Your Hands Off My Laptop: Physical Side-Channel Key-Extraction Attacks On PCs](http://www.tau.ac.il/~tromer/handsoff/)
* We demonstrated physical side-channel attacks on a popular software implementation of RSA and ElGamal, running on laptop computers. Our attacks use novel side channels and are based on the observation that the "ground" electric potential in many computers fluctuates in a computation-dependent way. An attacker can measure this signal by touching exposed metal on the computer's chassis with a plain wire, or even with a bare hand. The signal can also be measured at the remote end of Ethernet, VGA or USB cables. Through suitable cryptanalysis and signal processing, we have extracted 4096-bit RSA keys and 3072-bit ElGamal keys from laptops, via each of these channels, as well as via power analysis and electromagnetic probing. Despite the GHz-scale clock rate of the laptops and numerous noise sources, the full attacks require a few seconds of measurements using Medium Frequency signals (around 2 MHz), or one hour using Low Frequency signals (up to 40 kHz).

[Poor Man's Guide to Troubleshooting TLS Failures](http://blogs.technet.com/b/tspring/archive/2015/02/23/poor-man-s-guide-to-troubleshooting-tls-failures.aspx)

[Website detailing various crypto laws around world](http://www.cryptolaw.org/)

[Encrypting Strings in Android: Let's make better mistakes](http://tozny.com/blog/encrypting-strings-in-android-lets-make-better-mistakes/)

[cr.yp.to blog](http://blog.cr.yp.to/index.html)

[java-aes-crypto (Android class)](https://github.com/tozny/java-aes-crypto)
* A simple Android class for encrypting & decrypting strings, aiming to avoid the classic mistakes that most such classes suffer from.



[keyCzar](http://www.keyczar.org/)
* Keyczar is an open source cryptographic toolkit designed to make it easier and safer for developers to use cryptography in their applications. Keyczar supports authentication and encryption with both symmetric and asymmetric keys.

[RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis](http://www.tau.ac.il/~tromer/acoustic/)
* Here, we describe a new acoustic cryptanalysis key extraction attack, applicable to GnuPG's current implementation of RSA. The attack can extract full 4096-bit RSA decryption keys from laptop computers (of various models), within an hour, using the sound generated by the computer during the decryption of some chosen ciphertexts. We experimentally demonstrate that such attacks can be carried out, using either a plain mobile phone placed next to the computer, or a more sensitive microphone placed 4 meters away.


[Primer on Zero-Knowledge Proofs](http://blog.cryptographyengineering.com/2014/11/zero-knowledge-proofs-illustrated-primer.html?m=1)


[Widespread Weak Keys in Network Devices](https://factorable.net/)


http://www.tau.ac.il/~tromer/acoustic/
Here, we describe a new acoustic cryptanalysis key extraction attack, applicable to GnuPG's current implementation of RSA. The attack can extract full 4096-bit RSA decryption keys from laptop computers (of various models), within an hour, using the sound generated by the computer during the decryption of some chosen ciphertexts. We experimentally demonstrate that such attacks can be carried out, using either a plain mobile phone placed next to the computer, or a more sensitive microphone placed 4 meters away.


[Why does cryptographic software fail? A case study and open problems](http://pdos.csail.mit.edu/papers/cryptobugs:apsys14.pdf)
* Abstract: Mistakes in cryptographic software implementations often undermine the strong security guarantees offered by cryptography. This paper presents a systematic study of cryptographic vulnerabilities in practice, an examination of state-of-the-art techniques to prevent such vulnerabilities, and a discussion of open problems and possible future research directions. Our study covers 269 cryptographic vulnerabilities reported in the CVE database from January 2011 to May 2014. The results show that just 17% of the bugs are in cryptographic libraries (which often have devastating consequences), and the remaining 83% are misuses of cryptographic libraries by individual applications. We observe that preventing bugs in different parts of a system requires different techniques, and that no effective techniques exist to deal with certain classes of mistakes, such as weak key generation.


https://crypto.is/blog/

[Matsano Crypto Challenges](Cryptopals.co)

[Simple crypto tools](http://rumkin.com/tools/)



[Cryptographic Implementations Analysis Toolkit (CIAT)](http://ciat.sourceforge.net/)
* The Cryptographic Implementations Analysis Toolkit (CIAT) is compendium of command line and graphical tools whose aim is to help in the detection and analysis of encrypted byte sequences within files (executable and non-executable). 



[An Empirical Study of Cryptographic Misuse in Android Applications](https://www.cs.ucsb.edu/~chris/research/doc/ccs13_cryptolint.pdf)




###Books:
	Cryptography Engineering
	Applied Cryptography
	
###Courses:
	Coursera Cryptography



	Matsano Crypto Challenges
	Go through a series of increasingly difficult challenges while learning all about cryptography.
	Expected knowledge level: You passed 9th grade math and you have 0 knowledge of crypto.
		http://cryptopals.com/	




###Stenograhpy

[imagejs](https://github.com/jklmnn/imagejs)
* imagejs is a small tool to hide javascript inside a valid image file. The image file is recognized as one by content checking software, e.g. the file command you might now from Linux or other Unix based operation systems.


