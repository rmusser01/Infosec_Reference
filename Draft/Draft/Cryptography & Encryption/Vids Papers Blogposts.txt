##Resources

[Attacking and Defending Full Disk Encryption - Tom Kopchak](http://www.irongeek.com/i.php?page=videos/bsidescleveland2014/attacking-and-defending-full-disk-encryption-tom-kopchak)

[InsidePro Wiki](http://wiki.insidepro.com/index.php/Main_Page)
Here you will find a lot of useful and unique information: 
Detailed descriptions of various hashing algorithms and check sums. 
Source codes of those algorithms in various programming languages. 
Information on the application of certain algorithms. 
Description of the applications that support such hashes. 	
Various articles on the subject. 
Useful advice on handling hashes. 
Links to various online resources on the subject of recovering passwords from hashes. 
And much more. 

[Zero-Knowledge Proofs - An Illustrated Primer](http://blog.cryptographyengineering.com/2014/11/zero-knowledge-proofs-illustrated-primer.html?m=1)

[Applied Cryptographic Hardening](https://bettercrypto.org/static/applied-crypto-hardening.pdf)

[Instant ciphertext-only cryptnalysis of GSM encryptd communications](http://cryptome.org/gsm-crack-bbk.pdf)

[Malleability Attack against CBC Encrypted LUKS partitions](http://www.jakoblell.com/blog/2013/12/22/practical-malleability-attack-against-cbc-encrypted-luks-partitions/)

[How CryptoSystems are *Really* broken](http://www.forth.gr/onassis/lectures/pdf/How_Cryptosystems_Are_Really_Broken.pdf)

[Toward Robust Hidden Volumes using Write-Only Oblivious RAM](https://eprint.iacr.org/2014/344.pdf)

* With sensitive data being increasingly stored on mobile devices and laptops, hard disk encryption is more important than ever. In partic- ular, being able to plausibly deny that a hard disk contains certain information is a very useful and interesting research goal. However, it has been known for some time that existing “hidden volume” so- lutions, like TrueCrypt, fail in the face of an adversary who is able to observe the contents of a disk on multiple, separate occasions. In this work, we explore more robust constructions for hidden vol- umes and present HIVE, which is resistant to more powerful ad- versaries with multiple-snapshot capabilities. In pursuit of this, we propose the first security definitions for hidden volumes, and prove HIVE secure under these definitions. At the core of HIVE, we de- sign a new write-only Oblivious RAM. We show that, when only hiding writes, it is possible to achieve ORAM with optimal O (1) communication complexity and only poly-logarithmic user mem- ory. This is a significant improvement over existing work and an independently interesting result. We go on to show that our write- only ORAM is specially equipped to provide hidden volume func- tionality with low overhead and significantly increased security. Fi- nally, we implement HIVE as a Linux kernel block device to show both its practicality and usefulness on existing platforms.