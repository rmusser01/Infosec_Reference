##Password Bruting and Hashcracking


###Cull
http://blog.erratasec.com/2011/06/password-cracking-mining-and-gpus.html#.VG3xspPF_tw

http://arstechnica.com/security/2013/03/how-i-became-a-password-cracker/

[Crackstation’s Password Cracking Dictionary 1.5b words](https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm)
* HIGHLY recommended

[GitDigger](https://github.com/wick2o/gitdigger)
* gitDigger: Creating realworld wordlists from github hosted data.

[5min Guide to setting up a GPU cracker in the cloud on AWS + a script to automate it all](http://thehackerblog.com/amazon-ec2-gpu-hvm-spot-instance-cracking-setup-tutorial/)


[WPA/WPA2 Dictionaries](https://wifi0wn.wordpress.com/wepwpawpa2-cracking-dictionary/)



[How to Pull passwords from a memory dump](https://cyberarms.wordpress.com/2011/11/04/memory-forensics-how-to-pull-passwords-from-a-memory-dump/)

[Dumping a Domains worth of passwords using mimikatz](http://carnal0wnage.attackresearch.com/2013/10/dumping-domains-worth-of-passwords-with.html)



[Dump Windows password hashes efficiently - Part 1](bernardodamele.blogspot.com/2011/12/dump-windows-password-hashes.html)


[crackxls2003 0.4](https://github.com/GavinSmith0123/crackxls2003)
* This program may be used to break the encryption on Microsoft Excel and
Microsoft Word file which have been encrypted using the RC4 method, which
uses a 40-bit-long key. This was the default encryption method in Word and Excel
97/2000/2002/2003. This program will not work on files encrypted using Word
or Excel 2007 or later, or for versions 95 or earlier. It will not work if
a file was encrypted with a non-default method. Additionally, documents
created with the Windows system locale set to France may use a different
encryption method.


[Password Recovery Speeds](http://www.lockdown.co.uk/?pg=combi)
* Password cracking time measurements

Building a Better GPU based hash cracking methodology](https://blog.netspi.com/gpu-password-cracking-building-a-bette Penr-methodology/)
* Bit basic advice but still great advice nonetheless



[Introduction to Cracking Hashes](http://n0where.net/introduction-break-that-hash/)
* Good introduction source to hash cracking.




[OCL hashcat wiki](http://hashcat.net/wiki/)
* Its the Wiki

[OCL hashcat](http://n0where.net/introduction-break-that-hash/)
* It’s OCL hashcat

Hashcat attacks
[Mask atttack](http://hashcat.net/wiki/doku.php?id=mask_attack)
* Try all combinations from a given keyspace just like in Brute-Force attack, but more specific. 

[Combinator attack](http://hashcat.net/wiki/doku.php?id=combinator_attack)
* Each word of a dictionary is appended to each word in a dictionary. 

[Dictionary attack](http://hashcat.net/wiki/doku.php?id=dictionary_attack)
* The dictionary attack is a very simple attack mode. It is also known as a “Wordlist attack”. 

[Fingerprint Attack](http://hashcat.net/wiki/doku.php?id=fingerprint_attack)
* The Fingerprint attack is a combination of the results of the expander with a combination engine. It is an automatically generated attack on pattern that works fine on GPGPU. 

[Hybrid attack](http://hashcat.net/wiki/doku.php?id=hybrid_attack)
* Basically, the hybrid attack is just a Combinator attack. One side is simply a dictionary, the other is the result of a Brute-Force attack. In other words, the full Brute-Force keyspace is either appended or prepended to each of the words from the dictionary. That's why it's called “hybrid”. 

[Mask attack](http://hashcat.net/wiki/doku.php?id=mask_attack)
* Try all combinations from a given keyspace just like in Brute-Force attack, but more specific. 

[Permutation attack[(http://hashcat.net/wiki/doku.php?id=permutation_attack)
* Each word in a dictionary generates all permutations of itself. 

[Rule Based attack](http://hashcat.net/wiki/doku.php?id=rule_based_attack)
* The rule-based attack is one of the most complicated of all the attack modes. The reason for this is very simple. The rule-based attack is like a programming language designed for password candidate generation. It has functions to modify, cut or extend words and has conditional operators to skip some, etc. That makes it the most flexible, accurate and efficient attack. 

[Table Lookup attack](http://hashcat.net/wiki/doku.php?id=table_lookup_attack)
* With each word in our dictionary, it automatically generates masks as in a batch of Mask attack. 

[Toggle-Case attack](http://hashcat.net/wiki/doku.php?id=toggle_case_attack)
* For each word in a dictionary, all possible combinations of upper- and lower-case variants are generated. 











Password Cracking

Website Dedicated to Password Research
	http://www.passwordresearch.com/papers/pubindex.html

	A core objective of the Password Research Institute is to improve the industry awareness of existing authentication research. Many valuable solutions for the problems associated with authentication have gone unnoticed by the people interested in, or responsible for, authentication security. 

	This project will compile and share a comprehensive, but moderated, index of password and authentication related research papers. We aim to share the details of useful papers, provide access to the papers, and encourage collaboration between authors and other security professionals.




Crunch

Creating Wordlists with Crunch
http://adaywithtape.blogspot.com/2011/05/creating-wordlists-with-crunch-v30.html

Generating Wordlists:
http://netsec.ws/?p=457


###Writeups

#####[How to crack password hashes efficiently](http://www.dafthack.com/blog/howtocrackpasswordhashesefficiently)
* Excellent writeup/methodology explanation


List of hash types/examples
https://docs.google.com/file/d/0B0TzWBRmg5pWWUtxRTFMbFRRZzA/edit




###Tools

#####[Patator](https://github.com/lanjelot/patator)
* Patator was written out of frustration from using Hydra, Medusa, Ncrack, Metasploit modules and Nmap NSE scripts for password guessing attacks. I opted for a different approach in order to not create yet another brute-forcing tool and avoid repeating the same shortcomings. Patator is a multi-threaded tool written in Python, that strives to be more reliable and flexible than his fellow predecessors.


#####[CeWL](http://digi.ninja/projects/cewl.php)
* CeWL is a ruby app which spiders a given url to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers such as John the Ripper. 

#####[Wikigen](https://github.com/zombiesam/wikigen)
* A script to generate wordlists out of wikipedia pages. Should support most of the subdomains. Some ugly code may occur

#####[Hashtag](http://www.smeegesec.com/2013/11/hashtag-password-hash-identification.html)
* Password hash identification tool written in python

#####[Firefox password cracker](https://github.com/pradeep1288/ffpasscracker)

###Papers

#####[Optimizing computation of Hash Algorithms as an attacker](https://hashcat.net/events/p13/js-ocohaaaa.pdf)


###Wordlists

[SkullSecurity Password lists](https://wiki.skullsecurity.org/Passwords)

[CrackStation’s Password Cracking Dictionary](https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm)

[Crack Me if You Can - Defcon 2010](http://contest-2010.korelogic.com/wordlists.html)

rockyou















