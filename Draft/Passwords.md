# Password Bruting and Hashcracking

----------------------------------------------------
## Table of Contents
- [General](#general)
	- [BruteForce](#brute)
	- [CAPTCHA](#captcha)
	- [Password Auditing](#audit)
	- [Default Credentials](#default)
	- [Password Statistics](#stats)
	- [Password Spraying](#spray)
	- [Wordlist Generation](#wordlistgen)
	- [Wordlists](#wordlists)
- [Cracking Passwords/Hashes](#crack)
	- [CAPTCHA](#captcha)
	- [John-the-Ripper](#jtr)
	- [Hashcat](#hashcat)
		- [Automating Hashcat](#hauto)
		- [Hashcat Attacks](#hattack)
		- [Hashcat Rules](#hrules)
		- [Hashcat Tools](#htools)
- [App Specific Tools(as in single application focus)](#appt)
	- [KeePass](#keepass)
	- [MS Office](#msoffice)
	- [PDFs](#pdf)
	- [Zip Files](#zip)
- [General Cracking Tools](#generalt)
- [Papers](#papers)
----------------------------------------------------

* **To-Do**
	* Crackmeifyoucan contests
	* Other contests
	* Other stuff

---------------------------
### <a name="general"></a> General
* **101**
* **Account Validation**
	* [Six Methods to Determine Valid User Accounts in Web Applications - Dave](https://whiteoaksecurity.com/blog/2019/2/11/six-methods-to-determine-valid-user-accounts-in-web-applications)
* **Articles/Papers/Talks/Writeups**
	* [RockYou Wordlist Origin](https://en.wikipedia.org/wiki/RockYou#Data_breach)
	* [How I fcame a password cracker](https://arstechnica.com/information-technology/2013/03/how-i-became-a-password-cracker/)
	* [Th3 L@s7 0f u$: Analysis of Survival Password Genetics - @netmux](https://www.netmux.com/blog/survivor-password-hashes)
	* [A cr4cking g00d time – 12 challenges. 1 cryptocurrency prize! - @stealthsploit](https://in.security/password-cracking-ctf/)
		* [A cr4cking g00d time – walkthrough](https://in.security/a-cr4cking-g00d-time-walkthrough/)
	* [Authentication Research Paper Index - PasswordResearch.com](http://www.passwordresearch.com/papers/pubindex.html)
		*  This project is an ongoing effort to compile and share a comprehensive, but curated, index of password and authentication related research produced by academic, industry, and government experts. We share the details of useful research, provide links to free copies of the papers (when possible), and encourage collaboration between authors and other security professionals. 
* **Building a Hash Cracking Rig**
	* [Why Most Passwords Suck - Brett Dewall(2019)](https://whiteoaksecurity.com/blog/2019/5/2/why-most-passwords-suck)
	* [How To Build A Password Cracking Rig](https://www.netmux.com/blog/how-to-build-a-password-cracking-rig)
* **BruteForce**<a name="brute"></a>
	* **Tools**
		* [Crowbar](https://github.com/galkan/crowbar)
			* Crowbar is brute forcing tool that can be used during penetration tests. It is developed to support protocols that are not currently supported by thc-hydra and other popular brute forcing tools.
* **CAPTCHA**<a name="captcha"></a>
* **Default Credentials**<a name="default"></a>
	* [Web Application Defaults DB(2012)](https://github.com/pwnwiki/webappdefaultsdb)
		* A DB of known Web Application Admin URLS, Username/Password Combos and Exploits
	* [Web Application Defaults DB(2013)](https://github.com/pwnwiki/webappdefaultsdb)
	* [Default Oracle Creds](http://www.petefinnigan.com/default/default_password_list.htm)
* **Password Analysis/Auditing**<a name="audit"></a>
	* **101**
		* [Validating the user password selection in Azure AD B2C by invoking Troy Hunt’s “Pwned Passwords” API - Rory Braybrook](https://medium.com/the-new-control-plane/validating-the-user-password-selection-in-azure-ad-b2c-by-invoking-troy-hunts-pwned-passwords-fbb044b26698)
	* **Articles/Papers/Talks/Writeups**
		* [Analyzing large password dumps with Elastic Stack and Python - Victor Pasknel(2018)](https://morphuslabs.com/analyzing-large-password-dumps-with-elastic-stack-and-python-cde7eb384f7)
	* **Tools**
		* **Active Directory**
			* [Domain Password Audit Tool (DPAT)](https://github.com/clr2of8/DPAT)
				* This is a python script that will generate password use statistics from password hashes dumped from a domain controller and a password crack file such as hashcat.potfile generated from the Hashcat tool during password cracking. The report is an HTML report with clickable links.
			* [Match-ADHashes](https://github.com/DGG-IT/Match-ADHashes)
				* Builds a hashmap of AD NTLM hashes/usernames and iterates through a second list of hashes checking for the existence of each entry in the AD NTLM hashmap
		* **General**
			* [Cryptbreaker](https://github.com/Sy14r/Cryptbreaker)
				* Upload files and use AWS Spot Instances to crack passwords. Using cloud capabilities you can even prevent plaintext credentials from leaving the isolated cracking box ensuring that you get usable statistics on passwords while minimizing plaintext credential exposure.
* **Password Generation**
	* **Tools**
		* [DPG](https://github.com/62726164/dpg)
			* DPG is a deterministic password generator that does not store data or keep state. Its output is based purely on user input.
		* [Password Guessing Framework](https://github.com/RUB-SysSec/Password-Guessing-Framework)
			* The Password Guessing Framework is an open source tool to provide an automated and reliable way to compare password guessers. It can help to identify individual strengths and weaknesses of a guesser, its modes of operation or even the underlying guessing strategies. Therefor, it gathers information about how many passwords from an input file (password leak) have been cracked in relation to the amount of generated guesses. Subsequent to the guessing process an analysis of the cracked passwords is performed.
* **Password Strength/Usage Statistics**<a name="stats"></a>
	* [Password Statistics - ldapwiki(2018)](https://ldapwiki.com/wiki/Password%20Statistics)
	* [Authentication Statistic Index - PasswordResearch.com](http://www.passwordresearch.com/stats/statindex.html)
		* This page offers an categorized index of useful and commonly requested authentication statistics. Want to see how your organization's password practices compare to others? Interested in targeting a topic for user awareness training? Find the statistics that interest you and click on the title to read the details. 
	* [A Study of Chinese Passwords - Sunnia Ye(2018)](https://medium.com/@ye.sunnia/an-analysis-of-chinese-passwords-e49b97b91919)
	* [Analysing over 1M leaked passwords from the UK's biggest companies - passlo](https://www.passlo.com/blog/analysing-over-1m-leaked-passwords-from-the-uks-biggest-companies/)
	* [Uncovering Password Habits: Are Users’ Password Security Habits Improving? (Infographic) - Nate Lord(2018)](https://digitalguardian.com/blog/uncovering-password-habits-are-users-password-security-habits-improving-infographic)
	* [44 million Microsoft users reused passwords in the first three months of 2019 - Catalin Cimpanu(2019)]
	* [Most hacked passwords revealed as UK cyber survey exposes gaps in online security](https://www.ncsc.gov.uk/news/most-hacked-passwords-revealed-as-uk-cyber-survey-exposes-gaps-in-online-security)
		* The NCSC's first 'UK cyber survey' published alongside global password risk list
	* [Ranked: The World’s Top 100 Worst Passwords - Davey Winder(2019)](https://www.forbes.com/sites/daveywinder/2019/12/14/ranked-the-worlds-100-worst-passwords/#276122e169b4)
* **Password Spraying <a name="spray"></a>**
	* **General**
		* **Articles/Papers/Talks/Writeups**
			* [Exploiting Password Reuse on Personal Accounts: How to Gain Access to Domain Credentials Without Being on a Target’s Network: Part 1 - Beau Bullock](https://www.blackhillsinfosec.com/exploiting-password-reuse-on-personal-accounts-how-to-gain-access-to-domain-credentials-without-being-on-a-targets-network-part-1/)
			* [Brute Forcing with Burp - Pentesters Tips & Tricks Week 1 - securenetwork.com](https://www.securenetworkinc.com/news/2017/7/16/brute-forcing-with-burp-pentesters-tips-tricks-week-1)
		* **Tools**	
			* [brut3k1t](https://github.com/ex0dus-0x/brut3k1t)
				* brute is a Python-based library framework and engine that enables security professionals to rapidly construct bruteforce / credential stuffing attacks. It features both a multi-purpose command-line application (brute), and a software library that can be used in tandem to quickly generate standalone module scripts for attack.
	* **Linux**
		* [Raining shells on Linux environments with Hwacha](https://www.n00py.io/2017/12/raining-shells-on-linux-environments-with-hwacha/)
		* [Hwacha](https://github.com/n00py/Hwacha)
			* Hwacha is a tool to quickly execute payloads on `*`Nix based systems. Easily collect artifacts or execute shellcode on an entire subnet of systems for which credentials are obtained.
	* **MS Outlook/Office365**
		* **Articles/Papers/Talks/Writeups**
			* [Password Spraying Outlook Web Access – How to Gain Access to Domain Credentials Without Being on a Target’s Network: Part 2 - Beau Bullock](https://www.blackhillsinfosec.com/password-spraying-outlook-web-access-how-to-gain-access-to-domain-credentials-without-being-on-a-targets-network-part-2/)
		* **Tools**	
			* [MSOLSpray](https://github.com/dafthack/MSOLSpray)
				* A password spraying tool for Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
			* [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit)
				* Scripts to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient
	* **Windows**
		* [Use PowerShell to Get Account Lockout and Password Policy](https://blogs.technet.microsoft.com/heyscriptingguy/2014/01/09/use-powershell-to-get-account-lockout-and-password-policy/)
		* [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
			* DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain.
		* [NTLM - Open-source script from root9B for manipulating NTLM authentication](https://github.com/root9b/NTLM)
			* This script tests a single hash or file of hashes against an ntlmv2 challenge/response e.g. from auxiliary/server/capture/smb The idea is that you can identify re-used passwords between accounts that you do have the hash for and accounts that you do not have the hash for, offline and without cracking the password hashes. This saves you from trying your hashes against other accounts live, which triggers lockouts and alerts.
		* [CredNinja](https://github.com/Raikia/CredNinja)
			* A multithreaded tool designed to identify if credentials are valid, invalid, or local admin valid credentials within a network at-scale via SMB, plus now with a user hunter.
		* [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit/blob/master/README.md)
			* A set of Python scripts/utilities that tries to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient.
		* [RDPassSpray](https://github.com/xFreed0m/RDPassSpray)
			* Python3 tool to perform password spraying using RDP
* **Wordlist Generation** <a name="wordlistgen"></a>
	* **Articles/Writeups**
		* [Generating Wordlists](http://netsec.ws/?p=457)
		* [Weak in, Weak out: Keeping Password Lists Current - @NYXGEEK](https://www.trustedsec.com/blog/weak-in-weak-out-keeping-password-lists-current/)
		* [Efficient Wordlists - Why you don't need 25GB To Be a Pro - Dimitri Fousekis(2015)](http://passwordresearch.com/papers/paper622.html)
		* [Generating Custom Wordlists For Targeted Attacks - securethelogs(2019)](https://securethelogs.com/2019/05/25/generating-custom-wordlists-for-targeted-attacks/)
	* **Source: From Nothing**
		* [Creating Wordlists with Crunch](http://adaywithtape.blogspot.com/2011/05/creating-wordlists-with-crunch-v30.html)
		* [weakpass_generator](https://github.com/nyxgeek/weakpass_generator)
			* generates weak passwords based on current date
	* **Source: Keyboard Walks**
		* [Generating Keyboard Walks - bytesdarkly.com](https://bytesdarkly.com/2014/08/generating-keyboard-walks/)
		* [Methods to Generate Keyboard Walks for Password Cracking - Rich Kelley](https://github.com/Rich5/Keyboard-Walk-Generators)
	* **Source: Permutations Based on User Input**
		* [Creating Wordlists with Crunch](http://adaywithtape.blogspot.com/2011/05/creating-wordlists-with-crunch-v30.html)
		* [OMEN: Ordered Markov ENumerator](https://github.com/RUB-SysSec/OMEN)
			* OMEN is a Markov model-based password guesser written in C. It generates password candidates according to their occurrence probabilities, i.e., it outputs most likely passwords first. OMEN significantly improves guessing speed over existing proposals. If you are interested in the details on how OMEN improves on existing Markov model-based password guessing approaches, please refer to OMEN: Faster Password Guessing Using an Ordered Markov Enumerator.
	* **Source: User Profiling**
		* [Mentalist](https://github.com/sc0tfree/mentalist)
			* Mentalist is a graphical tool for custom wordlist generation. It utilizes common human paradigms for constructing passwords and can output the full wordlist as well as rules compatible with Hashcat and John the Ripper.
			* [Wiki](https://github.com/sc0tfree/mentalist/wiki)
		* [cupp.py - Common User Passwords Profiler](https://github.com/Mebus/cupp)
			* The most common form of authentication is the combination of a username and a password or passphrase. If both match values stored within a locally stored table, the user is authenticated for a connection. Password strength is a measure of the difficulty involved in guessing or breaking the password through cryptographic techniques or library-based automated testing of alternate values. A weak password might be very short or only use alphanumberic characters, making decryption simple. A weak password can also be one that is easily guessed by someone profiling the user, such as a birthday, nickname, address, name of a pet or relative, or a common word such as God, love, money or password. That is why CUPP has born, and it can be used in situations like legal penetration tests or forensic crime investigations.
	* **Source: Designated website/resource**
		* [GitDigger](https://github.com/wick2o/gitdigger)
			* gitDigger: Creating realworld wordlists from github hosted data.
		* [Wikigen](https://github.com/zombiesam/wikigen)
			* A script to generate wordlists out of wikipedia pages. Should support most of the subdomains. Some ugly code may occur
		* [CeWL](http://digi.ninja/projects/cewl.php)
			* CeWL is a ruby app which spiders a given url to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers such as John the Ripper.
			* [Comprehensive Guide on Cewl Tool - Raj Chandel](https://rajhackingarticles.blogspot.com/2018/11/hello-friends-in-this-article-we-are.html)
		* [rhodiola](https://github.com/utkusen/rhodiola)
			* Rhodiola tool is developed to narrow the brute force combination pool by creating a personalized wordlist for target people. It finds interest areas of a given user by analyzing his/her tweets, and builds a personalized wordlist.
	 	* [Generating Personalized Wordlists by Analyzing Targets Tweets - Utku Sen(DEFCON27 ReconVillage)](https://www.youtube.com/watch?v=R3XuI9JUFDA&list=PL9fPq3eQfaaCkpP6XOD4uCQB6NpGrbujo&index=4&t=0s)
	* **BigData**
		* [Commonspeak2](https://github.com/assetnote/commonspeak2)
    		* Commonspeak2 leverages publicly available datasets from Google BigQuery to generate content discovery and subdomain wordlists. As these datasets are updated on a regular basis, the wordlists generated via Commonspeak2 reflect the current technologies used on the web. By using the Golang client for BigQuery, we can stream the data and process it very quickly. The future of this project will revolve around improving the quality of wordlists generated by creating automated filters and substitution functions. Let's turn creating wordlists from a manual task, into a reproducible and reliable science with BigQuery.
    * **Modifying Wordlists**
	    * [HVAZARD Dictionary Modifier](https://github.com/MichaelDim02/Hvazard)
			* Remove short passwords & duplicates, change lowercase to uppercase & reverse, combine wordlists!
		* [duprule](https://github.com/0xbsec/duprule)
			*  Detect & filter duplicate hashcat rules
		* [rurasort](https://github.com/bitcrackcyber/rurasort)
			* This utility is used to help you streamline your worldlists by performing tasks on them. Note that output is made to STDOUT and you have to pipe data to where you want it to go. Usually to a file with > myfile.txt
		* [cauldera](https://github.com/aaronjones111/cauldera)
			* Distillations, expansions and riffs on Rocktastic Why cauldera? As potent as I've found rocktastic to be, and wickedly effective using PACK has been, I picture the gargantuon results of their combination to be a massive, simmering pool of doom. Like Yellowstone.
		* [cudaMergeSort](https://github.com/epixoip/cudaMergeSort)
			* cudaMergeSort is a highly parallel hybrid mergesort for sorting large files of arbitrary ASCII text (such as password cracking wordlists.) It is intended to be a fast replacement for sort(1) for large files. A parallel radix sort is performed on each chunk of the input file on GPU (complements of Thrust), while each chunk is merged in parallel on the host CPU. Only unique lines are merged, and cudaMergeSort is therefore directly analogous to performing sort -u on an ASCII text file.
* **Lists of Wordlists** <a name="wordlists"></a>
	* [Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists)
		* Wordlists sorted by probability originally created for password generation and testing
	* [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
		* This resource contains wordlists for creating statistically likely usernames for use in username-enumeration, simulated password-attacks and other security testing tasks.
	* [SecLists](https://github.com/danielmiessler/SecLists)
	* [Crackstation’s Password Cracking Dictionary 1.5b words](https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm)
		* HIGHLY recommended
	* [WPA/WPA2 Dictionaries](https://wifi0wn.wordpress.com/wepwpawpa2-cracking-dictionary/)
	* [SkullSecurity Password lists](https://wiki.skullsecurity.org/Passwords)
	* [Crack Me if You Can - Defcon 2010](http://contest-2010.korelogic.com/wordlists.html)
	* [BEWGor](https://github.com/berzerk0/BEWGor)
		* Bull's Eye Wordlist Generator
	* [SecLists](https://github.com/danielmiessler/SecLists)
	* [Oracle Default Password List](http://www.petefinnigan.com/default/default_password_list.htm)
	* [Passhunt](https://github.com/Viralmaniar/Passhunt/blob/master/README.md)
		* Passhunt is a simple tool for searching of default credentials for network devices, web applications and more. Search through 523 vendors and their 2084 default passwords.
	* [Rocktastic: a word list on steroids - nettitude](https://labs.nettitude.com/blog/rocktastic/)
	* [Commonspeak: Content discovery wordlists built with BigQuery - Shubham Shah](https://pentester.io/commonspeak-bigquery-wordlists/)
	* [passphrase-wordlist](https://github.com/initstring/passphrase-wordlist)
		*  Passphrase wordlist and hashcat rules for offline cracking of long, complex passwords 
	* [Google Fuzzing dictionaries](https://github.com/google/fuzzing/tree/master/dictionaries)
* **Wordlist Tools**
	* [HVAZARD Dictionary Modifier](https://github.com/MichaelDim02/Hvazard)
		* Remove short passwords & duplicates, change lowercase to uppercase & reverse, combine wordlists!
* **Other**
	* [HashView](https://github.com/hashview/hashview)
		* Hashview is a tool for security professionals to help organize and automate the repetitious tasks related to password cracking. Hashview is a web application that manages hashcat (https://hashcat.net) commands. Hashview strives to bring constiency in your hashcat tasks while delivering analytics with pretty pictures ready for ctrl+c, ctrl+v into your reports.
	* [Password cracking, mining, and GPUs](http://blog.erratasec.com/2011/06/password-cracking-mining-and-gpus.html#.VG3xspPF_tw)
	* [CredKing](https://github.com/ustayready/CredKing)
		* Password spraying using AWS Lambda for IP rotation


































--------------------
### Cracking Hashes
* **Cracking Passwords/Hashes**<a name="crack"></a>
	* **101**
		* [Introduction to Cracking Hashes](http://n0where.net/introduction-break-that-
		/)
			* Good introduction source to hash cracking.
		* [Example hashes - hashcat.net](https://hashcat.net/wiki/doku.php?id=example_hashes)
		* [A Practical Guide to Cracking Password Hashes - Matt Marx(2015)](https://labs.f-secure.com/archive/a-practical-guide-to-cracking-password-hashes/)
		* [My password cracking brings all the hashes to the yard.. - Larry Pesce(Hackfest2015)](https://web.archive.org/web/20190926024106/https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1493862354.pdf)
		* [Password Cracking 201: Beyond the Basics - Royce Williams(2017)](https://www.youtube.com/watch?v=cSOjQI0qbuU)
			* [Slides](https://www.techsolvency.com/talks/2017-bsideslv/bslv17_ground1234_passwords-201-beyond-the-basics_royce-williams_2017-07-26.pdf)
		* [Password Cracking – Here’s How the Pros Do It - Nick VanGilder(2018)](http://blog.cspire.com/password-cracking-heres-how-the-pros-do-it)
		* [Let's Get Cracking: A Beginner's Guide to Password Analysis - Steve Tornio(2019)](https://blog.focal-point.com/lets-get-cracking-a-beginners-guide-to-password-analysis)
		* [Hashcat: How to discard words of length less than N after rules have been applied? - StackExchange(2018)](https://security.stackexchange.com/questions/195682/hashcat-how-to-discard-words-of-length-less-than-n-after-rules-have-been-applie)
	* **Reference**
		* [List of hash types/examples](https://docs.google.com/file/d/0B0TzWBRmg5pWWUtxRTFMbFRRZzA/edit)
		* [Password Recovery Speeds](http://www.lockdown.co.uk/?pg=combi)
			* Password cracking time measurements
	* **Articles & Writeups**
		* [Cracking Active Directory Passwords or “How to Cook AD Crack"](https://www.sans.org/reading-room/whitepapers/testing/cracking-active-directory-passwords-how-cook-ad-crack-37940)
		* [How to crack password hashes efficiently](http://www.dafthack.com/blog/howtocrackpasswordhashesefficiently)
			* Excellent writeup/methodology explanation
		* [Building a Better GPU based hash cracking methodology](https://blog.netspi.com/gpu-password-cracking-building-a-bette Penr-methodology/)
			* Bit basic advice but still great advice nonetheless
		* [5min Guide to setting up a GPU cracker in the cloud on AWS + a script to automate it all](http://thehackerblog.com/amazon-ec2-gpu-hvm-spot-instance-cracking-setup-tutorial/)
		* [GPU Password Cracking – Building a Better Methodology - Karl Fosaaen](https://blog.netspi.com/gpu-password-cracking-building-a-better-methodology/)
		* [oclHashcat, HalfLM (netlm), and Bruteforcing the Second Half - jedge.com](http://www.jedge.com/wordpress/2014/01/oclhashcat-halflm-netlm-and-bruteforcing-the-second-half/)
		* [Hashdumps and Passwords(2010-2014) - adeptus-mechanicus](http://www.adeptus-mechanicus.com/codex/hashpass/hashpass.php)
		* [Statistics Will Crack Your Password - Julian Dunning](https://p16.praetorian.com/blog/statistics-will-crack-your-password-mask-structure)
		* [Unmasked:  What 10 million passwords reveal about the people who choose them](https://wpengine.com/unmasked/)
		* [Password cracking and auditing - DarthSidious](https://hunter2.gitbook.io/darthsidious/credential-access/password-cracking-and-auditing)
		* [Estimating Password Cracking Times - BetterBuys(2016)](https://www.betterbuys.com/estimating-password-cracking-times/)
	* **Talks/Videos/Presentations**
		* [Cracking Corporate Passwords – Exploiting Password Policy Weaknesses - Rick Redman(Derbycon2013)](https://www.irongeek.com/i.php?page=videos/derbycon3/1301-cracking-corporate-passwords-exploiting-password-policy-weaknesses-minga-rick-redman)
			* “Cracking corporate passwords is no different than cracking public MD5 leaks off of pastebin. Except, it totally is. Corporate passwords are not in the same formats you are used to, they require capital letters, numbers and/or special characters.“Cracking corporate passwords is no different than cracking public MD5 leaks off of pastebin. Except, it totally is. Corporate passwords are not in the same formats you are used to, they require capital letters, numbers and/or special characters. - How can we use this knowledge to our advantage?; - What sort of tricks are users doing when they think no one is looking?; - What other types of vulnerabilities is Password policy introducing?; - What patterns is password rotation policy creating?
		* [PRINCE: modern password guessing algorithm - Jens Steube(2014)](https://web.archive.org/web/20200214080638/https://hashcat.net/events/p14-trondheim/prince-attack.pdf)
			* [Tutorial - atom(2015)](https://web.archive.org/web/20200721235117/https://hashcat.net/forum/thread-3914.html)
		* [Modeling Password Creation Habits with Probabilistic Context Free Grammars - Dr Matt Weir(BSidesLV2016)](https://www.youtube.com/watch?v=IjqjVduCB6k)
			* [Slides](http://passwordresearch.com/papers/paper668.html)
		* [Hashcat: GPU password cracking for maximum win - `_NSAKEY`(PhreakNIC 19)](https://www.youtube.com/watch?v=_QbVP1yh2YI)
			* After briefly touching on the general concept of password cracking, the focus of the talk will be on the effectiveness of different attack modes in hashcat, with a heavy emphasis on rule-based attacks. While the name of the talk is â€œhashcat,â€ this talk will almost exclusively discuss the GPU-enabled versions (Specifically cudahashcat). The final phase of the talk will include the results of my own experiments in creating rule sets for password cracking, along with an analysis of the known plaintext passwords from the test hash list.
			* [Slides](https://www.slideshare.net/_NSAKEY/hashcat-gpu-password-cracking-for-maximum-win-57720263)
		* [SecTalks SYD0x37 (55th)-Password Cracking in 2020 (or) why does this still work? - Raaqim Mohammed(2020)](https://www.youtube.com/watch?v=Ovi0XdZ0gis)
			* It was the 90s, I was but a child and LM hashes ruled the day. Windows didn't salt their hashes.  It is 2020, I grew up and NTLM hashes ruled the day. Windows didn't salt their hashes. This presentation will provide a guide of what to do once you get your hands on these tasty hashes and need to figure out how to 'crack' them when things aren't as easy as you expected...
	* **Password Rulesets**
		* [Statistics Will Crack Your Password - Julian Dunning(2015)](https://www.praetorian.com/blog/statistics-will-crack-your-password-mask-structure)
		* [Hob0Rules Released: Statistics Based Password Cracking Rules - Julian Dunning(2016)](https://www.praetorian.com/blog/hob064-statistics-based-password-cracking-rules-hashcat-d3adhob0)
		* [One Rule to Rule Them All - notsosecure(2017)](https://www.notsosecure.com/one-rule-to-rule-them-all/)
		* [rulesfinder](https://github.com/synacktiv/rulesfinder)
			* This tool finds efficient password mangling rules (for John the Ripper or Hashcat) for a given dictionary and a list of passwords.
	* **Tools**
		* [Hashtag](http://www.smeegesec.com/2013/11/hashtag-password-hash-identification.html)
			* Password hash identification tool written in python
		* [hcxtools](https://github.com/ZerBea/hcxtools)
			* Small set of tools to capture and convert packets from wlan devices (h = hash, c = capture, convert and calculate candidates, x = different hashtypes) for the use with latest hashcat or John the Ripper. The tools are 100% compatible to hashcat and John the Ripper and recommended by hashcat. This branch is pretty closely synced to hashcat git branch (that means: latest hcxtools matching on latest hashcat beta) and John the Ripper git branch ( "bleeding-jumbo").
		* [PACK (Password Analysis and Cracking Toolkit)](https://github.com/iphelix/pack)
			* PACK (Password Analysis and Cracking Toolkit) is a collection of utilities developed to aid in analysis of password lists in order to enhance password cracking through pattern detection of masks, rules, character-sets and other password characteristics. The toolkit generates valid input files for Hashcat family of password crackers.
		* [BarsWF](https://3.14.by/en/md5)
			* MD5 Cracker
		* [Cryptbreaker](https://github.com/Sy14r/Cryptbreaker)
			* Upload files and use AWS Spot Instances to crack passwords. Using cloud capabilities you can even prevent plaintext credentials from leaving the isolated cracking box ensuring that you get usable statistics on passwords while minimizing plaintext credential exposure.
		* [princeprocessor](https://github.com/hashcat/princeprocessor)
			* Standalone password candidate generator using the PRINCE algorithm
	* **Miscellaneous**
	* **Cisco**
		* [Cisco Password Cracking and Decrypting Guide - infosecmatter.com](https://www.infosecmatter.com/cisco-password-cracking-and-decrypting-guide/)
			* In this guide we will go through Cisco password types that can be found in Cisco IOS-based network devices. We will cover all common Cisco password types (0, 4, 5, 7, 8 and 9) and provide instructions on how to decrypt them or crack them using popular open-source password crackers such as John the Ripper or Hashcat.
	* **Windows**
		* **Articles/Papers/Talks/Writeups**
			* [Cracking NTLMv1 \w ESS/SSP - crack.sh](https://crack.sh/cracking-ntlmv1-w-ess-ssp/)
			* [LM, NTLM, Net-NTLMv2, oh my! A Pentester’s Guide to Windows Hashes- Peter Gombos](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4)
		* **Talks/Presentations/Videos**
		* **Tools**
			* [Rainbow Crackalack v1.2](https://github.com/jtesta/rainbowcrackalack)
				* This project produces open-source code to generate rainbow tables as well as use them to look up password hashes. While the current release only supports NTLM, future releases may support MD5, SHA-1, SHA-256, and possibly more. Both Linux and Windows are supported!
				* [Homepage](https://www.rainbowcrackalack.com/)
			* [ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi)
				* This tool modifies NTLMv1/NTLMv1-ESS/MSCHAPv2 hashes so they can be cracked with DES Mode 14000 in hashcat
* **CAPTCHA**
	* **Talks & Presentations**
		* [Releasing the CAPTCHA Cracken - Sean Brodie, Tinus Green](https://labs.f-secure.com/blog/releasing-the-captcha-cracken/)
	* **Tools**
		* [CAPTCHA22](https://github.com/FSecureLABS/captcha22)
			* CAPTCHA22 is a toolset for building, and training, CAPTCHA cracking models using neural networks. These models can then be used to crack CAPTCHAs with a high degree of accuracy. When used in conjunction with other scripts, CAPTCHA22 gives rise to attack automation; subverting the very control that aims to stop it.
* **Cracking Specific Application Passwords/Hashes**<a name="appt"></a>
	* **KeePass**<a name="keepass"></a>
		* [mod0keecrack](https://github.com/devio/mod0keecrack)
			* mod0keecrack is a simple tool to crack/bruteforce passwords of KeePass 2 databases. It implements a KeePass 2 Database file parser for .kdbx files, as well as decryption routines to verify if a supplied password is correct. mod0keecrack only handles the encrypted file format and is not able to parse the resulting plaintext database. The only purpose of mod0keecrack is the brute-forcing of a KeePass 2 database password.
	* **MS Office**<a name="msoffice"></a>
		* [crackxls2003 0.4](https://github.com/GavinSmith0123/crackxls2003)
			* This program may be used to break the encryption on Microsoft Excel and Microsoft Word file which have been encrypted using the RC4 method, which uses a 40-bit-long key. This was the default encryption method in Word and Excel 97/2000/2002/2003. This program will not work on files encrypted using Word or Excel 2007 or later, or for versions 95 or earlier. It will not work if a file was encrypted with a non-default method. Additionally, documents created with the Windows system locale set to France may use a different encryption method.
	* **NTLM**
		* [LM, NTLM, Net-NTLMv2, oh my! - Péter Gombos](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4)
		* [A 9-step recipe to crack a NTLMv2 Hash from a freshly acquired .pcap - kimvb3r](https://research.801labs.org/cracking-an-ntlmv2-hash/)
		* [How to Dump NTLM Hashes & Crack Windows Passwords - Tokyoneon](https://null-byte.wonderhowto.com/how-to/hacking-windows-10-dump-ntlm-hashes-crack-windows-passwords-0198268/)
			* [The NTLM Authentication Protocol and Security Support Provider - davenport.sourceforge](http://davenport.sourceforge.net/ntlm.html)
		* [Live off the Land and Crack the NTLMSSP Protocol](https://www.mike-gualtieri.com/posts/live-off-the-land-and-crack-the-ntlmssp-protocol)
			* Last month Bleeping Computer published an article about PKTMON.EXE, a little known utility in Windows 10 that provides the ability to sniff and monitor network traffic.  I quickly wondered if it would be feasible to use this utility, and other native tools within Windows, to capture NTLMv2 network authentication handshakes. TL;DR: Yes it is possible and I wrote a Python3 script called NTLMRawUnHide that can extract NTLMv2 password hashes from packet dumps of many formats!
		* [NTLMRawUnhide.py](https://github.com/mlgualtieri/NTLMRawUnHide)
			* NTLMRawUnhide.py is a Python3 script designed to parse network packet capture files and extract NTLMv2 hashes in a crackable format. The tool was developed to extract NTLMv2 hashes from files generated by native Windows binaries like NETSH.EXE and PKTMON.EXE without conversion.
	* **PDF**<a name="pdf"></a>
		* [PDFCrack](http://pdfcrack.sourceforge.net/)
			* PDFCrack is a GNU/Linux (other POSIX-compatible systems should work too) tool for recovering passwords and content from PDF-files. It is small, command line driven without external dependencies. The application is Open Source (GPL).
	* **SAP**
		* [SAP password hacking Part I: SAP BCODE hash hacking - saptechnicalguru.com](https://www.saptechnicalguru.com/sap-password-hacking-bcode/)
			* This blog series will explain the process of hacking SAP password hashes: also know as SAP password hacking. The process of hacking will be explained and appropriate countermeasures will be explained.
			* [SAP password hash hacking Part II: SAP PASSCODE hash hacking](https://www.saptechnicalguru.com/sap-password-hacking-passcode/)
			* [SAP password hash hacking Part III: SAP PWDSALTEDHASH hash hacking](https://www.saptechnicalguru.com/sap-password-hash-hacking-pwdsaltedhash/)
			* [SAP password hash hacking Part IV: rule based attack](https://www.saptechnicalguru.com/sap-password-hash-hacking-rulebased-attack/)
	* **Wordpress**
		* [Cracking WordPress Passwords with Hashcat - Jonas Lejon(2019)](https://blog.wpsec.com/cracking-wordpress-passwords-with-hashcat/)
	* **WPA2**
		* [WPA2 Cracking Using HashCat - rootsh3ll](https://rootsh3ll.com/wpa2-cracking/)	
	* **ZIP Archives**<a name="zip"></a>
		* [Cracking ZIP files with fcrackzip - Allan Feid(2009)](https://allanfeid.com/content/cracking-zip-files-fcrackzip)
		* [fcrackzip](https://github.com/hyc/fcrackzip)
			* A braindead program for cracking encrypted ZIP archives. Forked from http://oldhome.schmorp.de/marc/fcrackzip.html
* **John the Ripper**<a name="jtr"></a>
	* **101**
		* [John the Ripper benchmarks - openwall](https://openwall.info/wiki/john/benchmarks)
		* [John The Ripper Hash Formats - pentestmonkey](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)
		* [JTR Docs](https://www.openwall.com/john/doc/)
	* **Rules**
		* [KoreLogic Custom Rules(2010)](https://contest-2010.korelogic.com/rules.html)
			* "KoreLogic used a variety of custom rules to generate the passwords. These _same_ rules can be used to crack passwords in corporate environments. These rules were originally created because the default ruleset for John the Ripper fails to crack passwords with more complex patterns used in corporate environments."
* **OCL/Hashcat** <a name="hashcat"></a>
	* **101**
		* [OCL hashcat](http://n0where.net/introduction-break-that-hash/)
			* It’s OCL hashcat
		* [OCL hashcat wiki](http://hashcat.net/wiki/)
			* Its the Wiki
		* [Hashcat FAQ](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions)
	* **Articles/Blogposts/Writeups**
		* [Password Analysis To Hashcat (PATH) script](https://tickorone.wordpress.com/2012/06/02/password-analysis-to-hashcat-path-script/)
		* [Advanced Password Guessing: Hashcat techniques for the last 20%](https://www.yumpu.com/en/document/read/33666366/advanced-password-guessing-hashcat)
	* **Automating Hashcat**<a name="hauto"></a>
		* [Hate_Crack](https://github.com/trustedsec/hate_crack)
			* A tool for automating cracking methodologies through Hashcat from the TrustedSec team. 
		* [HAT - Hashcat Automation Tool](https://github.com/sp00ks-git/hat)
			* An automated Hashcat tool for common wordlists and rules to speed up the process of cracking hashes during engagements. HAT is simply a wrapper for Hashcat (with a few extra features) - https://hashcat.net, however I take no credit for that superb tool.
	* **Hashcat Attacks**<a name="hattack"></a>
		* **Types of**
			* [Mask atttack](http://hashcat.net/wiki/doku.php?id=mask_attack)
				* Try all combinations from a given keyspace just like in Brute-Force attack, but more specific. 
			* [Combinator attack](http://hashcat.net/wiki/doku.php?id=combinator_attack)
				* Each word of a dictionary is appended to each word in a dictionary. 
			* [Dictionary attack](http://hashcat.net/wiki/doku.php?id=dictionary_attack)
				* The dictionary attack is a very simple attack mode. It is also known as a “Wordlist attack”. 
			* [Fingerprint Attack](http://hashcat.net/wiki/doku.php?id=fingerprint_attack)
				* The Fingerprint attack is a combination of the results of the expander with a combination engine. It is an automatically generated attack on pattern that works fine on GPGPU. 
			* [Hybrid attack](http://hashcat.net/wiki/doku.php?id=hybrid_attack)
				* Basically, the hybrid attack is just a Combinator attack. One side is simply a dictionary, the other is the result of a Brute-Force attack. In other words, the full Brute-Force keyspace is either appended or prepended to each of the words from the dictionary. That's why it's called “hybrid”. 
			* [Mask attack](http://hashcat.net/wiki/doku.php?id=mask_attack)
				* Try all combinations from a given keyspace just like in Brute-Force attack, but more specific. 
			* [Permutation attack[(http://hashcat.net/wiki/doku.php?id=permutation_attack)
				* Each word in a dictionary generates all permutations of itself. 
			* [Rule Based attack](http://hashcat.net/wiki/doku.php?id=rule_based_attack)
				* The rule-based attack is one of the most complicated of all the attack modes. The reason for this is very simple. The rule-based attack is like a programming language designed for password candidate generation. It has functions to modify, cut or extend words and has conditional operators to skip some, etc. That makes it the most flexible, accurate and efficient attack. 
			* [Table Lookup attack](http://hashcat.net/wiki/doku.php?id=table_lookup_attack)
				* With each word in our dictionary, it automatically generates masks as in a batch of Mask attack. 
			* [Toggle-Case attack](http://hashcat.net/wiki/doku.php?id=toggle_case_attack)
				* For each word in a dictionary, all possible combinations of upper- and lower-case variants are generated. 
			* [Purple Rain Attack: Password Cracking With Random Generation - netmux](https://www.netmux.com/blog/purple-rain-attack)
			* [OCLHashcat Hash Examples + hash code](https://hashcat.net/wiki/doku.php?id=example_hashes)
		* **Performing**
			* [How To Perform a Combinator Attack Using Hashcat - William Hurer-Mackay(2016)](https://www.4armed.com/blog/hashcat-combinator-attack/#)
			* [How to Perform a Mask Attack Using hashcat - William Hurer-Mackay(2016)](https://www.4armed.com/blog/perform-mask-attack-hashcat/)
			* [Hashcat Mask Attack - Sevenlayers](https://www.sevenlayers.com/index.php/287-hashcat-mask-attack)
			* [How To Perform A Rule-Based Attack Using Hashcat - William Hurer-Mackay(2016)](https://www.4armed.com/blog/hashcat-rule-based-attack/)
			* [Performing Rule Based Attack Using Hashcat - Shubhankar Singh](https://www.armourinfosec.com/performing-rule-based-attack-using-hashcat/)
			* [Run All Rules for Hashcat - mubix(2020)](https://malicious.link/post/2020/run-all-rules-hashcat/)
				* "This is just a quick script to demonstrate using PowerShell to run all the rules against a specific hash (or hash file), starting from the smallest file (usually the simplest rules)"
			* [Automated Password Cracking: Use oclHashcat To Launch A Fingerprint Attack](https://www.question-defense.com/2010/08/15/automated-password-cracking-use-oclhashcat-to-launch-a-fingerprint-attack)
	* **Hashcat Masks**
		* [Corporate_Masks](https://github.com/golem445/Corporate_Masks)
			*  8-14 character Hashcat masks based on analysis of 1.5 million NTLM hashes cracked while pentesting 
	* **Hashcat Rules**<a name="hrules"></a>
		* **101**
			* [Rule Based Attack - Hashcat Wiki](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
			* [Hashcat Tutorial – Rule Writing - LaconicWolf](https://laconicwolf.com/2019/03/29/hashcat-tutorial-rule-writing/)
		* **Articles/Blogposts/Writeups**
			* [How To Perform A Rule-Based Attack Using Hashcat - William Hurer-Mackay(2016)](https://www.4armed.com/blog/hashcat-rule-based-attack/)
			* [An Explanation of Hashcat Rules - Kaotic Creations(2011)](https://kaoticcreations.blogspot.com/2011/09/explanation-of-hashcat-rules.html)
			* [RevsUp Lab: Hashcat 06](https://www.cs.csub.edu/~melissa/revs-up/sum2018/polo/hashcat06.html)
		* Rulesets
			* [nsa-rules](https://github.com/NSAKEY/nsa-rules)
				* Password cracking rules and masks for hashcat that I generated from cracked passwords.
			* [Hob0Rules](https://github.com/praetorian-code/Hob0Rules)
				* Password cracking rules for Hashcat based on statistics and industry patterns.
			* [password_cracking_rule - notsosecure](https://github.com/NotSoSecure/password_cracking_rules)
				* [One Rule to Rule Them All - ](https://www.notsosecure.com/one-rule-to-rule-them-all/)
	* **Hashcat-related Tools**<a name="htools"></a>
		* [CrackerJack](https://github.com/ctxis/crackerjack)
			* Web Interface for Hashcat by Context Information Security
* **Tools** <a name="generalt"></a>
	* **General**
	* **Distributed Hash-Cracking**
		* [Hashtopolis](https://github.com/s3inlc/hashtopolis)
			* Hashtopolis is a multi-platform client-server tool for distributing hashcat tasks to multiple computers. The main goals for Hashtopolis's development are portability, robustness, multi-user support, and multiple groups management.
			* [Automating Hashtopolis - EvilMog(NolaCon2019)](https://www.irongeek.com/i.php?page=videos/nolacon2019/nolacon-2019-c-04-automating-hashtopolis-evil-mog)
		* [Cracklord](https://github.com/jmmcatee/cracklord)
			* CrackLord is a system designed to provide a scalable, pluggable, and distributed system for both password cracking as well as any other jobs needing lots of computing resources. Better said, CrackLord is a way to load balance the resources, such as CPU, GPU, Network, etc. from multiple hardware systems into a single queueing service across two primary services: the Resource and Queue. It won't make these tasks faster, but it will make it easier to manage them.
		* [NPK](https://github.com/Coalfire-Research/npk)
			* NPK is a distributed hash-cracking platform built entirely of serverless components in AWS including Cognito, DynamoDB, and S3. It was designed for easy deployment and the intuitive UI brings high-power hash-cracking to everyone.
			* [High-Power Hash Cracking with NPK - Brad Woodward(2019)](https://www.coalfire.com/The-Coalfire-Blog/March-2019/High-Power-Hash-Cracking-with-NPK)
	* [Firefox password cracker](https://github.com/pradeep1288/ffpasscracker)
	* [Dagon](https://github.com/Ekultek/Dagon)
		* Named after the prince of Hell, Dagon (day-gone) is an advanced hash cracking and manipulation system, capable of bruteforcing multiple hash types, creating bruteforce dictionaries, automatic hashing algorithm verification, random salt generation from Unicode to ASCII, and much more.
	* [Gladius](https://github.com/praetorian-inc/gladius)
		* Automated Responder/secretsdump.py cracking. Gladius provides an automated method for cracking credentials from various sources during an engagement. We currently crack hashes from Responder, secretsdump.py, and smart_hashdump.
* **Papers** <a name="papers"></a>
	* [Optimizing computation of Hash Algorithms as an attacker](https://hashcat.net/events/p13/js-ocohaaaa.pdf)
	* [Attacking NTLM with Precomputed Hashtables](http://uninformed.org/?v=all&a=13&t=sumry)
		* Breaking encrypted passwords has been of interest to hackers for a long time, and protecting them has always been one of the biggest security problems operating systems have faced, with Microsoft's Windows being no exception. Due to errors in the design of the password encryption scheme, especially in the LanMan(LM) scheme, Windows has a bad track in this field of information security. Especially in the last couple of years, where the outdated DES encryption algorithm that LanMan is based on faced more and more processing power in the average household, combined with ever increasing harddisk size, made it crystal clear that LanMan nowadays is not just outdated, but even antiquated. 
	* [Website Dedicated to Password Research](http://www.passwordresearch.com/papers/pubindex.html)
		* A core objective of the Password Research Institute is to improve the industry awareness of existing authentication research. Many valuable solutions for the problems associated with authentication have gone unnoticed by the people interested in, or responsible for, authentication security. This project will compile and share a comprehensive, but moderated, index of password and authentication related research papers. We aim to share the details of useful papers, provide access to the papers, and encourage collaboration between authors and other security professionals.
	* [When Privacy meets Security: Leveraging personal information for password cracking - M. Dürmuth,A. ChaabaneD. Perito,C. Castelluccia](https://arxiv.org/abs/1304.6584)
		* Passwords are widely used for user authentication and, de- spite their weaknesses, will likely remain in use in the fore seeable future. Human-generated passwords typically have a rich structure , which makes them susceptible to guessing attacks. In this paper, we stud y the effectiveness of guessing attacks based on Markov models. Our contrib utions are two-fold. First, we propose a novel password cracker based o n Markov models, which builds upon and extends ideas used by Narayana n and Shmatikov (CCS 2005). In extensive experiments we show that it can crack up to 69% of passwords at 10 billion guesses, more than a ll probabilistic password crackers we compared against. Second, we systematically analyze the idea that additional personal informatio n about a user helps in speeding up password guessing. We find that, on avera ge and by carefully choosing parameters, we can guess up to 5% more pas swords, especially when the number of attempts is low. Furthermore, we show that the gain can go up to 30% for passwords that are actually b ased on personal attributes. These passwords are clearly weaker an d should be avoided. Our cracker could be used by an organization to detect and reject them. To the best of our knowledge, we are the first to syst ematically study the relationship between chosen passwords and users’ personal in- formation. We test and validate our results over a wide colle ction of leaked password databases.
	* [PassGAN](https://github.com/brannondorsey/PassGAN)
		* This repository contains code for the [PassGAN: A Deep Learning Approach for Password Guessing paper](https://arxiv.org/abs/1709.00440). The model from PassGAN is taken from [Improved Training of Wasserstein GANs](https://arxiv.org/abs/1704.00028) and it is assumed that the authors of PassGAN used the [improved_wgan_training tensorflow](https://github.com/igul222/improved_wgan_training) implementation in their work. For this reason, I have modified that reference implementation in this repository to make it easy to train (train.py) and sample (sample.py) from. 
	* [Mnemonic Password Formulas](http://uninformed.org/?v=all&a=33&t=sumry)
		*  The current information technology landscape is cluttered with a large number of information systems that each have their own individual authentication schemes. Even with single sign-on and multi-system authentication methods, systems within disparate management domains are likely to be utilized by users of various levels of involvement within the landscape as a whole. Due to this complexity and the abundance of authentication requirements, many users are required to manage numerous credentials across various systems. This has given rise to many different insecurities relating to the selection and management of passwords. This paper details a subset of issues facing users and managers of authentication systems involving passwords, discusses current approaches to mitigating those issues, and finally introduces a new method for password management and recalls termed Mnemonic Password Formulas. 




