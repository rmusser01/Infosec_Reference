# Phishing

----------------------------------
## Table of Contents
- [General](#general)
	- [Articles/Blogposts](#articles)
	- [Papers](#papers)
	- [Talks/Presentations](#talks)
	- [Writeups](#writeups)
	- [Metrics](#metrics)
	- [Writeups]
	- [Phishing Pretexts](#pretxt)
	- [Vishing](#vishing)
	- [Homoglyphs/Punicode/Unicode Funniness](#puni)
- [Documentation](#documentation)
	- [Dynamic Data Exchange(DDE)](#ddde)
	- [DomainKeys Identified Mail](#ddkim)
	- [Domain Message Authentication, Reporting, and Conformance - DMARC](#ddmarc)
	- [Factur-X](#dfx)
	- [Html Application (HTA)](#hata)	
	- [Object Linking and Embedding](#dole)
	- [Office Open XML Format](#doxml)
	- [Office URI Schemes](#douri)
	- [PowerPoint Mouseover](#ppm)
	- [Protected View](#dpv)	
	- [ScriptControl](#dsc)
	- [Sender Policy Framework - SPF](#dspf)
	- [Subdocument Reference](#sdf)
	- [Transport Neutral Encapsulation Format](#dsr)
	- [Visual Basic for Applications (VBA)](#dvba)
	- [XLL](#dxll)
- [Phishing Frameworks](#framework)
	- [All-In-Ones](#aio)
	- [Built for 2FA](#2fa)
	- [Social Media](#sm)
	- [Specific Purpose](#specific)
- [Payloads](#payloads)
	- [Delivery](#delivery)
	- [CHM File](#chm)
	- [ClickOnce](#clickonce)
	- [DotNetToJScript](#dotnetjs)
	- [GadgetToJScript](#gtjs)
	- [HTA](#htap)
	- [OLE+LNK / Embedded Objects](#olelnk)
	- [PDF](#pdf)
	- [.SettingContent-ms](#scms)
	- [UNC](#unc)	
- [Tools](#tools)
- [Microsoft Outlook/Exchange Stuff/Office 365](#msoutlook)
- [Microsoft Office](#msoffice)
	- [General](#ms)
	- [DDE](#gdde)
	- [DLL](#gdll)
	- [Embeds](#gembed)
	- [Exploits](#gexploit)
	- [Excel](#excel)
	- [Excel+DDE+PowerQuery](#gpq)
	- [Field Codes](#gfield)
	- [InfoPath](#ginfo)
	- [LoL](#glol)
	- [Macros](#macros)
		- [101](#m101)
		- [Articles/Blogposts/Writeups](#mart)
		- [Activex](#max)
		- [Execution](#mex)
		- [Evasion](#mev)
		- [Excel Specific / 4.0 Macros](#excel)
		- [Keying](#keying)
		- [macOS Specific](#mmosx)
		- [Remote Template Injection](#mrti)
		- [VBA Stomping](#mstomp)
		- [Tools](#mtools)
	- [OLE](#ole)
	- [Online Video in MS Word](#mov)
	-[PowerPoint MouseOver](#ppm)
	- [Protected View](#mpv)
	- [subdDoc](#msubdoc)
	- [Temporary File Drop](#tnf)
	- [Word Fields](#mwf)
- [Setting up a Server](#settingup)
- [Local Phishing](#localphish)
------------------------------------------------------

To Do:
	* Other payload types
	* File smuggling
	* Wifi
	* Unicode
	* RTF
	* OpenOffice stuff



------------------
### <a name="general">General</a>
* **General**
	* [Phishing - wikipedia](http://www.en.wikipedia.org/wiki/Phishing):
		* Phishing is the attempt to acquire sensitive information such as usernames, passwords, and credit card details (and sometimes, indirectly, money) by masquerading as a trustworthy entity in an electronic communication.
	* [Phishing with Maldocs](https://www.n00py.io/2017/04/phishing-with-maldocs/)
	* [Post exploitation trick - Phish users for creds on domains, from their own box](https://enigma0x3.wordpress.com/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
	* [iOS Privacy: steal.password - Easily get the user's Apple ID password, just by asking](https://krausefx.com/blog/ios-privacy-stealpassword-easily-get-the-users-apple-id-password-just-by-asking)
	* [Phishing for Funds: Understanding Business Email Compromise - Keith Turpin - BH Asia2017](https://www.youtube.com/watch?v=_gk4i33lriY&list=PLH15HpR5qRsWx4qw9ZlgmisHOcKG4ZcRS&index=11)
		* Business Email Compromise (aka CEO fraud) is a rapidly expanding cybercrime in which reported cases jumped 1300% from 2015 to 2016. This financial fraud scheme can target any market segment or organization regardless of size. Thousands of organizations from more than 100 countries have reported losses. The reasons for this surge is simple - it makes money. 
		* [Slides](https://www.blackhat.com/docs/asia-17/materials/asia-17-Turpin-Phishing-For-Funds-Understanding-Business-Email-Compromise.pdf)
	* [Red Team Techniques: Gaining access on an external engagement through spear-phishing - Josh Kamdjou(2019)](https://blog.sublimesecurity.com/red-team-techniques-gaining-access-on-an-external-engagement-through-spear-phishing/)
	* [Blocking Spam and Phishing on a Budget - ?(2019)](https://blog.sublimesecurity.com/blocking-spam-and-phishing-on-a-budget/)
* **Articles/Blogposts**<a name="articles"></a>
	* [Best Time to send email](https://coschedule.com/blog/best-time-to-send-email/)
	* [Top 10 Email Subjects for Company Phishing Attacks](http://www.pandasecurity.com/mediacenter/security/top-10-email-subjects-phishing-attacks/)
	* [Some Tips for Legitimate Senders to Avoid False Positives - Apache SpamAssassin](https://wiki.apache.org/spamassassin/AvoidingFpsForSenders)
	* [Email Delivery: What Pen Testers Should Know - cs(2013)](https://blog.cobaltstrike.com/2013/10/03/email-delivery-what-pen-testers-should-know/)
	* [What are the go-to phishing technique or exploit? - cs(2014)](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
	* [Introduction: Bypassing Email Security - Hector Monsegur](https://rhinosecuritylabs.com/social-engineering/bypassing-email-security-url-scanning/)
	* [Phishing, Lateral Movement, SCADA, OH MY!](https://web.archive.org/web/20160408193653/http://www.idzer0.com/?p=210)
	* [Phishing with Empire - Enigma0x3](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
	* [Phishing for Access - rvrsh3ll's blog](http://www.rvrsh3ll.net/blog/phishing/phishing-for-access/)
	* [Cross-Site Phishing](http://blog.obscuritylabs.com/merging-web-apps-and-red-teams/)
	* [Email Notification on shell connectback MSF Plugin](https://hansesecure.de/howto-msf-email/)
		* [Code](https://github.com/HanseSecure/metasploit-modules)
	* [How to Bypass Safe Link/Attachment Processing of ATP - support.knowbe4.com](https://support.knowbe4.com/hc/en-us/articles/115004326408-How-to-Bypass-Safe-Link-Attachment-Processing-of-ATP)
	* [These Aren't the Phish You're Looking For - Curtiz Brazzell(2020)](https://medium.com/@curtbraz/these-arent-the-phish-you-re-looking-for-7374c3986af5)
		* "My research took me down a long but enjoyable adventure over the last month and I learned a great deal about how sites end up on blacklists, who shares information behind the scenes, and ultimately, how to completely bypass ending up on a blacklist altogether."
	* [Phishing Against Bromium - Steve Borosh(2017)](https://medium.com/rvrsh3ll/phishing-against-bromium-cc2486397763)
	* [Lessons learned on written social engineering attacks - DiabloHorn(2020)](https://diablohorn.com/2020/03/04/lessons-learned-on-written-social-engineering-attacks/)
	* [Phishing Sites with Netlify - HunnicCyber](https://blog.hunniccyber.com/phishing-with-netlify/)
	* [Quick exploration of the use of .chm and .hta files in APT phishing campaigns - jh904(2020)](https://testofpen.wordpress.com/2020/04/02/quick-exploration-of-the-use-of-chm-and-hta-files-in-apt-phishing-campaigns/)
	* [What are email reply-chain attacks & How can you stay safe?](https://www.sentinelone.com/blog/email-reply-chain-attacks-what-are-they-how-can-you-stay-safe/)
	* [The totally legitimate guide to spearphishing and whaling - Andrew Long(2020)](https://medium.com/@c.andrewlong/the-totally-legitimate-guide-to-spearphishing-and-whaling-81729b94d713)
	* [Hiding in Plain Sight - Obfuscation Techniques in Phishing Attacks - ProofPoint](https://www.proofpoint.com/sites/default/files/proofpoint-obfuscation-techniques-phishing-attacks-threat-insight-en-v1.pdf)
	* [Code Obfuscation `10**2+(2*a+3)%2` - Gaetan Ferry(JSecIn 2018)](https://www.synacktiv.com/ressources/jsecin_code_obfu.pdf)
	* [Spear-phishing campaign tricks users to transfer money (TTPs & IOC) - readteam.pl(2020)](https://blog.redteam.pl/2020/06/spear-phishing-muhammad-appleseed1-mail-ru.html)
	* [Low-tech EDR bypass - dumpco.re(2020)](http://dumpco.re/blog/low-tech-edr-bypass)
		* "TL;DR: I designed a piece of super simple malware/implant that evaded everything that I threw against it."
	* **Abusing 3rd Party Service Providers**<a name="3rdparty"></a>
		* [Abusing Misconfigured Cloud Email Providers for Enhanced Phishing Campaigns - und3rf10w.blogspot](https://und3rf10w.blogspot.com/2017/07/abusing-misconfigured-cloud-email.html)
		* [Next Gen Phishing - Leveraging Azure Information Protection - Oddvar Moe](https://www.trustedsec.com/2019/04/next-gen-phishing-leveraging-azure-information-protection/)
			* In this blog post, I will go over how to use Azure Information Protection (AIP) to improve phishing campaigns from the perspective of an attacker. The idea came during an engagement where I was having trouble getting phishing emails into usersâ€™ inboxes without being caught by a sandbox on the way. During this engagement, it struck me like a bolt of lightning that I could use AIP (also known as Rights Management Service) to protect the attachments and even the email so that only the designated recipient could open it. That way, it would not matter if the sandbox got the file since it will not be possible for it to read the contents.
		* [Using SharePoint as a Phishing Platform - David Cash(2020)](https://research.nccgroup.com/2020/05/14/using-sharepoint-as-a-phishing-platform/)
	* **Campaign Writeups**
		* [Guccifer Rising? Months-Long Phishing Campaign on ProtonMail Targets Dozens of Russia-Focused Journalists and NGOs - Bellingcat](https://www.bellingcat.com/news/uk-and-europe/2019/08/10/guccifer-rising-months-long-phishing-campaign-on-protonmail-targets-dozens-of-russia-focused-journalists-and-ngos/)
* **Papers**<a name="papers"></a>
	* [Tab Napping - Phishing](http://www.exploit-db.com/papers/13950/)
	* [Skeleton in the closet. MS Office vulnerability you didnÃ¢â‚¬â„¢t know about](https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about)
		* Microsoft Equation Editor Exploit writeup
	* [MetaPhish Paper](https://www.blackhat.com/presentations/bh-usa-09/SMITH_VAL/BHUSA09-Smith-MetaPhish-PAPER.pdf)
	* [MetaPhish - Defcon17](https://www.defcon.org/images/defcon-17/dc-17-presentations/Valsmith/defcon-17-valsmith-metaphish-wp.pdf)
* **Talks & Presentations**<a name="talks"></a>
	* [Phishing for Funds: Understanding Business Email Compromise - Keith Turpin - BHA17](https://www.youtube.com/watch?v=_gk4i33lriY&list=PLH15HpR5qRsWx4qw9ZlgmisHOcKG4ZcRS&index=11)
		* Business Email Compromise (aka CEO fraud) is a rapidly expanding cybercrime in which reported cases jumped 1300% from 2015 to 2016. This financial fraud scheme can target any market segment or organization regardless of size. Thousands of organizations from more than 100 countries have reported losses. The reasons for this surge is simple - it makes money.
	* [Casting with the Pros Tips and Tricks - Nathan Sweaney(DEFCON27 RedTeam Village)](https://www.youtube.com/watch?v=tarNIQwo4Es&list=PL9fPq3eQfaaChXmQKpp1YO19Gw-6SxBDs&index=5)
		* [Slides](https://tiny.si/slides/2020_WWHF_CastingWithThePros.pdf)
		* Phishing seems easy enough, but getting successful results can be difficult. In this talk we'll walk through practical tips for getting better responses. We'll talk about target selection, ruse development, technology deployment, and suggestions for working with clients to maximize the value of the assessment.
	* [Hacking Corporate Email Systems - Nate Power(BSides Columbus 2016)](https://www.youtube.com/watch?v=mJ172K1dxoM)
	* [Purple Haze: The SpearPhishing Experience - Jesse Nebling(Toorcon21)](https://talks.toorcon.net/media/Purple_Haze__The_SpearPhishing_Experience.pdf)
	* [Three Years of Phishing - What We've Learned - Mike Morabito](http://www.irongeek.com/i.php?page=videos/centralohioinfosec2015/tech105-three-years-of-phishing-what-weve-learned-mike-morabito)
		* Cardinal Health has been aggressively testing and training users to recognize and avoid phishing emails. This presentation covers 3 years of lessons learned from over 18,000 employees tested, 150,000 individual phishes sent, 5 complaints, thousands of positive comments, and a dozen happy executives. Learn from actual phishing templates what works well, doesn,t work at all, and why? See efficient templates for education and reporting results.
	* [Ichthyology: Phishing as a Science - BH USA 2017](https://www.youtube.com/watch?v=Z20XNp-luNA&app=desktop)
	* [Modern Evasion Techniques Jason Lang - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)
		* As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.
	* [Phishing Like The Pros - Luis Santana - Derbycon 2013](https://www.irongeek.com/i.php?page=videos/derbycon3/1305-phishing-like-the-pros-luis-connection-santana)
		* This talk will discuss phishing techniques used by professionals during phishing campaigns and introduce PhishPoll, a PHP-based phishing framework for creating, managing, and tracking phishing campaigns.
	* [MetaPhish - Valsmith, Colin Ames, and David Kerb - DEF CON 17](https://www.youtube.com/watch?v=3DYOMkkTK4A)
	* [Phishing for Funds: Understanding Business Email Compromise - Keith Turpin - BH Asia2017](https://www.youtube.com/watch?v=_gk4i33lriY&list=PLH15HpR5qRsWx4qw9ZlgmisHOcKG4ZcRS&index=11)
		* Business Email Compromise (aka CEO fraud) is a rapidly expanding cybercrime in which reported cases jumped 1300% from 2015 to 2016. This financial fraud scheme can target any market segment or organization regardless of size. Thousands of organizations from more than 100 countries have reported losses. The reasons for this surge is simple - it makes money. 
	* [Defeating The Latest Advances in Script Obfuscation - Mark Mager(Derbycon2016)](https://www.irongeek.com/i.php?page=videos/derbycon6/109-defeating-the-latest-advances-in-script-obfuscation-mark-mager)
		* This talk will cover some of the most recently seen advanced obfuscation techniques employed by APTs, exploit kits, and other malware authors along with proven methods for circumventing and decoding these techniques. I will then apply these methods to guide the audience through the deobfuscation of a fully obfuscated script. Audience members will walk away with a solid understanding of how common obfuscation techniques are employed in scripting languages along with how they can be defeated.
	* [Phishing 2020 – Part 1 - hacktheplanet.io](https://hackplanet.io/aiovg_videos/phishing-2020-part-1-2020-01-30/)
		* [Part 2](https://hackplanet.io/aiovg_videos/phishing-2020-part-2-2020-02-07/)
		* [Part 3](https://hackplanet.io/aiovg_videos/phishing-2020-part-3-2020-02-14/)
	* [You've Got Pwned: Exploiting E-Mail Systems by @securinti #NahamCon2020](https://www.youtube.com/watch?v=cThFNXrBYQU&list=PLKAaMVNxvLmAD0ZVUJ2IGFFC0APFZ5gzy&index=3)
* **Writeups**<a name="writeups"></a>
	* [How do I phish? Advanced Email Phishing Tactics - Pentest Geek](https://www.pentestgeek.com/2013/01/30/how-do-i-phish-advanced-email-phishing-tactics/)
	* [Real World Phishing Techniques - Honeynet Project](http://www.honeynet.org/book/export/html/89)
	* [Phishing with Maldocs - n00py](https://www.n00py.io/2017/04/phishing-with-maldocs/)
	* [Tabnabbing - An art of phishing - securelayer7](http://blog.securelayer7.net/tabnabbing-art-phishing/)
	* [Add-In Opportunities for Office Persistence](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)
		* This post will explore various opportunities for gaining persistence through native Microsoft Office functionality.  It was inspired by Kostas Lintovois's similar work which identified ways to persist in transient Virtual Desktop Infrastructure (VDI) environments through adding a VBA backdoor to Office template files 
	* [One Template To Rule 'Em All](https://labs.mwrinfosecurity.com/publications/one-template-to-rule-em-all/)
		* This presentation discussed how Office security settings and templates can be abused to gain persistence in VDI implementations where traditional techniques relying on the file system or the Registry are not applicable. Additionally, it was described how the introduction of application control and anti-exploitation technologies may affect code execution in locked down environments and how these controls can be circumvented through the use of VBA.
	* [Spear Phishing 101 - inspired-sec.com](https://blog.inspired-sec.com/archive/2017/05/07/Phishing.html)
	* [There is a shell in your lunch-box by Rotimi Akinyele](https://hakin9.org/shell-lunch-box-rotimi-akinyele/)
	* [Advanced USB key phishing: Bypass airgap, drop, pwn using macro_pack - Emeric Nasi](http://blog.sevagas.com/?Advanced-USB-key-phishing)
	* [Red Team Attack Operation RT-011 - Phishing - Fake Laptop Upgrade - Gitlab(2020)](https://gitlab.com/gitlab-com/gl-security/gl-redteam/red-team-tech-notes/-/tree/master/RT-011%20-%20Phishing%20Campaign)
	* [Phish or Fox? A Penetration Testing Case Study From IBM X-Force Red - Dimitry Snezhkov](https://securityintelligence.com/phish-or-fox-a-penetration-testing-case-study-from-ibm-x-force-red/)
* **Phishing Metrics**<a name="metrics"></a>
	* **Articles/Blogposts**
		* [Internal Phishing Exercise Difficulty Scoring Tool - Cedric Owens(2018)](https://medium.com/red-teaming-with-a-blue-team-mentaility/internal-phishing-exercise-difficulty-scoring-e5a0979116d9)
		* [Introducing the Phishing Difficulty Calculator: How Hard Are Your Phishing Tests? - Masha Sedova(2018)](https://elevatesecurity.com/blog/introducing-the-phishing-difficulty-calculator-how-hard-are-your-phishing-tests/)
		* [37+ Stunningly Scary Phishing Statistics – An Ever-Growing Threat - hostingtribunal.com(2020)](https://hostingtribunal.com/blog/phishing-statistics/)
	* **Talks & Presentations**
	* **Tools**
		* [PhishDifficultyScorer](https://github.com/cedowens/PhishDifficultyScorer)
			* python3 script that rates the difficulty of a given phishing exercise.
* **Phishing Pre-texts**<a name="pretxt"></a>
	* **Articles/Blogposts**
		* [This Phish Uses DocuSign to Slip Past Symantec Gateway and Target Email Credentials - Tej Tulachan(2019)](https://cofense.com/phish-uses-docusign-slip-past-symantec-gateway-target-email-credentials/)
		* [9 Things I’ve Learned Writing Phishing Emails - Craig Hays(2019)](https://craighays.com/9-things-ive-learned-writing-phishing-emails/)
	* **Talks & Presentations**
		* [Phishy Little Liars - Pretexts That Kill (Alethe Denis(BSidesSF2020)](https://www.youtube.com/watch?v=JFAuHEOc77M&list=PLbZzXF2qC3RvlcHIxrqrsN1XhwHX8SQ-g)
			* The 'IT Guy' is the Nigerian Prince of Pretexts. As bad actors begin to use more specialized pretexts, so too should Pentesters use more specialized, custom pretexts during assessments. Learn to make custom pretexts that fly under the radar and wonâ€™t raise any red flags using target specific data.
		* [Phishing Pretexts](https://github.com/L4bF0x/PhishingPretexts)
			* A library of pretexts to use on offensive phishing engagements. Orginially presented at Layer8 by @L4bF0x and @RizzyRong.
			* [Video Presentation](https://www.youtube.com/watch?v=D21E_2sXqmo)
			* [Slides](https://goo.gl/U6qiiy)
	* **Tools**
		* [RealBusinessmen](http://realbusinessmen.com/)
			* All Business, All the Time.
* **Vishing**<a name="vishing"></a>
	* **Articles/Blogposts**
	* **Talks & Presentations**
		* [Vishing, Not just for Extroverts! - James Morris(BSidesAugust2019)](https://www.youtube.com/watch?v=42svpksXCb0&list=PLEJJRQNh3v_PF6cecq0ES2w25JtoG631g&index=27&t=0s)
	* **Tools**
* **Other**
	* [EmailAddressMangler](https://github.com/dafthack/EmailAddressMangler)
		* This module mangles two lists of names together to generate a list of potential email addresses or usernames. It can also be used to simply combine a list of full names in the format (firstname lastname) into either email addresses or usernames.
* **Homoglyphs/Punicode/Unicode**<a name="puni"></a>
	* **101**
		* [IDN homograph attack - Wikipedia](https://en.wikipedia.org/wiki/IDN_homograph_attack)
			* "The internationalized domain name (IDN) homograph attack is a way a malicious party may deceive computer users about what remote system they are communicating with, by exploiting the fact that many different characters look alike (i.e., they are homographs, hence the term for the attack, although technically homoglyph is the more accurate term for different characters that look alike). For example, a regular user of example.com may be lured to click a link where the Latin character "a" is replaced with the Cyrillic character "а"."
	* **Articles/Blogposts**
		* [Olc: Ruin someone’s day with homoglyphs - Teamwork Engineering]](https://engineroom.teamwork.com/olc-ruin-someones-day-with-homoglyphs-b14e9a1a05a4?gi=81bb0f02b356)
		* [Out of Character: Use of Punycode and Homoglyph Attacks to Obfuscate URLs for Phishing - Adrian Crenshaw()](https://www.irongeek.com/i.php?page=security/out-of-character-use-of-punycode-and-homoglyph-attacks-to-obfuscate-urls-for-phishing)
		* [Domain hacks with unusual Unicode characters - @edent(2018)](https://shkspr.mobi/blog/2018/11/domain-hacks-with-unusual-unicode-characters/)
		* [É¢oogle.news is not google.news: POC For Google Phishing with SSL - Avi Lumelsky(2020)](https://medium.com/@avi_59283/poc-for-google-phishing-in-10-minutes-%C9%A2oogletranslate-com-dcd0d2c32d91)
		* [Out of character: Homograph attacks explained  - Jovi Umawing(2018)](https://blog.malwarebytes.com/101/2017/10/out-of-character-homograph-attacks-explained/)
		* [Emoji to Zero-Day: Latin Homoglyphs in Domains and Subdomains - Matt Hamilton(2020)](https://www.soluble.ai/blog/public-disclosure-emoji-to-zero-day)
		* [Homoglyph attack prevention with OCR. - Aaron (Ari) Bornstein(2019)](https://towardsdatascience.com/homoglyph-attack-prevention-with-ocr-a6741ee7c9cd?gi=e0f9221f2806)
	* **Tools**
		* [Homoglyph Attack Generator - Adrian Crenshaw](https://www.irongeek.com/homoglyph-attack-generator.php)
		* [homoglyph](https://github.com/codebox/homoglyph)
			*  A big list of homoglyphs and some code to detect them 
		* [olc](https://github.com/adam-lynch/olc)
			* Ruins days by replacing characters in files with a homograph / homoglyph (like substituting semi-colons with the Greek question mark). "Olc" is the Irish word for "bad".













----------
### <a name="documentation"> Documentation
* [BetterSolutions.com - Microsoft Office Expertise and Automation for End Users](https://bettersolutions.com/index.htm)
* **Dynamic Data Exchange(DDE)**<a name="ddde"></a>
	* [About Dynamic Data Exchange - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dataxchg/about-dynamic-data-exchange)
	* [Dynamic Data Exchange - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dataxchg/dynamic-data-exchange)
		* This section provides guidelines for implementing dynamic data exchange for applications that cannot use the Dynamic Data Exchange Management Library (DDEML). 
	* [Dynamic Data Exchange - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dataxchg/dynamic-data-exchange)
		* This section provides guidelines for implementing dynamic data exchange for applications that cannot use the Dynamic Data Exchange Management Library (DDEML). 
* **DomainKeys Identified Mail**<a name="ddkim"></a>
	* [DomainKeys Identified Mail - Wikipedia](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail)
* **Domain Message Authentication, Reporting, and Conformance - DMARC**<a name="ddmarc"></a>
	* [DMARC - Wikipedia](https://en.wikipedia.org/wiki/DMARC)
	* [Domain-based Message Authentication, Reporting, and Conformance (DMARC) - RFC7489](https://tools.ietf.org/html/rfc7489)
* **Excel**
	* [Insert an object in your Excel spreadsheet - support.office](https://support.office.com/en-us/article/Insert-an-object-in-your-Excel-spreadsheet-e73867b2-2988-4116-8d85-f5769ea435ba)
* **Extensible Stylesheet Language(XSL/XSL Transformations)**
	* [What Is XSLT - G. Ken Holman(2000)](https://www.xml.com/pub/a/2000/08/holman/)
	* [Hello, World! (XSLT) - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms765388(v=vs.85))
		* The following example shows a simple but complete XML document transformed by an XSLT style sheet. The source XML document, hello.xml, contains a "Hello, World!" greeting from "An XSLT Programmer".
	* [XSLT Stylesheet Scripting Using `<msxsl:script>` - docs.ms](https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script)
	* [Stylesheet (XSL) web resources - docs.ms](https://docs.microsoft.com/en-us/dynamics365/customerengagement/on-premises/developer/stylesheet-xsl-web-resources)
	* [XSLT for MSXML - docs.ms](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms759204(v=vs.85))
* **Excel Macros**<a name="excelm"></a>
	* [Application.ExecuteExcel4Macro method (Excel) - docs.ms(2019)](https://docs.microsoft.com/en-us/office/vba/api/excel.application.executeexcel4macro)
	* [Excel 4.0 Macro Functions Reference - Philip Treacy](https://d13ot9o61jdzpp.cloudfront.net/files/Excel%204.0%20Macro%20Functions%20Reference.pdf)
* **Excel PowerQuery**
	* [Introduction to Microsoft Power Query for Excel - support.ms](https://support.microsoft.com/en-us/office/introduction-to-microsoft-power-query-for-excel-6e92e2f4-2079-4e1f-bad5-89f6269cd605)
	* [Power Query - Overview and Learning - support.ms](https://support.microsoft.com/en-us/office/power-query-overview-and-learning-ed614c81-4b00-4291-bd3a-55d80767f81d?ui=en-us&rs=en-us&ad=us)
* **Factur-X**<a name="dfx"></a>
	* [Factur-X](http://fnfe-mpe.org/factur-x/factur-x_en/)
		* Factur-X is a Franco-German standard for hybrid e-invoice (PDF for users and XML data for process automation), the first implementation of the European Semantic Standard EN 16931 published by the European Commission on October 16th 2017. Factur-X is the same standard than ZUGFeRD 2.0.
		* Factur-X is at the same time a full readable invoice in a PDF A/3 format, containing all information useful for its treatment, especially in case of discrepancy or absence of automatic matching with orders and / or receptions, and a set of invoice data presented in an XML structured file conformant to EN16931 (syntax CII D16B), complete or not, allowing invoice process automation.
	* [Factur-X Python library - github](https://github.com/invoice-x/factur-x-ng)
		* Factur-X is a EU standard for embedding XML representations of invoices in PDF files. This library provides an interface for reading, editing and saving the this metadata.
* **Microsoft HTA**
	* [Introduction to HTML Applications (HTAs) - docs.ms(2013)](https://web.archive.org/web/20200711161356/https://docs.microsoft.com/en-us/previous-versions//ms536496(v=vs.85))
	* [HTML Applications Reference - docs.ms(2013)]()
* **MS Word Field Codes**
	* [Insert, edit, and view fields in Word - support.ms](https://support.microsoft.com/en-us/office/insert-edit-and-view-fields-in-word-c429bbb0-8669-48a7-bd24-bab6ba6b06bb?ui=en-US&rs=en-US&ad=US)
    	* Fields codes are useful as placeholders for data that might change in your document, and you can use them to automate certain aspects of your document. Field codes are inserted for you when you use Word features like page numbers or a table of contents, but you can insert field codes manually for other tasks like performing calculations or filling in document content from a data source.
	* [List of field codes in Word - support.ms](https://support.microsoft.com/en-us/office/list-of-field-codes-in-word-1ad6d91a-55a7-4a8d-b535-cf7888659a51)
* **MS Office File Formats**
	* [File format reference for Word, Excel, and PowerPoint - docs.ms(2020)](https://docs.microsoft.com/en-us/deployoffice/compat/office-file-format-reference)
    	* Supported file formats and their extensions are listed in the following tables for Word, Excel, and PowerPoint.
    * [[MS-CFB]: Compound File Binary File Format - docs.ms(2020)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b)
	* [OpenOffice.org's Documentation of theMicrosoft Compound Document File Format - Daniel Rentz](https://www.openoffice.org/sc/compdocfileformat.pdf)
	* [MS-OSHARED: Office Common Data Types and Objects Structures](https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/d93502fa-5b8f-4f47-a3fe-5574046f4b8d). Includes property sets that can store document-level properties (metadata).
    * [MS-OLEPS: Object Linking and Embedding (OLE) Property Set Data Structures](https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-OLEPS/). Property sets in XLS documents are stored as OLE items.
    * [MS-OFFCRYPTO: Office Document Cryptography Structure (latest version)](https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/).
	* [[MS-XLS]: Excel Binary File Format (.xls) Structure - docs.ms](https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/cd03cb5f-ca02-4934-a391-bb674cb8aa06)
    	* Specifies the Excel Binary File Format (.xls) Structure, which is the binary file format used by Microsoft Excel 97, Microsoft Excel 2000, Microsoft Excel 2002, and Microsoft Office Excel 2003.
	* [MICROSOFT OFFICE EXCEL97-2007BINARY FILE FORMAT SPECIFICATION[`*.xls` (97-2007) format]](https://www.loc.gov/preservation/digital/formats/digformatspecs/Excel97-2007BinaryFileFormat(xls)Specification.pdf)
    * [About the .xls binary format - gaia-gis.it](http://www.gaia-gis.it/gaia-sins/freexl-1.0.5-doxy-doc/html/Format.html)
    * [[MS-XLSX]: Excel (.xlsx) Extensions to the Office Open XML SpreadsheetML File Format - docs.ms(2020)](https://docs.microsoft.com/en-us/openspecs/office_standards/ms-xlsx/2c5dee00-eff2-4b22-92b6-0738acd4475e)
    	* Specifies the Excel (.xlsx) Extensions to the Office Open XML SpreadsheetML File Format, which are extensions to the Office Open XML file formats as described in [ISO/IEC-29500-1]. The extensions are specified using conventions provided by the Office Open XML file formats as described in [ISO/IEC-29500-3].
    * [OpenOffice.org's Documentation of the Microsoft Excel File Format - Daniel Rentz](https://www.openoffice.org/sc/excelfileformat.pdf)
* **HTA**<a name="hata"></a>
	* **101**
		* [HTML Application - Wikipedia](https://en.wikipedia.org/wiki/HTML_Application)
		* [HTML Applications - docs.ms(2013)](https://docs.microsoft.com/en-us/previous-versions//ms536471(v=vs.85)?redirectedfrom=MSDN)
			* HTML Applications (HTAs) are full-fledged applications. These applications are trusted and display only the menus, icons, toolbars, and title information that the Web developer creates. In short, HTAs pack all the power of Windows Internet Explorer—its object model, performance, rendering power, protocol support, and channel–download technology—without enforcing the strict security model and user interface of the browser. HTAs can be created using the HTML and Dynamic HTML (DHTML) that you already know.
		* [Learn About Scripting for HTML Applications (HTAs) - technet.ms](https://technet.microsoft.com/en-us/scriptcenter/dd742317.aspx)
	* **Articles/Blogposts/Writeups**
		* [Extreme Makeover: Wrap Your Scripts Up in a GUI Interface - technet.ms](https://technet.microsoft.com/en-us/library/ee692768.aspx)
	* **Tools**
* **Object Linking and Embedding**<a name="dole"></a>
	* [Object Linking and Embedding - Wikipedia](https://en.wikipedia.org/wiki/Object_Linking_and_Embedding)
	* [OLE - msdn.ms](https://msdn.microsoft.com/en-us/library/df267wkc.aspx)
	* [[MS-OLEDS]: Object Linking and Embedding (OLE) Data Structures - msdn.ms](https://msdn.microsoft.com/en-us/library/dd942265.aspx)
	* [Insert an object in your Excel spreadsheet - support.office](https://support.office.com/en-us/article/Insert-an-object-in-your-Excel-spreadsheet-e73867b2-2988-4116-8d85-f5769ea435ba)
* **Office Open XML Format**<a name="doxml"></a>
	* [Introducing the Office (2007) Open XML File Formats - docs.ms](https://docs.microsoft.com/en-us/previous-versions/office/developer/office-2007/aa338205(v=office.12)#office2007aboutnewfileformat_structureoftheofficexmlformats)
* **Office URI Schemes**<a name="douri"></a>
	* [Office URI Schemes - docs.ms](https://docs.microsoft.com/en-us/office/client-developer/office-uri-schemes)
		* This document defines the format of Uniform Resource Identifiers (URIs) for office productivity applications. The scheme is supported in Microsoft Office 2010 Service Pack 2 and later, including the Microsoft Office 2013 for Windows and the Microsoft SharePoint 2013 products. It is also supported in Office for iPhone, Office for iPad, and Office for Mac 2011.
* **Protected View**<a name="dpv"></a>
	* [What is Protected View? - support.office.com](https://support.office.com/en-us/article/What-is-Protected-View-d6f09ac7-e6b9-4495-8e43-2bbcdbcb6653)
* **ScriptControl**<a name="dsc"></a>
	* [Using ScriptControl Methods - docs.ms](https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-6.0/aa227637(v=vs.60))
		* The ScriptControl contains methods to execute code, add code and objects to the scripting engine, and reset the scripting engine to its initial state.
* **Sender Policy Framework - SPF**<a name="dspf"></a>
	* [Sender Policy Framework - Wikipedia](https://en.wikipedia.org/wiki/Sender_Policy_Framework)
* **SMTP Strict Transport Security** 
	* [SMTP Strict Transport Security](https://lwn.net/Articles/684462/)
* **Subdocument Reference**<a name="sdf"></a>
	* [SubDocumentReference class - msdn.ms](https://msdn.microsoft.com/en-us/library/office/documentformat.openxml.wordprocessing.subdocumentreference.aspx?cs-save-lang=1&cs-lang=vb#Syntax)
* **Transport Neutral Encapsulation Format**<a name="dsr"></a>
	* [Transport Neutral Encapsulation Format - Wikipedia](https://en.wikipedia.org/wiki/Transport_Neutral_Encapsulation_Format)
* **Visual Basic for Applications (VBA)**<a name="dvba"></a>
	* [[MS-OVBA]: Office VBA File Format Structure - msdn.ms](https://msdn.microsoft.com/en-us/library/cc313094(v=office.12).aspx)
		* Specifies the Office VBA File Format Structure, which describes the Microsoft Visual Basic for Applications (VBA) File Format for Microsoft Office 97, Microsoft Office 2000, Microsoft Office XP, Microsoft Office 2003, and the 2007 Microsoft Office system. This specification also describes a storage that contains a VBA project, which contains embedded macros and custom forms for use in Office documents.
	* [[MS-VBAL]: VBA Language Specification](https://msdn.microsoft.com/en-us/library/dd361851.aspx)
		* Specifies the VBA Language, which defines the implementation-independent and operating system-independent programming language that is required to be supported by all conforming VBA implementations. This specification also defines all features and behaviors of the language that are required to exist and behave identically in all conforming implementations.
* **Visual Basic Script**
	* [Using Visual Basic Scripting Edition - docs.ms(2019)](https://web.archive.org/web/20200713180024/https://docs.microsoft.com/en-us/office/vba/outlook/how-to/using-visual-basic-to-customize-outlook-forms/using-visual-basic-scripting-edition)
	* [VBScript Fundamentals - rhino3d.com](https://web.archive.org/web/20200713180137/https://developer.rhino3d.com/api/rhinoscript/vbscript_fundamentals/vbscript_fundamentals.htm)
	* [VBScript - Wikipedia](https://en.wikipedia.org/wiki/VBScript)
	* [What is VBScript? Introduction & Examples - Guru99](https://www.guru99.com/introduction-to-vbscript.html)
	* [What Is VBScript, and Why Did Microsoft Just Kill It? - Chris Hoffman(2019)](https://www.howtogeek.com/437372/what-is-vbscript-and-why-did-microsoft-just-kill-it/)
		* VBScript no longer supported in IE by default.
	* [Rob van der Woude's VBScript Scripting Techniques](https://www.robvanderwoude.com/vbstech.php)
* **XLL**<a name="dxll"></a>
	* [Welcome to the Excel Software Development Kit - msdn.ms](https://msdn.microsoft.com/en-us/library/office/bb687883.aspx)
	* [Accessing XLL code in Excel - docs.ms](https://docs.microsoft.com/en-us/office/client-developer/excel/accessing-xll-code-in-excel)
* **General**
	* [SPF, DKIM, and DMARC Demystified - McAfee](https://jira.sakaiproject.org/secure/attachment/43722/sb-spf-dkim-dmarc-demystified.pdf)
	* [Add commands to your presentation with action buttons](https://support.office.com/en-us/article/Add-commands-to-your-presentation-with-action-buttons-7db2c0f8-5424-4780-93cb-8ac2b6b5f6ce)
		* Add commands to your presentation with action buttons
	* [Variable Object (Word) - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Word-VBA/articles/variable-object-word)
	* [Using ScriptControl Methods - docs.ms](https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-6.0/aa227637(v=vs.60))
		* The ScriptControl contains methods to execute code, add code and objects to the scripting engine, and reset the scripting engine to its initial state.
	* [VBA ScriptControl to run Java Script Function](https://www.experts-exchange.com/questions/28190006/VBA-ScriptControl-to-run-Java-Script-Function.html)
	* [CallByName Function - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Language-Reference-VBA/articles/callbyname-function)
		* Executes a method of an object, or sets or returns a property of an object. SyntaxCallByName( object, procname, calltype,[args()])






















----------
### <a name="framework">Phishing Frameworks:</a>
* **All-in-Ones**<a name="aio"></a>
	* [Phishing Frenzy](http://www.phishingfrenzy.com/)
		* Phishing Frenzy is an Open Source Ruby on Rails application that is leveraged by penetration testers to manage email phishing campaigns. The goal of the project is to streamline the phishing process while still providing clients the best realistic phishing campaign possible. This goal is obtainable through campaign management, template reuse, statistical generation, and other features the Frenzy has to offer.
	* [sptoolkit](https://github.com/sptoolkit/sptoolkit)
		* Simple Phishing Toolkit is a super easy to install and use phishing framework built to help Information Security professionals find human vulnerabilities
	* [sptoolkit-rebirth](https://github.com/simplephishingtoolkit/sptoolkit-rebirth)
		* sptoolkit hasn't been actively developed for two years. As it stands, it's a brilliant peice of software, and the original developers are pretty damn awesome for creating it. But we'd like to go further, and bring sptoolkit up to date. We've tried contacting the developers, but to no avail. We're taking matters into our own hands now.
	* [KingPhisher](https://github.com/securestate/king-phisher)
		* King Phisher is a tool for testing and promoting user awareness by simulating real world phishing attacks. It features an easy to use, yet very flexible architecture allowing full control over both emails and server content. King Phisher can be used to run campaigns ranging from simple awareness training to more complicated scenarios in which user aware content is served for harvesting credentials.
	* [Gophish](https://github.com/gophish/gophish)
		* Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
		* [gophish documentation](https://getgophish.com/documentation/)
	* [FiercePhish](https://github.com/Raikia/FiercePhish)
		* FiercePhish is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more
	* [Mercure](https://github.com/synhack/mercure/)
		* Mercure is a tool for security managers who want to teach their colleagues about phishing.
	* [Cartero](https://github.com/Section9Labs/Cartero)
		* Cartero is a modular project divided into commands that perform independent tasks (i.e. Mailer, Cloner, Listener, AdminConsole, etc...). In addition each sub-command has repeatable configuration options to configure and automate your work.
	* [King Phisher](https://github.com/securestate/king-phisher)
		* King Phisher is a tool for testing and promoting user awareness by simulating real world phishing attacks. It features an easy to use, yet very flexible architecture allowing full control over both emails and server content. King Phisher can be used to run campaigns ranging from simple awareness training to more complicated scenarios in which user aware content is served for harvesting credentials.
	* [SpeedPhish Framework](https://github.com/tatanus/SPF)
		* SPF (SpeedPhish Framework) is a python tool designed to allow for quick recon and deployment of simple social engineering phishing exercises.
	* [Phishing-API](https://github.com/curtbraz/Phishing-API)
		* This API has three main features. One allows you to easily deploy cloned landing pages for credential stealing, another is weaponized Word doc creation, and the third is saved email campaign templates. Both attack methods are integrated into Slack for real-time alerting.
* **Built for 2FA**<a name="2fa">
	* [CredSniper](https://github.com/ustayready/CredSniper)
		* CredSniper is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens. Easily launch a new phishing site fully presented with SSL and capture credentials along with 2FA tokens using CredSniper. The API provides secure access to the currently captured credentials which can be consumed by other applications using a randomly generated API token.
	* [ReelPhish](https://github.com/fireeye/ReelPhish)
		* [ReelPhish: A Real-Time Two-Factor Phishing Tool](https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html)
	* [evilginx2](https://github.com/kgretzky/evilginx2)
		* evilginx2 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.
	* [modlishka](https://github.com/drk1wi/Modlishka)
		* Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow, which allows to transparently proxy multi-domain destination traffic, both TLS and non-TLS, over a single domain, without a requirement of installing any additional certificate on the client. What does this exactly mean? In short, it simply has a lot of potential, that can be used in many use case scenarios...
* **One-Off**
* **Social Media**<a name="sm"></a>
	* [ShellPhish](https://github.com/thelinuxchoice/shellphish)
		* Phishing Tool for Instagram, Facebook, Twitter, Snapchat, Github, Yahoo, Protonmail, Google, Spotify, Netflix, Linkedin, Wordpress, Origin, Steam, Microsoft, InstaFollowers, Pinterest 
	* [social_attacker](https://github.com/Greenwolf/social_attacker)
		* An Open Source Multi Site Automated Social Media Phishing Framework 
	* [SocialFish](https://github.com/UndeadSec/SocialFish)
		* Easy phishing using social media sites
* **Specific Purpose**<a name="specific"></a>
	* [Ares](https://github.com/dutchcoders/ares)
		* Phishing toolkit for red teams and pentesters. Ares allows security testers to create a landing page easily, embedded within the original site. Ares acts as a proxy between the phised and original site, and allows (realtime) modifications and injects. All references to the original site are being rewritten to the new site. Users will use the site like they'll normally do, but every step will be recorded of influenced. Ares will work perfect with dns poisoning as well.
	* [FormPhish](https://github.com/thelinuxchoice/formphish)
		* Auto Phishing form-based websites. This tool can automatically detect inputs on html form-based websites to create a phishing page.
	* [LockPhish](https://github.com/thelinuxchoice/lockphish)
		* Lockphish is a tool for phishing attacks on the lock screen, designed to grab Windows credentials, Android PIN and iPhone Passcode 
	* [otu-plz](https://github.com/bashexplode/otu-plz)
		* otu-plz is an open-source phishing campaign toolkit that makes setting up phishing infrastructure, sending emails with one-time use tokens, and evading blue teams a breeze. It also stores all information within a database to keep track of clicks and other data.
	* [WifiPhisher](https://github.com/wifiphisher/wifiphisher)
    	* Wifiphisher is a rogue Access Point framework for conducting red team engagements or Wi-Fi security testing. Using Wifiphisher, penetration testers can easily achieve a man-in-the-middle position against wireless clients by performing targeted Wi-Fi association attacks. Wifiphisher can be further used to mount victim-customized web phishing attacks against the connected clients in order to capture credentials (e.g. from third party login pages or WPA/WPA2 Pre-Shared Keys) or infect the victim stations with malwares.
* **Templates**
	* [SimplyTemplate](https://github.com/killswitch-GUI/SimplyTemplate)
		* Phishing Template Generation Made Easy. The goal of this project was to hopefully speed up Phishing Template Gen as well as an easy way to ensure accuracy of your templates. Currently my standard Method of delivering emails is the Spear Phish in Cobalt strike so you will see proper settings for that by defaul
	* [TackleBox](https://github.com/trailofbits/tacklebox)
		* A phishing toolkit for generating and sending phishing emails.













------------------------------------
### <a name="payloads"></a>Payloads
* **Delivery**<a name="delivery"></a>
	* **File smuggling**
		* **Articles/Blogposts/Writeups**
			* [HTML smuggling explained - Stan Hegt(2018)](https://outflank.nl/blog/2018/08/14/html-smuggling-explained/)
			* [Smuggling HTA files in Internet Explorer/Edge - Richard Warren(2017)](https://www.nccgroup.com/us/about-us/newsroom-and-events/blog/2017/august/smuggling-hta-files-in-internet-exploreredge/)
			* [File Smuggling with HTML and JavaScript - @spottheplanet](https://ired.team/offensive-security/defense-evasion/file-smuggling-with-html-and-javascript)
			* [Strange Bits: HTML Smuggling and GitHub Hosted Malware - Karsten Hahn(2019)](https://www.gdatasoftware.com/blog/2019/05/31695-strange-bits-smuggling-malware-github)
		* **Tools**	
			* [EmbedInHTML](https://github.com/Arno0x/EmbedInHTML)
				* What this tool does is taking a file (any type of file), encrypt it, and embed it into an HTML file as resource, along with an automatic download routine simulating a user clicking on the embedded ressource. Then, when the user browses the HTML file, the embedded file is decrypted on the fly, saved in a temporary folder, and the file is then presented to the user as if it was being downloaded from the remote site. Depending on the user's browser and the file type presented, the file can be automatically opened by the browser.
* **CHM File**<a name="chm"></a>
	* **101**
		* [Microsoft Compiled HTML Help - Wikipedia](https://en.wikipedia.org/wiki/Microsoft_Compiled_HTML_Help)
		* [Unofficial (Preliminary) HTML Help Specification - Paul Wise, Jed Wing(nongnu.org)](https://www.nongnu.org/chmspec/latest/)
	* **Articles/Blogposts/Writeups**
		* [Microsoft Compiled HTML Help / Uncompiled .chm File XML External Entity Injection - hyp3rlinx(2019)](https://packetstormsecurity.com/files/153660/MICROSOFT-WINDOWS-HTML-HELP-UNCOMPILED-CHM-FILE-XML-EXTERNAL-ENTITY-INJECTION.txt)
			* Microsoft compiled HTML Help and uncompiled .chm files can be leveraged for XML external entity injection attacks.
	* **Talks/Presentations/Videos**
	* **Tools**
		* [List of CHM readers and viewers for Window - blog.kowalczyk](https://blog.kowalczyk.info/articles/chm-reader-viewer-for-windows.html)
* **ClickOnce**<a name="clickonce"></a>
	* **101**
		* [Demystifying ClickOnce - ericlaw(2019)](https://textslashplain.com/2019/01/02/demystifying-clickonce/)
		* [ClickOnce security and deployment - docs.ms](https://docs.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment?view=vs-2019)
		* "ClickOnce is a deployment technology that enables you to create self-updating Windows-based applications that can be installed and run with minimal user interaction. Visual Studio provides full support for publishing and updating applications deployed with ClickOnce technology if you have developed your projects with Visual Basic and Visual C#. "	
		* [What is an APPREF-MS file? - fileinfo.com](https://fileinfo.com/extension/appref-ms)
			* Application reference file used by ClickOnce, a Microsoft platform used to deploy and run remote Web applications; contains a local or remote link to an application; commonly used to enable links from the Windows Start Menu.
	* **Articles/Blogposts/Writeups**
		* [List Of ClickOnce Articles - @robindotnet](https://robindotnet.wordpress.com/list-of-clickonce-articles/)
		* [ClickOnce (Twice or Thrice): A Technique for Social Engineering and (Un)trusted Command Execution - bohops](https://bohops.com/2017/12/02/clickonce-twice-or-thrice-a-technique-for-social-engineering-and-untrusted-command-execution/)
		* [ClickOnce Security and Deployment - docs.ms](https://docs.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment?view=vs-2015)
		* [ClickOnce application suddenly blocked by AppLocker Group Policy - tech.xenit](https://tech.xenit.se/clickonce-application-suddenly-blocked-by-applocker-group-policy/)
		* [publishing-clickonce-applications.md - MS Visual Studio Docs](https://github.com/MicrosoftDocs/visualstudio-docs/blob/master/docs/deployment/publishing-clickonce-applications.md)
		* [ClickOnce deployment for Add-in Express solutions](https://www.add-in-express.com/docs/net-clickonce-solution.php)
		* [Continuously Deploy Your ClickOnce Application From Your Build Server - Daniel Schroeder(2017)](https://blog.danskingdom.com/continuously-deploy-your-clickonce-application-from-your-build-server/)
		* [ClickOnce (Twice or Thrice): A Technique for Social Engineering and (Un)trusted Command Execution - BOHOPS(2017)](https://bohops.com/2017/12/02/clickonce-twice-or-thrice-a-technique-for-social-engineering-and-untrusted-command-execution/)
		* [How to sign a ClickOnce application - StackOverflow(2012)](https://stackoverflow.com/questions/9610556/how-to-sign-a-clickonce-application)
	* **Talks/Presentations/Videos**
		* [All You Need is One - A ClickOnce Love Story - Ryan Gandrud, Cody Wass(Secure360 2015)](https://www.slideshare.net/NetSPI/all-you-need-is-one-a-click-once-love-story-secure360-2015)
		* [ClickOnce and You're in - When Appref-ms Abuse is Operating as Intended - William Burke(BHUSA2019)](https://www.youtube.com/watch?v=4FtVwiuBtx4)
			* [Slides](https://i.blackhat.com/USA-19/Wednesday/us-19-Burke-ClickOnce-And-Youre-In-When-Appref-Ms-Abuse-Is-Operating-As-Intended-wp.pdf)
			* As tried-and-true methods of code execution via phishing are getting phased out, new research was required to maintain that avenue of gaining initial access. Sifting through different file types and how they operate led to further examination of the ".Appref-ms" extension, utilized by Microsoft's ClickOnce. This research led down a long and winding road, not only resulting in some new updates to be applied to our phishing methodology but an innovative method for C2 management as well - all while staying within the means of how appref-ms is intended to be used. Follow us down the rabbit hole as we delve into what an .appref-ms file is, how it operates, and some of the methods discovered that can be leveraged to deploy our own nefarious purposes. We will also provide insight on what this execution looks like from the user's perspective, and additional steps that can be taken throughout deployment to further mask and enhance these malicious capabilities. To play our own devil's advocate, we will also cover potential indicators of compromise that result from appref-ms abuse in addition to some preemptive measures that can be deployed to protect against it. Appref-ms abuse has the potential to be a great addition to any security tester's toolkit. It runs natively on Windows 10 and 7, blends in with normal operations, and is an easily adaptable method of code delivery and execution. It's up to you to determine how to use it.
	* **Tools**
		* [ClickOnceGenerator](https://github.com/Mr-Un1k0d3r/MaliciousClickOnceGenerator)
			* Quick Malicious ClickOnceGenerator for Red Team. The default application a simple WebBrowser widget that point to a website of your choice.
* **DotNetToJScript**<a name="dotnetjs"></a>
	* **Articles/Blogposts/Writeups**
		* [DotNetToJScript](https://github.com/tyranid/DotNetToJScript)
			*  A tool to create a JScript file which loads a .NET v2 assembly from memory. 
		* [ Disabling AMSI in JScript with One Simple Trick - James Forshaw(2018)](https://www.tiraniddo.dev/2018/06/disabling-amsi-in-jscript-with-one.html)
		* [CSharp, DotNetToJScript, XSL - Rastamouse(2018)](https://rastamouse.me/2018/05/csharp-dotnettojscript-xsl/)
		* [Executing C# Assemblies from Jscript and wscript with DotNetToJscript - @spottheplanet](https://ired.team/offensive-security/defense-evasion/executing-csharp-assemblies-from-jscript-and-wscript-with-dotnettojscript)
		* [Advanced TTPs – DotNetToJScript (Part 1) - Jerry Odegaard(2020)](https://whiteoaksecurity.com/blog/2020/1/16/advanced-ttps-dotnettojscript-part-1)
			* "We’ve covered the basics on what DotNetToJScript is, and why you should still care about it. We’ve also seen that it’s pretty easy to get DotNetToJScript downloaded, built and tested. In the next blog on this topic we’ll modify the UnmanagedPowerShell project’s PowerShellRunner to use with DotNetToJScript. Stay tuned!"
		* [Part 2](https://whiteoaksecurity.com/blog/2020/1/23/advanced-ttps-dotnettojscript-part-2)
			* "We’ve made some progress in weaponizing a DotNetToJScript payload. We repurposed the PowerShellRunner component from the UnmanagedPowerShell project to execute PowerShell commands directly from client-side JavaScript. Our payload completely avoids sophisticated PowerShell logging in environments that still have .NET 2.0 installed, which in our experience is most environments. In the next blog, we’ll take a look at further weaponizing DotNetToJScript by manually building a malicious document (maldoc) to execute our payload!"
		* [Part 3](https://whiteoaksecurity.com/blog/2020/2/3/advanced-ttps-dotnettojscript-part-3)
* **GadgetToJScript**<a name="gtjs"></a>
	* **101**
		* [GadgetToJScript](https://github.com/med0x2e/GadgetToJScript)
			* A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts. 
		* [GadgetToJScript, Covenant, Donut - 3xpl01tc0d3r(2020)](https://3xpl01tc0d3r.blogspot.com/2020/02/gadgettojscript-covenant-donut.html)
	* **Tools**
* **HTA**<a name="htap"></a>
	* **Articles/Blogposts/Writeups**
		* [HTA Tips - 599cd.com](https://www.599cd.com/tips/hta/?key=)
		* [Rob van der Woude's VBScript Scripting Techniques: HTA](https://www.robvanderwoude.com/vbstech_hta.php)
		* [Hacking around HTA Files](http://blog.sevagas.com/?Hacking-around-HTA-files)
		* [LethalHTA - A new lateral movement technique using DCOM and HTA - codewhitesec](https://codewhitesec.blogspot.com/2018/07/lethalhta.html)
		* [MSHTA code execution - bypass application whitelisting. - @spottheplanet](https://ired.team/offensive-security/code-execution/t1170-mshta-code-execution)
		* [Bypass Application Whitelisting using mshta.exe (Multiple Methods) - Raj Chandel](https://www.hackingarticles.in/bypass-application-whitelisting-using-mshta-exe-multiple-methods/)
		* [Pentesting and .hta (bypass PowerShell Constrained Language Mode) - Josh Graham(2018)](https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997)
		* [pentesting .hta files](https://github.com/jpginc/pentesting-hta)
		* [Malicious HTAs - trustedsec](https://www.trustedsec.com/2015/07/malicious-htas/)
	* **Tools**
		* [WeirdHTA](https://github.com/felamos/weirdhta)
			* A python tool to create obfuscated HTA script.
		* [Demiguise](https://github.com/nccgroup/demiguise)
			* The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page, the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user.
		* [morphHTA - Morphing Cobalt Strike's evil.HTA](https://github.com/vysec/morphHTA)
		* [LethalHTA](https://github.com/codewhitesec/LethalHTA)
			* "Repo for our Lateral Movement technique using DCOM and HTA."
* **OLE+LNK / Embedded Objects**<a name="olelnk"></a>
	* [Click me if you can, Office social engineering with embedded objects - Yorick Koster(2018)](https://www.securify.nl/blog/SFY20180801/click-me-if-you-can_-office-social-engineering-with-embedded-objects.html)
	* [Phishing: Embedded HTML Forms - @spottheplanet](https://ired.team/offensive-security/initial-access/phishing-with-ms-office/phishing-embedded-html-forms)
	* [Phishing: OLE + LNK - @spottheplanet](https://ired.team/offensive-security/initial-access/phishing-with-ms-office/phishing-ole-+-lnk)
	* [Phishing: Embedded Internet Explorer - @spottheplanet](https://ired.team/offensive-security/initial-access/phishing-with-ms-office/phishing-embedded-internet-explorer)
* **PDF**<a name="ppdf"></a>
	* **Articles/Blogposts/Writeups**
		* [PDF – NTLM Hashes - pentestlab.blog](https://pentestlab.blog/2018/05/09/pdf-ntlm-hashes/)
	* **Tools**
		* [JS2PDFInjector](https://github.com/cornerpirate/JS2PDFInjector)
			* Use this tool to Inject a JavaScript file into a PDF file.
		* [Bad-PDF](https://github.com/deepzec/Bad-Pdf)
			* Bad-PDF create malicious PDF file to steal NTLM(NTLMv1/NTLMv2) Hashes from windows machines, it utilize vulnerability disclosed by checkpoint team to create the malicious PDF file. Bad-Pdf reads the NTLM hashes using Responder listener.
		* [Worse-PDF](https://github.com/3gstudent/Worse-PDF)
			* Turn a normal PDF file into malicious.Use to steal Net-NTLM Hashes from windows machines.
		* [pdf2xdp.rb](https://github.com/rapid7/metasploit-framework/blob/master/tools/exploit/pdf2xdp.rb)
			* This script converts a PDF file to an equivalent XML Data Package file, which can be opened by Adobe Reader as well and typically escapes AV detection better than a "normal" PDF
		* [peepdf](https://github.com/jesparza/peepdf)
			* peepdf is a Python tool to explore PDF files in order to find out if the file can be harmful or not. The aim of this tool is to provide all the necessary components that a security researcher could need in a PDF analysis without using 3 or 4 tools to make all the tasks. With peepdf it's possible to see all the objects in the document showing the suspicious elements, supports all the most used filters and encodings, it can parse different versions of a file, object streams and encrypted files. With the installation of PyV8 and Pylibemu it provides Javascript and shellcode analysis wrappers too. Apart of this it's able to create new PDF files and to modify/obfuscate existent ones.
* **.SettingContent-ms**<a name="scms"></a>
		* [The Tale of SettingContent-ms Files - Matt Nelson(2018)](https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39)
		* [Defending Against SettingContent-MS being used in MS Office and PDF Files - Taeil Goh](https://www.opswat.com/blog/defending-against-setting-content-ms-being-used-in-ms-office-and-pdf-files)
		* [TA505 Abusing SettingContent-ms within PDF files to Distribute FlawedAmmyy RAT - ProofPoint](https://www.proofpoint.com/us/threat-insight/post/ta505-abusing-settingcontent-ms-within-pdf-files-distribute-flawedammyy-rat)
		* [Analysis - .SettingContent-ms Exploit - ](https://rinseandrepeatanalysis.blogspot.com/2018/10/analysis-settingcontent-ms-exploit.html)
		* [Microsoft Blocks Embedding SettingContent-ms Files in Office 365 Docs - ](https://www.bleepingcomputer.com/news/security/microsoft-blocks-embedding-settingcontent-ms-files-in-office-365-docs/)
		* [SettingContent-ms can be Abused to Drop Complex DeepLink and Icon-based Payload - Michael Villanueva](https://blog.trendmicro.com/trendlabs-security-intelligence/settingcontent-ms-can-be-abused-to-drop-complex-deeplink-and-icon-based-payload/)
		* [Weaponizing .SettingContent-ms Extensions for Code Execution - David Kennedy(2018)](https://www.trustedsec.com/blog/weaponizing-settingcontent/)
	* **Tools**
		* [auto_SettingContent-ms](https://github.com/trustedsec/auto_SettingContent-ms)
			* This is a quick POC for using the Matt Nelson (enigma0x3) technique for generating a malicious .SettingContent-ms extension type for remote code execution. This automates generating an HTA downloader and embeds it in the SettingContent-ms file for you and starts Apache. 
		* [SettingContent-MS-File-Execution](https://github.com/bvoris/SettingContent-MS-File-Execution)
			*  SettingContent-MS File Execution vulnerability in Windows 10 PoC
* **UNC**<a name="uncp"></a>
	* **Articles/Blogposts/Writeups**
	* **Tools**














------------------
### <a name="tools"></a>Tools
* **Cloning**<a name="cloning"></a>
	* [Cooper](https://github.com/chrismaddalena/Cooper)
		* Cooper simplifies the process of cloning a target website or email for use in a phishing campaign. Just find a URL or download the raw contents of an email you want to use and feed it to Cooper. Cooper will clone the content and then automatically prepare it for use in your campaign. Scripts, images, and CSS can be modified to use direct links instead of relative links, links are changed to point to your phishing server, and forms are updated to send data to you -- all in a matter of seconds. Cooper is cross-platform and should work with MacOS, Linux, and Windows.
* **Defense**
	* [IsThisLegit](https://github.com/duo-labs/isthislegit)
		* IsThisLegit is a dashboard and Chrome extension that makes it easy to receive, analyze, and respond to phishing reports.
* **Document Generation**
	* [unioffice](https://github.com/unidoc/unioffice)
    	* unioffice is a library for creation of Office Open XML documents (.docx, .xlsx and .pptx). It's goal is to be the most compatible and highest performance Go library for creation and editing of docx/xlsx/pptx files.
* **Domains**
	* [CatMyFish](https://github.com/Mr-Un1k0d3r/CatMyFish)
		* Search for categorized domain that can be used during red teaming engagement. Perfect to setup whitelisted domain for your Cobalt Strike beacon C&C.  It relies on expireddomains.net to obtain a list of expired domains. The domain availability is validated using checkdomain.com
	* [CatPhish](https://github.com/ring0lab/catphish)
		* Generate similar-looking domains for phishing attacks. Check expired domains and their categorized domain status to evade proxy categorization. Whitelisted domains are perfect for your C2 servers.
* **Email Harvesting**
	* [Email Address Harvesting for Phishing](http://www.shortbus.ninja/email-address-harvesting-for-phishing-attacks/)
	* [PhishBait](https://github.com/hack1thu7ch/PhishBait)
		* Tools for harvesting email addresses for phishing attacks
* **Local Phishing**
	* [Ask and ye shall receive - Impersonating everyday applications for profit - FoxIT](https://www.fox-it.com/en/insights/blogs/blog/phishing-ask-and-ye-shall-receive/)
	* [Invoke-CredentialPhisher](https://github.com/fox-it/Invoke-CredentialPhisher)
		* The first one is a powershell script to send toast notifications on behalf on an (installed) application or the computer itself. The user will be asked to supply credentials once they click on the notification toast. The second one is a Cobalt Strike module to launch the phishing attack on connected beacons.
	* [Phishing for Credentials: If you want it, just ask! - enigma0x3](http://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
	* [iOS Privacy: steal.password - Easily get the user's Apple ID password, just by asking - Felix Krause](https://krausefx.com/blog/ios-privacy-stealpassword-easily-get-the-users-apple-id-password-just-by-asking)
	* [Gone-Phishing-2](https://github.com/benb116/Gone-Phishing-2)
		* This is a new and improved version of Gone Phishing that uses applescript to phish for a Mac user's password. It uploads the password and keychain items to a remote server
* **Payloads**
	* [Social-Engineering-Payloads - t3ntman](https://github.com/t3ntman/Social-Engineering-Payloads)
	* [backdoorppt](https://github.com/r00t-3xp10it/backdoorppt)
		* transform your payload.exe into one fake word doc (.ppt)
	* [malicious_file_maker](https://github.com/carnal0wnage/malicious_file_maker)
		* malicious file maker/sender to create and send malicious attachments to test your email filter/alerting
	* [VBA ScriptControl to run Java Script Function](https://www.experts-exchange.com/questions/28190006/VBA-ScriptControl-to-run-Java-Script-Function.html)
	* [CVE-2018-8420 | MS XML Remote Code Execution Vulnerability - portal.msrc.ms](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8420)
	* [Microsoft Windows MSHTML Engine - 'Edit' Remote Code Execution/CVE:2019-0541](https://www.exploit-db.com/exploits/46536)
	* [Abusing native Windows functions for shellcode execution - ropgadget](http://ropgadget.com/posts/abusing_win_functions.html)
	* [docem](https://github.com/whitel1st/docem)
		* Uility to embed XXE and XSS payloads in docx,odt,pptx,etc (OXML_XEE on steroids) 
* **Recon**
	* [hackability](https://github.com/PortSwigger/hackability)
		* Rendering Engine Hackability Probe performs a variety of tests to discover what the unknown rendering engine supports. To use it simply extract it to your web server and visit the url in the rendering engine you want to test. The more successful probes you get the more likely the target engine is vulnerable to attack.
	* [Image-Cache-Logger](https://github.com/kale/image-cache-logger)
		* A simple tool to see when other services/clients like Gmail open an image and test if they are storing it within their cache.
* **SMTP Server**
	* [Papercut](https://github.com/changemakerstudios/papercut)
		* Simple Desktop SMTP Server
* **User Profiling**
	* [DeviceDetector.NET](https://github.com/totpero/DeviceDetector.NET)
		* The Universal Device Detection library will parse any User Agent and detect the browser, operating system, device used (desktop, tablet, mobile, tv, cars, console, etc.), brand and model.























------------------
### <a name="msoutlook"></a>Microsoft Outlook/Exchange Stuff/Office 365
* **General**
	* [Outlook Home Page - Another Ruler Vector](https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/)
	* [Outlook Forms and Shells](https://sensepost.com/blog/2017/outlook-forms-and-shells/)
	* [Exchange Versions, Builds & Dates](https://eightwone.com/references/versions-builds-dates/)
	* [Microsoft Support and Recovery Assistant for Office 365](https://testconnectivity.microsoft.com/)
	* [Elevating your security with Office 365 clients. - BRK3143](https://www.youtube.com/watch?v=BGpQ8S2-Oss&feature=youtu.be&t=372&app=desktop)
* **Articles/Blogposts/Writeups**
	* [Office 365 Vulnerable to Brute Force Attack via Powershell - Tyler(2018)](https://cssi.us/office-365-brute-force-powershell/)
* **Bypass**
	* [How to bypass Web-Proxy Filtering](https://www.blackhillsinfosec.com/?p=5831)
* **Hiding Inbox Rules in O365**
	* [O365: Hidden InboxRules - Matthew Green(2019)](https://mgreen27.github.io/posts/2019/06/09/O365HiddenRules.html)
		* "In this post Im going to talk about Office365 hidden inbox rules. Im going to give some background, show rule modification, and talk about detection methodology."
	* [Hidden Inbox Rules in Microsoft Exchange - Damian Pfammatter(2020)](https://blog.compass-security.com/2018/09/hidden-inbox-rules-in-microsoft-exchange/)
* **Outlook Rules**
	* [Malicious Outlook Rules(2015) - Nick Landers](https://silentbreaksecurity.com/malicious-outlook-rules/)
	* [EXE-less Malicious Outlook Rules - BHIS](https://www.blackhillsinfosec.com/?p=5544)
* **Talks & Presentations**
	* [Outlook and Exchange for the Bad Guys - Nick Landers(Derbycon6)](https://www.youtube.com/watch?v=cVhc9VOK5MY)
* **Tools**
	* [MailRaider](https://github.com/xorrior/EmailRaider)
	* [Phishery](https://github.com/ryhanson/phishery)
		* An SSL Enabled Basic Auth Credential Harvester with a Word Document Template URL Injector		* MailRaider is a tool that can be used to browse/search a user's Outlook folders as well as send phishing emails internally using their Outlook client.
	* [PyEWS Documentation](https://py-ews.readthedocs.io/en/latest/)
	* [o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit)
		* [Introducing the Office 365 Attack Toolkit - MDSec](https://www.mdsec.co.uk/2019/07/introducing-the-office-365-attack-toolkit/)




















------------------
### <a name="msoffice"></a>MS Office
* **General**<a name="gms"></a>
	* **Articles/Blogposts/Writeups**
		* [VB2018 paper: Office bugs on the rise - Gabor Szappanos](https://www.virusbulletin.com/virusbulletin/2018/12/vb2018-paper-office-bugs-rise/)
		* [Next Gen Office Malware v2.0 - Greg Linares Dagmar Knechtel - Hushcon17](https://prezi.com/view/eZ3CSNMxPMOfIWEHwTje/)
		* [Office Document Macros, OLE, Actions, DDE Payloads and Filter Bypass - Pwndizzle](https://pwndizzle.blogspot.com.es/2017/03/office-document-macros-ole-actions-dde.html)
		* [Analysis of the Attack Surface of Microsoft Office from a User's Perspective](https://0b3dcaf9-a-62cb3a1a-s-sites.googlegroups.com/site/zerodayresearch/Analysis_of_the_Attack_Surface_of_Microsoft_Office_from_User_Perspective_final.pdf)
		* [Document Tracking: What You Should Know - justhaifei1](https://justhaifei1.blogspot.com/2013/10/document-tracking-what-you-should-know.html)
		* [Office Document Macros, OLE, Actions, DDE Payloads and Filter Bypass - PwnDizzle](https://pwndizzle.blogspot.com/2017/03/office-document-macros-ole-actions-dde.html)
		* [Persisting with Microsoft Office: Abusing Extensibility Options - William Knowles](https://labs.mwrinfosecurity.com/assets/BlogFiles/WilliamKnowles-MWR-44con-PersistingWithMicrosoftOffice.pdf)
		* [office-exploit-case-study](https://github.com/houjingyi233/office-exploit-case-study)
			* I collect some office vuln recent years.Many samples are malware used in the real world,please study them in virtual machine.Take responsibility yourself if you use them for illegal purposes. Samples should match hash in corresponding paper if mentioned.
			* [Next Gen Office Malware v2.0 - Greg Linares Dagmar Knechtel - Hushcon17](https://prezi.com/view/eZ3CSNMxPMOfIWEHwTje/)
			* [Next Gen Office Malware Repo](https://github.com/glinares/OfficeMalware)
	* **Inbuilt Functions**
		* [Variable Object (Word) - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Word-VBA/articles/variable-object-word)
		* [Using ScriptControl Methods - docs.ms](https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-6.0/aa227637(v=vs.60))
			* The ScriptControl contains methods to execute code, add code and objects to the scripting engine, and reset the scripting engine to its initial state.
	* **Access**
		* [Phishing for â€œAccessâ€ - Changing Phishing Tactics Require Closer User and Defender Attention - Steve Borosh](https://medium.com/rvrsh3ll/phishing-for-access-554105b0901e)
		* [MAccess - Bypassing Office macro warnings - kaiosec](https://kaiosec.com/blog/maccess.html)
		* [Changing Phishing Tactics Require Closer User and Defender Attention - nuix.com](https://www.nuix.com/blog/changing-phishing-tactics-require-closer-user-and-defender-attention)
	* **Excel**
		* **Articles/Blogposts/Writeups**
			* [When Scriptlets Attack: Excelâ€™s Alternative to DDE Code Execution - David Wells](https://www.lastline.com/labsblog/when-scriptlets-attack-excels-alternative-to-dde-code-execution/)
			* [Malicious Excel DDE Execution with ML AV Bypass and Persistence - hyperiongray](https://blog.hyperiongray.com/excel-dde-exploitation-and-ml-av-bypass/)
			* [Insert an object in your Excel spreadsheet - support.office](https://support.office.com/en-us/article/Insert-an-object-in-your-Excel-spreadsheet-e73867b2-2988-4116-8d85-f5769ea435ba)
		* **Talks & Presentations**
			* [Tricks to Improve Web App Excel Export Attacks - Jerome Smith(CAMSEC)](https://www.youtube.com/watch?v=3wNvxRCJLQQ)
				* This presentation is an embellished version of the second half of a talk originally presented at BSides MCR 2016. It covers more general web app export issues as well as revisions on the DDE content following feedback from BSides.
			* [Slides](https://www.slideshare.net/exploresecurity/camsec-sept-2016-tricks-to-improve-web-app-excel-export-attacks)
		* **Tools**
			* [Excel-DNA](https://excel-dna.net/)
				* Excel-DNA is an independent project to integrate .NET into Excel. With Excel-DNA you can make native (.xll) add-ins for Excel using C#, Visual Basic.NET or F#, providing high-performance user-defined functions (UDFs), custom ribbon interfaces and more. Your entire add-in can be packed into a single .xll file requiring no installation or registration.
	* **EXD Files**
		* [EXD: An attack surface for Microsoft Office](https://www.fortinet.com/blog/threat-research/exd-an-attack-surface-for-microsoft-office.html)
			* Fortinet has discovered a potential attack surface for Microsoft office via EXD file. After a malformed or specifically crafted EXD file was placed in an expected location, it could trigger a remote code execution when a document with ActiveX is opened with office applications.
	* **NTLM Hashes**
		* [ Microsoft Office - NTLM Hashes via Frameset - pentestlab.blog(2017)](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)
		* [UNC Path Injection with Microsoft Access - Stephan Borosh](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/unc-path-injection-with-microsoft-access/)
		* [10 Places to Stick Your UNC Path - Karl Fossan](https://blog.netspi.com/10-places-to-stick-your-unc-path/)
		* [NTLM Credential Theft via malicious ODT Files - rmdavy.uk(2018)](https://secureyourit.co.uk/wp/2018/05/01/creating-malicious-odt-files/)
		* [Leaking Windows Creds Externally Via MS Office - Tradecraft Security Weekly #21](https://www.youtube.com/watch?v=40Ume_kbsIE)
			* In this episode of Tradecraft Security Weekly, Mike Felch discusses with Beau Bullock about the possibilities of using framesets in MS Office documents to send Windows password hashes remotely across the Internet. This technique has the ability to bypass many common security controls so add it to your red team toolboxes.
		* [WordSteal](https://github.com/0x09AL/WordSteal)
			* This script will create a POC that will steal NTML hashes from a remote computer. Do not use this for illegal purposes.The author does not keep responsibility for any illegal action you do. Microsoft Word has the ability to include images from remote locations.This is an undocumented feature but was found used by malware creators to include images through http for statistics.We can also include remote files to a SMB server and the victim will authenticate with his logins credentials.
	* **PowerPoint**
		* [Phishing with PowerPoint - BHIS](https://www.blackhillsinfosec.com/phishing-with-powerpoint/)
		* [PowerPoint and Custom Actions - Sean Wilson](https://cofense.com/powerpoint-and-custom-actions/)
	* **OSX**
		* [Sylk + XLM = Code execution on Office 2011 for Mac - Pieter Celeen](https://outflank.nl/blog/2018/10/12/sylk-xlm-code-execution-on-office-2011-for-mac/)
		* [Phishing: .SLK Excel - @spottheplanet](https://ired.team/offensive-security/initial-access/phishing-with-ms-office/phishing-.slk-excel)
* **DDE**<a name="gdde"></a>
	* **101**
		* [Disable DDEAUTO for Outlook, Word, OneNote, and Excel versions 2010, 2013, 2016](https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b)
	* **Blogposts/Writeups**
		* [Exploiting Office native functionality: Word DDE edition](https://www.securityforrealpeople.com/2017/10/exploiting-office-native-functionality.html)
		* [Excel DDE Walkthrough](https://github.com/merrillmatt011/Excel_DDE_Walkthrough/blob/master/Excel_DDE_Walkthrough.pdf)
		* [Macro-less Code Exec in MSWord -  Etienne Stalmans, Saif El-Sherei](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
		* [The Current State of DDE - Office DDE Attacks from an Offensive and Defensive Perspective - @0xdeadbeefJERKY](https://medium.com/@0xdeadbeefJERKY/the-current-state-of-dde-a62fd3277e9)
		* [ Microsoft Office - DDE Attacks - pentestlab.blog](https://pentestlab.blog/2018/01/16/microsoft-office-dde-attacks/)
		* [ Microsoft Office Ã¢â‚¬â€œ DDE Attacks - pentestlab.blog](https://pentestlab.blog/2018/01/16/microsoft-office-dde-attacks/)
		* [Abusing Microsoft Office DDE - SecuritySift](https://www.securitysift.com/abusing-microsoft-office-dde/)
		* [PowerShell, C-Sharp and DDE The Power Within](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
			* aka Exploiting MS16-032 via Excel DDE without macros.
		* [Macroless DOC malware that avoids detection with Yara rule - Furoner.CAT](https://furoner.wordpress.com/2017/10/17/macroless-malware-that-avoids-detection-with-yara-rule/)
		* [PowerShell, C-Sharp and DDE The Power Within - sensepost](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
		* [Microsoft Office - DDE Attacks - pentestlab.blog](https://pentestlab.blog/2018/01/16/microsoft-office-dde-attacks/)
		* [Abusing Microsoft Office DDE - SecuritySift](https://www.securitysift.com/abusing-microsoft-office-dde/)
		* [Malicious Excel DDE Execution with ML AV Bypass and Persistence - hyperiongray](https://blog.hyperiongray.com/excel-dde-exploitation-and-ml-av-bypass/)
		* [Abusing Microsoft Office DDE - Mike Czumak](https://www.securitysift.com/abusing-microsoft-office-dde/)
		* [The Current State of DDE - Office DDE Attacks from an Offensive and Defensive Perspective - @0xdeadbeefJERKY](https://medium.com/@0xdeadbeefJERKY/the-current-state-of-dde-a62fd3277e9)
		* [The Current State of DDE - 0xdeadbeefjerky(2018/1)](https://0xdeadbeefjerky.github.io/2018/01/29/state-of-dde.html)
		* [PowerShell, C-Sharp and DDE The Power Within - sensepost(2016)](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
		* [DDE Downloaders, Excel Abuse, and a PowerShell Backdoor - James Haughom Jr(2018)](https://rinseandrepeatanalysis.blogspot.com/2018/09/dde-downloaders-excel-abuse-and.html)
	* **Payload Creation/Generation**
		* [DDE Payloads - Panagiotis Gkatziroulis](https://medium.com/red-team/dde-payloads-16629f4a2fcd)
		* [Office-DDE-Payloads - 0xdeadbeefJERKY](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads)
			* Collection of scripts and templates to generate Word and Excel documents embedded with the DDE, macro-less command execution technique described by @\_staaldraad and @0x5A1F (blog post link in References section below). Intended for use during sanctioned red team engagements and/or phishing campaigns.
		* [CACTUSTORCH_DDEAUTO](https://github.com/xillwillx/CACTUSTORCH_DDEAUTO)
			* OFFICE DDEAUTO Payload Generation script to automatically create a .vbs/.hta/.js payload for use inside a Microsoft Office document. Will create the DDEAUTO function to download and execute your payload using powershell or mshta that you can paste inside a Word document. That function can also be copy and pasted from Word to trigger in One Note/Outlook email/Outlook Calendar/Outlook Task. 
		* [Office DDEAUTO attacks - Will Genovese](http://willgenovese.com/office-ddeauto-attacks/)
	* **Payload Obfuscation**
		* [MSWord - Obfuscation with Field Codes - Staaldraad](https://staaldraad.github.io/2017/10/23/msword-field-codes/)
		* [Malicious Excel DDE Execution with ML AV Bypass and Persistence - hyperiongray.com](https://blog.hyperiongray.com/excel-dde-exploitation-and-ml-av-bypass/)
		* [Three New DDE Obfuscation Methods - reversinglabs.com](https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation)
* **DLL**<a name="gdll"></a>
	* [DLL Tricks with VBA to Improve Offensive Macro Capability](https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/)
	* [DLL Execution via Excel.Application RegisterXLL() method](https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52)
		* A DLL can be loaded and executed via Excel by initializing the Excel.Application COM object and passing a DLL to the RegisterXLL method. The DLL path does not need to be local, it can also be a UNC path that points to a remote WebDAV server.
	* [ExcelDllLoader](https://github.com/3gstudent/ExcelDllLoader)
		* Execute DLL via the Excel.Application object's RegisterXLL() method
* **Embeds**<a name="gembed"></a>
	* [Abusing Microsoft Office Online Video(2018) - Avihai Ben-Yossef](https://blog.cymulate.com/abusing-microsoft-office-online-video)
* **Exploits**<a name="gexploit"></a>
	* [PowerShell, C-Sharp and DDE The Power Within](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
		* aka Exploiting MS16-032 via Excel DDE without macros.
	* [Exploiting CVE-2017-0199: HTA Handler Vulnerability](https://www.mdsec.co.uk/2017/04/exploiting-cve-2017-0199-hta-handler-vulnerability/)
	* [CVE-2017-0199 Toolkit](https://github.com/bhdresh/CVE-2017-0199)
	* [CVE-2017-0199: In the Wild Attacks Leveraging HTA Handler - Fireeye](https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html)
	* [CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199)
		* Exploit toolkit CVE-2017-0199 - v4.0 is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft Office RCE. It could generate a malicious RTF/PPSX file and deliver metasploit / meterpreter / other payload to victim without any complex configuration.
	* CVE-2017-11882
		* [CVE-2017-11882 - Office RCE](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11882)
		* [Analysis of CVE-2017-11882 Exploit in the Wild - Yanhui Jia](https://unit42.paloaltonetworks.com/unit42-analysis-of-cve-2017-11882-exploit-in-the-wild/)
		* [webdav_exec CVE-2017-11882](https://github.com/embedi/CVE-2017-11882)
		* [Skeleton in the closet. MS Office vulnerability you didn't know about - Embedi](https://embedi.org/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about/)
* **Excel**
* **Excel DDE PowerQuery**<a name="gpq"></a>
	* [The Complete Guide to Power Query - howtoexcel.com](https://www.howtoexcel.org/power-query/the-complete-guide-to-power-query/)
	* [Exploit Using Microsoft Excel Power Query for Remote DDE Execution Discovered - Doron Attias](https://www.mimecast.com/blog/2019/06/exploit-using-microsoft-excel-power-query-for-remote-dde-execution-discovered/)
	* [More Excel 4.0 Macro MalSpam Campaigns - Diana Lopera(2020](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/more-excel-4-0-macro-malspam-campaigns/)more-excel-4-0-macro-malspam-campaigns/
* **Field Codes**<a name="gfield"></a>
	* [MSWord - Obfuscation with Field Codes - Staaldraad](https://staaldraad.github.io/2017/10/23/msword-field-codes/)
	* [MS Office In Wonderland - Stan Hegt & Pieter Ceelen(BH Asia2019)](https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Hegt-MS-Office-in-Wonderland.pdf)
	* [MS Word field abuse(2019) - Pieter Celeen](https://outflank.nl/blog/2019/04/02/ms-word-field-abuse/)
	* [Detecting and Protecting Against Word Field Code Abuse - Mark E. Soderlund(2003)](https://www.giac.org/paper/gsec/2624/detecting-protecting-word-field-code-abuse/104497)
* **InfoPath**<a name="ginfo"></a>
	* [THE {PHISHING} {PATH} TO {INFO} WE MISSED](http://blog.obscuritylabs.com/the-phishing-path-to-info-we-missed/)
		* TL;DR: InfoPath is a fantastic way to run custom C# code, and we missed it as an attack vector sadly. At the moment it has been deprecated, but don't fret it's still everywhere!
	* [Resources for learning InfoPath - support.office.com](https://support.office.com/en-ie/article/Resources-for-learning-InfoPath-40227252-43A7-4E7A-97C6-29EC4B7E7B93)
	* [InfoPhish](https://github.com/InfoPhish/InfoPhish)
* **LoL**<a name="glol"></a>
	* [Unsanitized file validation leads to Malicious payload download via Office binaries. - Reegun](https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191)
* **Macros**<a name="macros"></a>
	* **101**<a name="m101"></a>
		* [Fundamentals of Malicious Word Macros - hunnicyber](https://blog.hunniccyber.com/word-macro-to-connect-back-to-cobalt-strike-teamserver-via-a-staging-server-basic/)
		* [Variable Object (Word) - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Word-VBA/articles/variable-object-word)
		* [CallByName Function - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Language-Reference-VBA/articles/callbyname-function)
			* Executes a method of an object, or sets or returns a property of an object. Syntax `CallByName( object, procname, calltype,[args()])`
		* [Intro to Macros and VBA for Script Kiddies - Adam Todd(2020)](https://www.trustedsec.com/blog/intro-to-macros-and-vba-for-script-kiddies/)
		* [The VBA Language for Script Kiddies - Adam Todd(2020)](https://www.trustedsec.com/blog/the-vba-language-for-script-kiddies/)
		* [Developing with VBA for Script Kiddies - Adam Todd(2020)](https://www.trustedsec.com/blog/developing-with-vba-for-script-kiddies/)
		* [VBA Macros: Events Cheat-Sheet](https://github.com/BrunoMCBraga/VBA-Macros-Events-Cheat-Sheet)
			* Cheat-Sheet with events to look out for when analysing malicious Office documents. It is focused on Excel and Word since these are the most common ways to distribute malware.
	* **Articles/Blogposts/Writeups**<a name="mart"></a>
		* [bpmtk: Bypassing SRP with DLL Restrictions - Didier Stevens(2008)](https://blog.didierstevens.com/2008/06/25/bpmtk-bypassing-srp-with-dll-restrictions/)
		* [Excel Exercises in Style - Didier Stevens(2008)](https://blog.didierstevens.com/2008/10/23/excel-exercises-in-style/)
		* [Shellcode 2 VBScript - Didier Stevens(2009)](https://blog.didierstevens.com/2009/05/06/shellcode-2-vbscript/)
		* [Using Excel 4 Macro Functions - ExcelofftheGrid(2017)](https://exceloffthegrid.com/using-excel-4-macro-functions/)
		* [How To: Empire - Cross Platform Office Macro](https://www.blackhillsinfosec.com/empires-cross-platform-office-macro/)
		* [Excel macros with PowerShell](https://4sysops.com/archives/excel-macros-with-powershell/)
		* [Multi-Platform Macro Phishing Payloads](https://medium.com/@malcomvetter/multi-platform-macro-phishing-payloads-3b688e8eff68)
		* [Abusing native Windows functions for shellcode execution - ropgadget](http://ropgadget.com/posts/abusing_win_functions.html)
		* [Microsoft Office - Payloads in Document Properties - pentestlab.blog](https://pentestlab.blog/2017/12/15/microsoft-office-payloads-in-document-properties/)
		* [Pesky Old-Style Macro Popups — Advanced Maldoc Techniques - Carrie Roberts(2019)](https://medium.com/walmartlabs/pesky-old-style-macro-popups-advanced-maldoc-techniques-8868ed02d845)
		* [MAccess: Bypassing Office macro warnings - kaiosec](https://kaiosec.com/blog/maccess.html)
		* [Powershell Empire Stagers 1: Phishing with an Office Macro and Evading AVs - fzuckerman](https://fzuckerman.wordpress.com/2016/10/06/powershell-empire-stagers-1-phishing-with-an-office-macro-and-evading-avs/)
		* [Zero2Auto - Initial Stagers - From one Email to a Trojan - Danus(2020)](https://web.archive.org/web/20200628032136/https://0x00sec.org/t/zero2auto-initial-stagers-from-one-email-to-a-trojan/21722)
		* [VBA Macros Pest Control - Philippe Lagadec](https://www.decalage.info/files/THC17_Lagadec_Macro_Pest_Control2.pdf)
		* [Luckystrike: An Evil Office Document Generator](https://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator)
		* [Microsoft Office - Payloads in Document Properties - pentestlab.blog](https://pentestlab.blog/2017/12/15/microsoft-office-payloads-in-document-properties/)
			* Document properties in Microsoft office usually contain information related to the document and various other metadata details. However this location can be used to store commands that will execute payloads that are hosted on an SMB or HTTP server.
		* [VBA RunPE - Breaking Out of Highly Constrained Desktop Environments - Part 1/2 - itm4n(2018)](https://itm4n.github.io/vba-runpe-part1/)
			* [Part 2](https://itm4n.github.io/vba-runpe-part2/)
	* **ActiveX**<a name="max"></a>
		* [Having Fun with ActiveX Controls in Microsoft Word - Marcello Salvati](https://www.blackhillsinfosec.com/having-fun-with-activex-controls-in-microsoft-word/)
		* [Running Macros via ActiveX Controls - Parvez](https://www.greyhathacker.net/?p=948)
		* [Alternative Execution: A Macro Saga (part 1) - Jerry Odegaard(2020)](https://whiteoaksecurity.com/blog/2020/3/11/alternative-execution-a-macro-saga-part-1)
    		* "In this blog post we examined a non-standard Office event trigger to execute VBA macro code by usage of an embedded ActiveX control: InkPicture. Originally the InkPicture.Painted() event handler was used by cyber criminals to evade antivirus prevention of the more common Document_Open() and Workbook_Open() event handlers associated with Microsoft Word and Excel. We’ve repurposed it for demonstration and went further to identify an additional InkPicture event handler that could be used as an alternative: InkPicture.Painting()."
		* [Part 2](https://whiteoaksecurity.com/blog/2020/3/17/alternative-execution-a-macro-saga-part-2)
			* "In this blog we covered abuse of the Windows Media Player ActiveX control to trigger macro execution at the point in which a maldoc is opened. We identified and implemented reference code for three event handlers that can be used without specifying a valid media file for Windows Media Player to load. These methods of executing malicious VBA code do not depend on the Document_Open() or Workbook_Open() event handlers that are more commonly utilized by malicious actors to obtain code execution."
		* [Part 3](https://whiteoaksecurity.com/blog/2020/3/26/alternative-execution-a-macro-saga-part-3)
			* "In this blog we spent the time and energy to craft another maldoc making use of an unconventional automatic execution method: The System Monitor ActiveX control. We also worked through the process I had used initially with both Windows Media Player and System Monitor by making use of the oleviewdotnet tool to enumerate and research the COM classes associated with these controls. Again, we’ve been able to demonstrate executing VBA code that doesn’t depend on Document_Open() or Workbook_Open() event handlers that are common with maldocs to obtain automatic execution on target systems."
	* **Execution**<a name="mex"></a>
		* [CallByName Function - docs.ms](https://docs.microsoft.com/en-us/office/vba/Language/Reference/User-Interface-Help/callbyname-function)
		* [CallByName Function - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Language-Reference-VBA/articles/callbyname-function)
			* Executes a method of an object, or sets or returns a property of an object. SyntaxCallByName( object, procname, calltype,[args()])
		* [Abusing native Windows functions for shellcode execution - ropgadget](http://ropgadget.com/posts/abusing_win_functions.html)
		* [Direct shellcode execution in MS Office macros - scriptjunkie.us](https://www.scriptjunkie.us/2012/01/direct-shellcode-execution-in-ms-office-macros/)
		* [VBA ScriptControl to run Java Script Function](https://www.experts-exchange.com/questions/28190006/VBA-ScriptControl-to-run-Java-Script-Function.html)
		* [trigen](https://github.com/karttoon/trigen)
			* Trigen is a Python script which uses different combinations of Win32 function calls in generated VBA to execute shellcode.
	* **Evasion**<a name="mev"></a>
		* **Articles/Blogposts/Writeups**	
			* [I Think You Have the Wrong Number: Using Errant Callbacks to Enumerate and Evade Outlook's Sandbox - CX01N(2020)](https://www.bc-security.org/post/i-think-you-have-the-wrong-number-using-errant-callbacks-to-enumerate-and-evade-outlook-s-sandbox/)
			* [Bypassing AMSI for VBA - Pieter Ceelen(2019)](https://outflank.nl/blog/2019/04/17/bypassing-amsi-for-vba/)
			* [Dynamic Microsoft Office 365 AMSI In Memory Bypass Using VBA - @rd_pentest(2019)](https://secureyourit.co.uk/wp/2019/05/10/dynamic-microsoft-office-365-amsi-in-memory-bypass-using-vba/)
			* [How to Build Obfuscated Macros for your Next Social Engineering Campaign - Michael Finkel(2019)](https://blog.focal-point.com/how-to-build-obfuscated-macros-for-your-next-social-engineering-campaign)
			* [Building an Office macro to spoof parent processes and command line arguments(2019) - Christophe Tafani-Dereeper](https://blog.christophetd.fr/building-an-office-macro-to-spoof-process-parent-and-command-line/)
			* [Playing Cat and Mouse: Three Techniques Abused to Avoid Detection - ZLAB-YOROI](https://blog.yoroi.company/research/playing-cat-and-mouse-three-techniques-abused-to-avoid-detection/)
			* [Phishing template uses fake fonts to decode content and evade detection - ProofPoint(2019)](https://www.proofpoint.com/us/threat-insight/post/phishing-template-uses-fake-fonts-decode-content-and-evade-detection)
			* [Bypassing Parent Child / Ancestry Detections - @spottheplanet](https://ired.team/offensive-security/initial-access/phishing-with-ms-office/bypassing-malicious-macro-detections-by-defeating-child-parent-process-relationships)
			* [Dechaining Macros and Evading EDR - Noora Hyvärinen(2019)](https://blog.f-secure.com/dechaining-macros-and-evading-edr/)
			* [Advanced VBA macros: bypassing olevba static analyses with 0 hits - Gabriele Pippi](https://www.certego.net/en/news/advanced-vba-macros/)
		* **Tools**
			* [spoofing-office-macro](https://github.com/christophetd/spoofing-office-macro)
				* PoC of a VBA macro spawning a process with a spoofed parent and command line. 
				* [Blogpost](https://blog.christophetd.fr/building-an-office-macro-to-spoof-process-parent-and-command-line)
			* [OfficeMacro64](https://github.com/py7hagoras/OfficeMacro64)
				* This is a 64 bit VBA implementation of Christophe Tafani-Dereeper's original VBA code described in his blog @ https://blog.christophetd.fr/building-an-office-macro-to-spoof-process-parent-and-command-line/
	* **Excel Specific / 4.0 Macros**<a name="excel"></a>
		* **101**
			* [Working with Excel 4.0 macros - support.ms](https://support.microsoft.com/en-us/office/working-with-excel-4-0-macros-ba8924d4-e157-4bb2-8d76-2c07ff02e0b8?ui=en-us&rs=en-us&ad=us)
			* [Old school: evil Excel 4.0 macros (XLM) - Stan Hegt(2018)](https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/)
			* [Working with Excel 4.0 macros - support.ms](https://support.microsoft.com/en-us/office/working-with-excel-4-0-macros-ba8924d4-e157-4bb2-8d76-2c07ff02e0b8?ui=en-us&rs=en-us&ad=us)
			* [Application.ExecuteExcel4Macro method (Excel) - docs.ms](https://docs.microsoft.com/en-us/office/vba/api/excel.application.executeexcel4macro)
			* [Microsoft Office Excel 97-2003 Binary File Format (.xls, BIFF8)](https://www.loc.gov/preservation/digital/formats/fdd/fdd000510.shtml)
		* **Articles/Blogposts/Writeups**
			* [Phishing: XLM / Macro 4.0 - @spottheplanet](https://ired.team/offensive-security/initial-access/phishing-with-ms-office/phishing-xlm-macro-4.0)
			* [Further Evasion in the Forgotten Corners of MS-XLS - malware.pizza(2020)](https://malware.pizza/2020/06/19/further-evasion-in-the-forgotten-corners-of-ms-xls/)
			* [Evolution of Excel 4.0 Macro Weaponization - James Haughom and Stefano Ortolani(2020)](https://www.lastline.com/labsblog/evolution-of-excel-4-0-macro-weaponization/)
			* [Macros and More with SharpShooter v2.0 - MDSec](https://www.mdsec.co.uk/2019/02/macros-and-more-with-sharpshooter-v2-0/)
			* [XLS -> VBS -> .NET - James Haughom(2020)](https://malwaredisciple.com/part-i-xls-vbs-net/)
			* [ZLoader 4.0 Macrosheets Evolution - William MacArthur, Amirreza Niakanlahiji, Pedram Amini](https://inquest.net/blog/2020/05/06/ZLoader-4.0-Macrosheets-)
			* [Extracting "Sneaky" Excel XLM Macros - Amirreza Niakanlahiji, Pedram Amini(2019)](https://inquest.net/blog/2019/01/29/Carving-Sneaky-XLM-Files)
			* [Getting Sneakier: Hidden Sheets, Data Connections, and XLM Macros - Amirreza Niakanlahiji, Pedram Amini(2020)](https://inquest.net/blog/2020/03/18/Getting-Sneakier-Hidden-Sheets-Data-Connections-and-XLM-Macros)
			* [More Excel 4.0 Macro MalSpam Campaigns - Diana Lopera(2020)](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/more-excel-4-0-macro-malspam-campaigns/)
			* [Sylk + XLM = Code execution on Office 2011 for Mac - Pieter Ceelen(2018)](https://outflank.nl/blog/2018/10/12/sylk-xlm-code-execution-on-office-2011-for-mac/)
			* [bypass endpoint with XLM weaponization - 0xsp](https://0xsp.com/offensive/bypass-endpoint-with-xlm-weaponization)
			* [Excel 4.0 Macro, Old but New! - Hoang Bui(2019)](https://medium.com/@fsx30/excel-4-0-macro-old-but-new-967071106be9)
			* [FlawedAmmyy RAT & Excel 4.0 Macros - Ryan Campbell](https://security-soup.net/flawedammyy-rat-excel-4-0-macros/)
			* [Phishing AMSI Bypass - christopherja.rocks(2020)](https://christopherja.rocks/posts/2020/02/phishing-amsi-bypass/)
		* **Talks/Presentations/Videos**
			* [Dynamic Analysis of Obfuscated Excel 4 Macros - mattifestation(2020)](https://www.youtube.com/watch?v=7FH6Gzm2dAQ)
		* **Tools**
			* [EXCELntDonut](https://github.com/FortyNorthSecurity/EXCELntDonut/)
				* EXCELntDonut is a XLM (Excel 4.0) macro generator. Start with C# source code (DLL or EXE) and end with a XLM (Excel 4.0) macro that will execute your code in memory. XLM (Excel 4.0) macros can be saved in .XLS files.
				* [Blogpost](https://fortynorthsecurity.com/blog/excelntdonut/)
			* [Macrome](https://github.com/michaelweber/Macrome)
				* An Excel Macro Document Reader/Writer for Red Teamers & Analysts. Blog posts describing what this tool actually does can be found [here](https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/) and [here](https://malware.pizza/2020/06/18/further-evasion-in-the-forgotten-corners-of-ms-xls/).
			* [genxlm](https://github.com/med0x2e/genxlm)
				* Just a simple script to generate JScript code for calling Win32 API functions using XLM/Excel 4.0 macros via Excel.Application COM object and "ExecuteExcel4Macro" method. The script will generate a simple payload for performing a very basic shellcode injection by calling VirtualAlloc -> WriteProcessMemory -> CreateThread (just a poc, better options can be considered.)
			* [XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator/)
				* XLMMacroDeobfuscator can be used to decode obfuscated XLM macros (also known as Excel 4.0 macros). It utilizes an internal XLM emulator to interpret the macros, without fully performing the code. It supports both xls, xlsm, and xlsb formats. It uses xlrd2, pyxlsb2 and its own parser to extract cells and other information from xls, xlsb and xlsm files, respectively.
		* **XLL**
			* [Hello World XLL](https://github.com/edparcell/HelloWorldXll)
				* This is a simple XLL, showing how to create an XLL from scratch.
			* [xllpoc](https://github.com/MoooKitty/xllpoc)
				* A small project that aggregates community knowledge for Excel XLL execution, via xlAutoOpen() or PROCESS_ATTACH.
	* **Keying**<a name="keying"></a>
		* **Articles/Blogposts/Writeups**
			* [VBA Macro with Environmental Keying and Encryption(2019) - Hunnic Cyber](https://blog.hunniccyber.com/vba-macro-with-environmental-keying-and-encryption/)
	* **macOS Specific**<a name="mmosx"></a>
		* [Escaping the Microsoft Office Sandbox: a faulty regex, allows malicious code to escape and persist](https://objective-see.com/blog/blog_0x35.html)
		* [Word to Your Mac - analyzing a malicious word document targeting macOS users - Patrick Wardle](https://objective-see.com/blog/blog_0x3A.html)
		* [New Attack, Old Tricksâ€º analyzing a malicious document with a mac-specific payload - Patrick Wardle](https://objective-see.com/blog/blog_0x17.html)
	* **Remote Template Injection**<a name="mrti"></a>
		* **101**
			* [Executing Macros From a DOCX With Remote Template Injection - redxorblue(2018)](http://blog.redxorblue.com/2018/07/executing-macros-from-docx-with-remote.html)
				* "In this post, I want to talk about and show off a code execution method which was shown to me a little while back. This method allows one to create a DOCX document which will load up and allow a user to execute macros using a remote DOTM template file. [..] This blog post will detail how to use this method to download a macro-enabled template over HTTP(S) in a proxy-aware method into a DOCX document."
			* [Dynamic Office Template Injection - Joshua(2019)](https://sevrosecurity.com/2019/09/12/dynamic-office-template-injection-for-sandbox-bypass/)
			* [Template Injection Attacks - Bypassing Security Controls by Living off the Land - Brian Wiltse(SANS 2019)](https://www.sans.org/reading-room/whitepapers/intrusion/paper/38780)
		* **Articles/Blogposts/Writeups**
			* [Word template injection attack - Klion](https://developpaper.com/word-template-injection-attack/)
			* [VBA Macro Remote Template Injection With Unlinking & Self-Deletion - John Woodman(2019)](https://medium.com/@john.woodman11/vba-macro-remote-template-injection-with-unlinking-self-deletion-49aef5eec0cd)
			* [Word template injection attack - Klion](https://developpaper.com/word-template-injection-attack/)
			* [ Maldoc uses template injection for macro execution  - Josh Stroschein(2020)](https://0xevilc0de.com/maldoc-uses-template-injection-for-macro-execution/)
			* [Template Injection Attacks - Bypassing Security Controls by Living off the Land - Brian Wiltse(2020)](https://www.sans.org/reading-room/whitepapers/intrusion/paper/38780)
			* [Inject Macros from a Remote Dotm Template - @spottheplanet](https://ired.team/offensive-security/initial-access/phishing-with-ms-office/inject-macros-from-a-remote-dotm-template-docx-with-macros)
	* **VBA Stomp(ing)**<a name="mstomp"></a>
		* **101**
			* [VBA Stomp](https://vbastomp.com/)
		* **Articles/Blogposts/Writeups**
			* [VBA and P-code - Didier Stevens(2016)](https://isc.sans.edu/forums/diary/VBA+and+Pcode/21521/)
			* [Malicious VBA Office Document Without Source Code - Didier Stevens(2019)](https://isc.sans.edu/diary/Malicious+VBA+Office+Document+Without+Source+Code/24870)
			* [MS Office File Formats â€” Advanced Malicious Document (Maldoc) Techniques - Kirk Sayre, Harold Ogden, Carrie Roberts(2018)](https://medium.com/walmartlabs/ms-office-file-formats-advanced-malicious-document-maldoc-techniques-b5f948950fdf)
				* This post will discuss basic file formats used by MS Office and some of their implications. 
			* [Evasive VBA - Advanced Maldoc Techniques - Kirk Sayre, Harold Ogden, Carrie Roberts(2018)](https://medium.com/walmartlabs/evasive-vba-advanced-maldoc-techniques-1365e9373f80)
			* [VBA Stomping - Advanced Maldoc Techniques - Kirk Sayre, Harold Ogden, Carrie Roberts](https://medium.com/walmartlabs/vba-stomping-advanced-maldoc-techniques-612c484ab278)
			* [VBA Project Locked; Project is Unviewable - Carrie Roberts](https://medium.com/walmartlabs/vba-project-locked-project-is-unviewable-4d6a0b2e7cac)
			* [STOMP 2 DIS: Brilliance in the (Visual) Basics - Rick Cole, Andrew Moore, Genevieve Stark, Blaine Stancill](https://www.fireeye.com/blog/threat-research/2020/01/stomp-2-dis-brilliance-in-the-visual-basics.html)
			& 
			* [Evidence of VBA Purging Found in Malicious Documents](https://blog.nviso.eu/2020/02/25/evidence-of-vba-purging-found-in-malicious-documents/)
				* TL;DR We have found malicious Office documents containing VBA source code only, and no compiled code. Documents like these are more likely to evade anti-virus detection due to a technique we dubbed “VBA Purging”.
		* **Talks/Presentations/Videos**
			* [ VBA Stomping - Advanced Malware Techniques - Carrie Roberts, Kirk Sayre, Harold Ogden(Derbycon2018)](https://www.irongeek.com/i.php?page=videos/derbycon8/track-3-06-vba-stomping-advanced-malware-techniques-carrie-roberts-kirk-sayre-harold-ogden-)
				* [Slides](https://github.com/clr2of8/Presentations/blob/master/DerbyCon2018-VBAstomp-Final-WalmartRedact.pdf)
				* There are powerful malicious document generation techniques that are effective at bypassing anti-virus detection. A technique which we refer to as VBA stomping refers to destroying the VBA source code in a Microsoft Office document, leaving only a compiled version of the macro code known as p-code in the document file. Maldoc detection based only on the VBA source code fails in this scenario. Reverse engineering these documents presents significant challenges as well. In this talk we will demonstrate detailed examples of VBA stomping as well as introduce some additional techniques. Reverse engineering and defense tips will also be provided. 
			* [MS Office file format sorcery - Stan Hegt, Pieter Ceelen(TR19)](https://www.youtube.com/watch?v=iXvvQ5XML7g)
				* [Slides](https://github.com/outflanknl/Presentations/blob/master/Troopers19_MS_Office_file_format_sorcery.pdf)
				* A deep dive into file formats used in MS Office and how we can leverage these for offensive purposes. We will show how to fully weaponize ‘p-code’ across all MS Office versions in order to create malicious documents without using VBA code, successfully bypassing antivirus and other defensive measures.
			* [Advanced Malware VBA Stomping - presented by Carrie Roberts & Kirk Sayre(Sp4kCon2019)](https://www.youtube.com/watch?v=9hIWYtyO-eM)
				* [Slides](https://github.com/clr2of8/Presentations/blob/master/Sp4rkCon2019-VBAstomp.pdf)
				* There are powerful malicious document generation techniques that are effective at bypassing anti-virus detection. A technique which we call “VBA stomping” refers to destroying the VBA source code in a Microsoft Office document, leaving only a compiled version of the macro code known as p-code in the document file. Maldoc detection based only on the VBA source code fails in this scenario. Reverse engineering these documents presents significant challenges as well. Come find out what is new with VBA Stomping since our presentation on the topic last year.
			* [Advanced VBA Macros - Attack & Defense - Philippe Lagadec(BHEU2019](https://www.decalage.info/files/eu-19-Lagadec-Advanced-VBA-Macros-Attack-And-Defence.pdf)
		* **Tools**
			* [Example VBA Stomped Documents Repository](https://github.com/clr2of8/VBAstomp)
				* A repository of example VBA stomped documents. For more information about VBA Stomping, see vbastomp.com. These are non-malicious documents and the macro is a simple message box popup.
			* [olevba](https://github.com/decalage2/oletools/wiki/olevba)
				* olevba is a script to parse OLE and OpenXML files such as MS Office documents (e.g. Word, Excel), to detect VBA Macros, extract their source code in clear text, and detect security-related patterns such as auto-executable macros, suspicious VBA keywords used by malware, anti-sandboxing and anti-virtualization techniques, and potential IOCs (IP addresses, URLs, executable filenames, etc). It also detects and decodes several common obfuscation methods including Hex encoding, StrReverse, Base64, Dridex, VBA expressions, and extracts IOCs from decoded strings. XLM/Excel 4 Macros are also supported in Excel and SLK files.
			* [pcode2code.py](https://github.com/Big5-sec/pcode2code)
				* In 2019, EvilClippy tool made easily available for any attacker to dispose of an Office document where the macro code is transformed directly into bytecode. For any reference, please check this or this. To be able to analyze such "stomped" documents, Dr. Bontchev (@VessOnSecurity) released pcodedmp, a tool printing out the VBA bytecode of a document in a readable manner. However, the output might be still hardly readable and analyzable (please check out macaroni in tests folder). As such, pcode2code decompiles, based on pcodedmp's output, the VBA code.
			* [EvilClippy](https://github.com/outflanknl/EvilClippy)
				* A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows.
			* [Adaptive Document Builder (adb)](https://github.com/haroldogden/adb)
				* A framework for generating simulated malicious office documents.
			* [VBASeismograph](https://github.com/kirk-sayre-work/VBASeismograph)
				* tool for detecting VBA stomping. It has been developed and tested under Ubuntu 16.04.
			* [pcodedmp.py](https://github.com/bontchev/pcodedmp)
				*  A VBA p-code disassembler
	* **Tools**<a name="mtools"></a>
		* **Generators**
			* [unicorn](https://github.com/trustedsec/unicorn)
				* Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18.
			* [Pafish Macro](https://github.com/joesecurity/pafishmacro)
				* Pafish Macro is a Macro enabled Office Document to detect malware analysis systems and sandboxes. It uses evasion & detection techniques implemented by malicious documents.
			* [Malicious Macro Generator](https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator)
				* Simple utility design to generate obfuscated macro that also include a AV / Sandboxes escape mechanism.
			* [macphish](https://github.com/cldrn/macphish)
				* Office for Mac Macro Payload Generator 
			* [Generate Macro - Tool](https://github.com/enigma0x3/Generate-Macro)
			* [Generate MS Office Macro Malware Script](https://github.com/enigma0x3/Generate-Macro/blob/master/Generate-Macro.ps1)
				* Standalone Powershell script that will generate a malicious Microsoft Office document with a specified payload and persistence method
			* [Wepwnise](https://labs.mwrinfosecurity.com/tools/wepwnise/)
				* WePWNise is a proof-of-concept python script that generates architecture independent VBA code to be used in Office documents or templates. It aims in introducing a certain level of automation and intelligence to dynamically deliver its payload, circumventing defences such as application control and anti-exploitation mitigations that may exist on a target system.
			* [Malicious Macro MSBuild Generator](https://github.com/infosecn1nja/MaliciousMacroMSBuild)
				* Generates Malicious Macro and Execute Powershell or Shellcode via MSBuild Application Whitelisting Bypass.
			* [trigen](https://github.com/karttoon/trigen)
				* Trigen is a Python script which uses different combinations of Win32 function calls in generated VBA to execute shellcode.
			* [macro_pack](https://github.com/sevagas/macro_pack)
				* macro_pack is a tool by @EmericNasi used to automatize obfuscation and generation of MS Office documents for pentest, demo, and social engineering assessments. The goal of macro_pack is to simplify exploitation, antimalware bypass, and automatize the process from vba generation to final Office document generation.
			* [MacroCreator](https://github.com/Arno0x/PowerShellScripts/tree/master/MacroCreator)
				* Invoke-MacroCreator is a powershell Cmdlet that allows for the creation of an MS-Word document embedding a VBA macro with various payload delivery and execution capabilities.
		* **Samples**
			* [RobustPentestMacro](https://github.com/mgeeky/RobustPentestMacro)
				* This is a rich-featured Visual Basic macro code for use during Penetration Testing assignments, implementing various advanced post-exploitation techniques like sandbox evasion, WMI persistence and page substitution. Intended to be able to infect both Windows and Mac OS X Office platforms by implementing platform-detection logic.
			* [CVE-2017-8759-Exploit-sample](https://github.com/vysec/CVE-2017-8759-Exploit-sample)
				* Flow of the exploit: Word macro runs in the Doc1.doc file. The macro downloads a badly formatted txt file over wsdl, which triggers the WSDL parser log. Then the parsing log results in running mshta.exe which in turn runs a powershell commands that runs mspaint.exe
		* **Obfuscation**
			* [VBad](https://github.com/Pepitoh/VBad)
				* VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
			* [MacroShop](https://github.com/khr0x40sh/MacroShop)
				* Collection of scripts to aid in delivering payloads via Office Macros. Most are python.
* **OLE**<a name="ole"></a>
	* [Phishing with Empire](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
	* [Attacking Interoperability: An OLE Edition](https://www.blackhat.com/docs/us-15/materials/us-15-Li-Attacking-Interoperability-An-OLE-Edition.pdf)
	* [Microsoft Powerpoint as Malware Dropper - Marco Ramilli](https://marcoramilli.blogspot.com/2018/11/microsoft-powerpoint-as-malware-dropper.html)
	* [Office Document Macros, OLE, Actions, DDE Payloads and Filter Bypass - pwndizzle](http://pwndizzle.blogspot.com.es/2017/03/office-document-macros-ole-actions-dde.html)
	* [#OLEOutlook - bypass almost every Corporate security control with a pointâ€™nâ€™click GUI - Kevin Beaumont](https://doublepulsar.com/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0?gi=18b1f4a3ca13)
* **Online Video in MS Word**<a name="mov"></a>
	* [Abusing Microsoft Office Online Video - Avihai Ben-Yossef(2018)](https://blog.cymulate.com/abusing-microsoft-office-online-video)
	* [Phishing: Replacing Embedded Video with Bogus Payload - @spottheplanet](https://ired.team/offensive-security/initial-access/phishing-with-ms-office/phishing-replacing-embedded-video-with-bogus-payload)
* **PowerPoint Mouseover**<a name="ppm"></a>
	* [New PowerPoint Mouseover Based Downloader – Analysis Results - dodgethissecurity_1ooun4(2017)](https://www.dodgethissecurity.com/2017/06/02/new-powerpoint-mouseover-based-downloader-analysis-results/)
	* [PowerPoint File Downloads Malware When You Hover a Link, No Macros Required(2017)](https://www.bleepingcomputer.com/news/security/powerpoint-file-downloads-malware-when-you-hover-a-link-no-macros-required/)
	* [“Zusy” PowerPoint Malware Spreads Without Needing Macros - SentinelOne(2017](https://www.sentinelone.com/blog/zusy-powerpoint-malware-spreads-without-needing-macros/)
	* [Hover_with_Power - Mandar Satam](https://github.com/ethanhunnt/Hover_with_Power)
* **Protected View**<a name="mpv"></a>
	* **101**
		* [What is Protected View? - support.office.com](https://support.office.com/en-us/article/What-is-Protected-View-d6f09ac7-e6b9-4495-8e43-2bbcdbcb6653)
	* **Articles/Blogposts/Writeups**
		* [Phishing against Protected View](https://enigma0x3.net/2017/07/13/phishing-against-protected-view/)
		* [Understanding The Microsft Office 2013 Protected-View Sandbox - Yong Chuan, Kho (2015)](https://labs.mwrinfosecurity.com/assets/BlogFiles/UNDERSTANDING-THE-MICROSOFT-OFFICE-2013-PROTECTED-VIEW-SANDBOX-WP3.pdf)
		* [Corrupting Memory In Microsoft Office Protected-View Sandbox - Yong Chuan Koh(MS BlueHat '17)](https://labs.f-secure.com/assets/BlogFiles/mwri-corrupting-memory-in-ms-office-protected-view-v2.pdf)
			* The MS Office Protected-View is unlike any other sandboxes; it aims to provide only a text-view of the document contents and therefore does not have to provide full functionalities of the application. As a result, the broker -sandbox Inter-Process Communication (IPC) attack surface is greatly reduced. However this does not mean there are no vulnerabilities. This talk discussed the methodology for fuzzing this IPC attack surface, from the test-case generation to the discovery and analysis of CVE-2017-8502 and CVE-2017-8692.
		* [Getting Malicious Office Documents to Fire with Protected View Enabled - Curtis Brazzell(2019)](https://medium.com/@curtbraz/getting-malicious-office-documents-to-fire-with-protected-view-4de18668c386)
* **subDoc**<a name="msubdoc"></a>
	* **101**
		* [SubDocumentReference class - msdn.ms](https://msdn.microsoft.com/en-us/library/office/documentformat.openxml.wordprocessing.subdocumentreference.aspx?cs-save-lang=1&cs-lang=vb#Syntax)
	* **Articles/Blogposts/Writeups**
		* [Abusing Microsoft Word Features for Phishing: subdoc](https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc/)
* **Temporary File Drop**<a name="tnf"></a>
	* [Demonstration of the Windows/Office "Insecure Temporary File Dropping" Vulnerability - justhaifeil](https://justhaifei1.blogspot.com/2014/08/demonstration-of-windowsoffice-insecure.html)
* **TNEF**
	* [Transport Neutral Encapsulation Format - Wikipedia](https://en.wikipedia.org/wiki/Transport_Neutral_Encapsulation_Format)














------------------
### Setting up a Server
* [Mail Servers Made Easy - Inspired-Sec](https://blog.inspired-sec.com/archive/2017/02/14/Mail-Server-Setup.html)
* [Postfix-Server-Setup](https://github.com/n0pe-sled/Postfix-Server-Setup)
	* "Setting up a phishing server is a very long and tedious process. It can take hours to setup, and can be compromised in minutes. The esteemed gentlemen @cptjesus and @Killswitch_GUI have already made leaps and bounds in this arena. I took everything that I learned from them on setting up a server, and applied it to a bash script to automate the process.""



