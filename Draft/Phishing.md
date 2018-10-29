# Phishing

## Table of Contents
* [General](#general)
* [Phishing Frameworks](#framework)
* [Tools](#tools)
* [Microsoft Outlook/Exchange Related](#msoutlook)
* [Microsoft Office](#msoffice)
- [Setting up a Server](#settingup)
* [Talks/Presentations](#talks)




------------------
### <a name="general">General</a>
* **General**
	* [Phishing - wikipedia](http://www.en.wikipedia.org/wiki/Phishing):
		* “Phishing is the attempt to acquire sensitive information such as usernames, passwords, and credit card details (and sometimes, indirectly, money) by masquerading as a trustworthy entity in an electronic communication.”
	* [Phishing with Maldocs](https://www.n00py.io/2017/04/phishing-with-maldocs/)
	* [Post exploitation trick - Phish users for creds on domains, from their own box](https://enigma0x3.wordpress.com/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
	* [iOS Privacy: steal.password - Easily get the user's Apple ID password, just by asking](https://krausefx.com/blog/ios-privacy-stealpassword-easily-get-the-users-apple-id-password-just-by-asking)
	* [Phishing for Funds: Understanding Business Email Compromise - Keith Turpin - BH Asia2017](https://www.youtube.com/watch?v=_gk4i33lriY&list=PLH15HpR5qRsWx4qw9ZlgmisHOcKG4ZcRS&index=11)
		* Business Email Compromise (aka CEO fraud) is a rapidly expanding cybercrime in which reported cases jumped 1300% from 2015 to 2016. This financial fraud scheme can target any market segment or organization regardless of size. Thousands of organizations from more than 100 countries have reported losses. The reasons for this surge is simple - it makes money. 
		* [Slides](https://www.blackhat.com/docs/asia-17/materials/asia-17-Turpin-Phishing-For-Funds-Understanding-Business-Email-Compromise.pdf)
* **Articles/Blogposts**
	* [Best Time to send email](https://coschedule.com/blog/best-time-to-send-email/)
	* [Top 10 Email Subjects for Company Phishing Attacks](http://www.pandasecurity.com/mediacenter/security/top-10-email-subjects-phishing-attacks/)
	* [Some Tips for Legitimate Senders to Avoid False Positives - Apache SpamAssassin](https://wiki.apache.org/spamassassin/AvoidingFpsForSenders)
	* [Email Delivery – What Pen Testers Should Know - cs](https://blog.cobaltstrike.com/2013/10/03/email-delivery-what-pen-testers-should-know/)
	* [What’s the go-to phishing technique or exploit? - cs](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
	* [Phishing, Lateral Movement, SCADA, OH MY!](https://web.archive.org/web/20160408193653/http://www.idzer0.com/?p=210)
	* [Phishing with Empire - Enigma0x3](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
	* [Phishing for “Access” - rvrsh3ll's blog](http://www.rvrsh3ll.net/blog/phishing/phishing-for-access/)
	* [Cross-Site Phishing](http://blog.obscuritylabs.com/merging-web-apps-and-red-teams/)
	* [Email Notification on shell connectback MSF Plugin](https://hansesecure.de/howto-msf-email/)
		* [Code](https://github.com/HanseSecure/metasploit-modules)
* **Papers**
	* [Tab Napping - Phishing](http://www.exploit-db.com/papers/13950/)
	* [Skeleton in the closet. MS Office vulnerability you didn’t know about](https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about)
		* Microsoft Equation Editor Exploit writeup
	* [MetaPhish Paper](https://www.blackhat.com/presentations/bh-usa-09/SMITH_VAL/BHUSA09-Smith-MetaPhish-PAPER.pdf)
	* [MetaPhish - Defcon17](https://www.defcon.org/images/defcon-17/dc-17-presentations/Valsmith/defcon-17-valsmith-metaphish-wp.pdf)
* **Writeups**
	* [How do I phish? – Advanced Email Phishing Tactics - Pentest Geek](https://www.pentestgeek.com/2013/01/30/how-do-i-phish-advanced-email-phishing-tactics/)
	* [Real World Phishing Techniques - Honeynet Project](http://www.honeynet.org/book/export/html/89)
	* [Phishing with Maldocs - n00py](https://www.n00py.io/2017/04/phishing-with-maldocs/)
	* [Tabnabbing - An art of phishing - securelayer7](http://blog.securelayer7.net/tabnabbing-art-phishing/)
	* [Add-In Opportunities for Office Persistence](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)
		* This post will explore various opportunities for gaining persistence through native Microsoft Office functionality.  It was inspired by Kostas Lintovois’ similar work which identified ways to persist in transient Virtual Desktop Infrastructure (VDI) environments through adding a VBA backdoor to Office template files 
	* [One Template To Rule 'Em All](https://labs.mwrinfosecurity.com/publications/one-template-to-rule-em-all/)
		* This presentation discussed how Office security settings and templates can be abused to gain persistence in VDI implementations where traditional techniques relying on the file system or the Registry are not applicable. Additionally, it was described how the introduction of application control and anti-exploitation technologies may affect code execution in locked down environments and how these controls can be circumvented through the use of VBA.
	* [Spear Phishing 101 - inspired-sec.com](https://blog.inspired-sec.com/archive/2017/05/07/Phishing.html)
	* [There is a shell in your lunch-box by Rotimi Akinyele](https://hakin9.org/shell-lunch-box-rotimi-akinyele/)

----------
### <a name="documentation"> Documentation
* **Dynamic Data Exchange(DDE)**
	* [About Dynamic Data Exchange - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dataxchg/about-dynamic-data-exchange)
	* [Dynamic Data Exchange - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dataxchg/dynamic-data-exchange)
		* This section provides guidelines for implementing dynamic data exchange for applications that cannot use the Dynamic Data Exchange Management Library (DDEML). 
* **DomainKeys Identified Mail**
	* [DomainKeys Identified Mail - Wikipedia](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail)
* **Domain Message Authentication, Reporting, and Conformance - DMARC**
	* [DMARC - Wikipedia](https://en.wikipedia.org/wiki/DMARC)
	* [Domain-based Message Authentication, Reporting, and Conformance (DMARC) - RFC7489](https://tools.ietf.org/html/rfc7489)
* **HTA**
	* [HTML Application - Wikipedia](https://en.wikipedia.org/wiki/HTML_Application)
	* [Learn About Scripting for HTML Applications (HTAs) - technet.ms](https://technet.microsoft.com/en-us/scriptcenter/dd742317.aspx)
	* [Extreme Makeover: Wrap Your Scripts Up in a GUI Interface - technet.ms](https://technet.microsoft.com/en-us/library/ee692768.aspx)
* **Object Linking and Embedding**
	* [Object Linking and Embedding - Wikipedia](https://en.wikipedia.org/wiki/Object_Linking_and_Embedding)
	* [OLE - msdn.ms](https://msdn.microsoft.com/en-us/library/df267wkc.aspx)
	* [[MS-OLEDS]: Object Linking and Embedding (OLE) Data Structures - msdn.ms](https://msdn.microsoft.com/en-us/library/dd942265.aspx)
* **Sender Policy Framework - SPF**
	* [Sender Policy Framework - Wikipedia](https://en.wikipedia.org/wiki/Sender_Policy_Framework)
* **SMTP Strict Transport Security** 
	* [SMTP Strict Transport Security](https://lwn.net/Articles/684462/)
* **XLL**
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
* [TackleBox](https://github.com/trailofbits/tacklebox)
* [king-phisher](https://github.com/securestate/king-phisher)
	*  Phishing Campaign Toolkit
* [Mercure](https://github.com/synhack/mercure/)
	* Mercure is a tool for security managers who want to teach their colleagues about phishing.
* [Cartero](https://github.com/Section9Labs/Cartero)
	* Cartero is a modular project divided into commands that perform independent tasks (i.e. Mailer, Cloner, Listener, AdminConsole, etc...). In addition each sub-command has repeatable configuration options to configure and automate your work.
* [FiercePhish](https://github.com/Raikia/FiercePhish)
	* FiercePhish is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more
* [King Phisher](https://github.com/securestate/king-phisher)
	* King Phisher is a tool for testing and promoting user awareness by simulating real world phishing attacks. It features an easy to use, yet very flexible architecture allowing full control over both emails and server content. King Phisher can be used to run campaigns ranging from simple awareness training to more complicated scenarios in which user aware content is served for harvesting credentials.
* [SpeedPhish Framework](https://github.com/tatanus/SPF)
	* SPF (SpeedPhish Framework) is a python tool designed to allow for quick recon and deployment of simple social engineering phishing exercises.
* [CredSniper](https://github.com/ustayready/CredSniper)
	* CredSniper is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens. Easily launch a new phishing site fully presented with SSL and capture credentials along with 2FA tokens using CredSniper. The API provides secure access to the currently captured credentials which can be consumed by other applications using a randomly generated API token.
* [Ares](https://github.com/dutchcoders/ares)
	* Phishing toolkit for red teams and pentesters. Ares allows security testers to create a landing page easily, embedded within the original site. Ares acts as a proxy between the phised and original site, and allows (realtime) modifications and injects. All references to the original site are being rewritten to the new site. Users will use the site like they'll normally do, but every step will be recorded of influenced. Ares will work perfect with dns poisoning as well.
* [SocialFish](https://github.com/UndeadSec/SocialFish)
	* Easy phishing using socail media sites
* [ReelPhish: A Real-Time Two-Factor Phishing Tool](https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html)
* [ReelPhish](https://github.com/fireeye/ReelPhish)
	* Tool page
* [ReelPhish: A Real-Time Two-Factor Phishing Tool](https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html)
* [ReelPhish](https://github.com/fireeye/ReelPhish)
* [evilginx2](https://github.com/kgretzky/evilginx2)
	* evilginx2 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protection.


------------------
### <a name="tools"></a>Tools
* **Cloning**
	* [Cooper](https://github.com/chrismaddalena/Cooper)
		* Cooper simplifies the process of cloning a target website or email for use in a phishing campaign. Just find a URL or download the raw contents of an email you want to use and feed it to Cooper. Cooper will clone the content and then automatically prepare it for use in your campaign. Scripts, images, and CSS can be modified to use direct links instead of relative links, links are changed to point to your phishing server, and forms are updated to send data to you -- all in a matter of seconds. Cooper is cross-platform and should work with MacOS, Linux, and Windows.
* **Domains**
	* [CatMyFish](https://github.com/Mr-Un1k0d3r/CatMyFish)
		* Search for categorized domain that can be used during red teaming engagement. Perfect to setup whitelisted domain for your Cobalt Strike beacon C&C.  It relies on expireddomains.net to obtain a list of expired domains. The domain availability is validated using checkdomain.com
	* [CatPhish](https://github.com/ring0lab/catphish)
		* Generate similar-looking domains for phishing attacks. Check expired domains and their categorized domain status to evade proxy categorization. Whitelisted domains are perfect for your C2 servers.
* **Email Harvesting**
	* [PhishBait](https://github.com/hack1thu7ch/PhishBait)
		* Tools for harvesting email addresses for phishing attacks
	* [Email Address Harvesting for Phishing](http://www.shortbus.ninja/email-address-harvesting-for-phishing-attacks/)
* **Payloads**
	* [Demiguise](https://github.com/nccgroup/demiguise)
		* The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page, the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user.
	* [morphHTA - Morphing Cobalt Strike's evil.HTA](https://github.com/vysec/morphHTA)
	* [Social-Engineering-Payloads - t3ntman](https://github.com/t3ntman/Social-Engineering-Payloads)
	* [backdoorppt](https://github.com/r00t-3xp10it/backdoorppt)
		* transform your payload.exe into one fake word doc (.ppt)
	* [EmbedInHTML](https://github.com/Arno0x/EmbedInHTML)
		* What this tool does is taking a file (any type of file), encrypt it, and embed it into an HTML file as ressource, along with an automatic download routine simulating a user clicking on the embedded ressource. Then, when the user browses the HTML file, the embedded file is decrypted on the fly, saved in a temporary folder, and the file is then presented to the user as if it was being downloaded from the remote site. Depending on the user's browser and the file type presented, the file can be automatically opened by the browser.
* **Recon**
	* [hackability](https://github.com/PortSwigger/hackability)
		* Rendering Engine Hackability Probe performs a variety of tests to discover what the unknown rendering engine supports. To use it simply extract it to your web server and visit the url in the rendering engine you want to test. The more successful probes you get the more likely the target engine is vulnerable to attack.
	* [Image-Cache-Logger](https://github.com/kale/image-cache-logger)
		* A simple tool to see when other services/clients like Gmail open an image and test if they are storing it within their cache.
* **Templates**
	* [SimplyTemplate](https://github.com/killswitch-GUI/SimplyTemplate)
		* Phishing Template Generation Made Easy. The goal of this project was to hopefully speed up Phishing Template Gen as well as an easy way to ensure accuracy of your templates. Currently my standard Method of delivering emails is the Spear Phish in Cobalt strike so you will see proper settings for that by defaul
	* [MacroCreator](https://github.com/Arno0x/PowerShellScripts/tree/master/MacroCreator)
		* Invoke-MacroCreator is a powershell Cmdlet that allows for the creation of an MS-Word document embedding a VBA macro with various payload delivery and execution capabilities.









------------------
### <a name="msoutlook"></a>Microsoft Outlook/Exchange Stuff
* **General**
	* [Outlook Home Page – Another Ruler Vector](https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/)
	* [Outlook Forms and Shells](https://sensepost.com/blog/2017/outlook-forms-and-shells/)
	* [Exchange Versions, Builds & Dates](https://eightwone.com/references/versions-builds-dates/)
	* [Outlook and Exchange for the Bad Guys Nick Landers - Derbycon6](https://www.youtube.com/watch?v=cVhc9VOK5MY)
	* [Microsoft Support and Recovery Assistant for Office 365](https://testconnectivity.microsoft.com/)
	* [Elevating your security with Office 365 clients. - BRK3143](https://www.youtube.com/watch?v=BGpQ8S2-Oss&feature=youtu.be&t=372&app=desktop)
* **Bypass**
	* [How to bypass Web-Proxy Filtering](https://www.blackhillsinfosec.com/?p=5831)
* **Outlook Rules**
	* [Malicious Outlook Rules](https://silentbreaksecurity.com/malicious-outlook-rules/)
	* [EXE-less Malicious Outlook Rules - BHIS](https://www.blackhillsinfosec.com/?p=5544)
* **Tools**
	* [MailRaider](https://github.com/xorrior/EmailRaider)
	* [Phishery](https://github.com/ryhanson/phishery)
		* An SSL Enabled Basic Auth Credential Harvester with a Word Document Template URL Injector		* MailRaider is a tool that can be used to browse/search a user's Outlook folders as well as send phishing emails internally using their Outlook client.




------------------
### <a name="msoffice"></a>MS Office
* **General**
	* [office-exploit-case-study - houjingy1233](https://github.com/houjingyi233/office-exploit-case-study)
	* [Next Gen Office Malware v2.0 - Greg Linares Dagmar Knechtel - Hushcon17](https://prezi.com/view/eZ3CSNMxPMOfIWEHwTje/)
	* [Office Document Macros, OLE, Actions, DDE Payloads and Filter Bypass - Pwndizzle](https://pwndizzle.blogspot.com.es/2017/03/office-document-macros-ole-actions-dde.html)
	* [MSWord - Obfuscation with Field Codes - Staaldraad](https://staaldraad.github.io/2017/10/23/msword-field-codes/)
	* [Analysis of the Attack Surface of Microsoft Office from a User's Perspective](https://0b3dcaf9-a-62cb3a1a-s-sites.googlegroups.com/site/zerodayresearch/Analysis_of_the_Attack_Surface_of_Microsoft_Office_from_User_Perspective_final.pdf)
	* [Document Tracking: What You Should Know - justhaifei1](https://justhaifei1.blogspot.com/2013/10/document-tracking-what-you-should-know.html)
	* [ Microsoft Office – NTLM Hashes via Frameset - pentestlab.blog](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)
	* [EXD: An attack surface for Microsoft Office](https://www.fortinet.com/blog/threat-research/exd-an-attack-surface-for-microsoft-office.html)
		* Fortinet has discovered a potential attack surface for Microsoft office via EXD file. After a malformed or specifically crafted EXD file was placed in an expected location, it could trigger a remote code execution when a document with ActiveX is opened with office applications.
	* [Persisting with Microsoft Office: Abusing Extensibility Options - William Knowles](https://labs.mwrinfosecurity.com/assets/BlogFiles/WilliamKnowles-MWR-44con-PersistingWithMicrosoftOffice.pdf)
	* **Access**
		* [Phishing for “Access” - Changing Phishing Tactics Require Closer User and Defender Attention - Steve Borosh](https://medium.com/rvrsh3ll/phishing-for-access-554105b0901e)
		* [MAccess – Bypassing Office macro warnings - kaiosec](https://kaiosec.com/blog/maccess.html)
		* [Changing Phishing Tactics Require Closer User and Defender Attention - nuix.com](https://www.nuix.com/blog/changing-phishing-tactics-require-closer-user-and-defender-attention)
	* **Excel**
		* [When Scriptlets Attack: Excel’s Alternative to DDE Code Execution - David Wells](https://www.lastline.com/labsblog/when-scriptlets-attack-excels-alternative-to-dde-code-execution/)
		* [Malicious Excel DDE Execution with ML AV Bypass and Persistence - hyperiongray](https://blog.hyperiongray.com/excel-dde-exploitation-and-ml-av-bypass/)
	* **PowerPoint**
		* [Phishing with PowerPoint - BHIS](https://www.blackhillsinfosec.com/phishing-with-powerpoint/)
		* [PowerPoint and Custom Actions](https://phishme.com/powerpoint-and-custom-actions/)
* **DDE**
	* **Blogposts/Writeups**
		* [Exploiting Office native functionality: Word DDE edition](https://www.securityforrealpeople.com/2017/10/exploiting-office-native-functionality.html)
		* [Excel DDE Walkthrough](https://github.com/merrillmatt011/Excel_DDE_Walkthrough/blob/master/Excel_DDE_Walkthrough.pdf)
		* [Macro-less Code Exec in MSWord - Sensepost](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
		* [Macroless DOC malware that avoids detection with Yara rule](https://furoner.wordpress.com/2017/10/17/macroless-malware-that-avoids-detection-with-yara-rule/amp/)
		* [The Current State of DDE - Office DDE Attacks from an Offensive and Defensive Perspective - @0xdeadbeefJERKY](https://medium.com/@0xdeadbeefJERKY/the-current-state-of-dde-a62fd3277e9)
		* [ Microsoft Office – DDE Attacks - pentestlab.blog](https://pentestlab.blog/2018/01/16/microsoft-office-dde-attacks/)
		* [Abusing Microsoft Office DDE - SecuritySift](https://www.securitysift.com/abusing-microsoft-office-dde/)
		* [PowerShell, C-Sharp and DDE The Power Within](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
			* aka Exploiting MS16-032 via Excel DDE without macros.
		* [Macroless DOC malware that avoids detection with Yara rule - Furoner.CAT](https://furoner.wordpress.com/2017/10/17/macroless-malware-that-avoids-detection-with-yara-rule/)
		* [PowerShell, C-Sharp and DDE The Power Within - sensepost](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
	* **Payload Creation/Generation**
		* [Office-DDE-Payloads - 0xdeadbeefJERKY](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads)
			* Collection of scripts and templates to generate Word and Excel documents embedded with the DDE, macro-less command execution technique described by @\_staaldraad and @0x5A1F (blog post link in References section below). Intended for use during sanctioned red team engagements and/or phishing campaigns.
		* [DDE Payloads - Panagiotis Gkatziroulis](https://medium.com/red-team/dde-payloads-16629f4a2fcd)
		* [CACTUSTORCH_DDEAUTO](https://github.com/xillwillx/CACTUSTORCH_DDEAUTO)
			* OFFICE DDEAUTO Payload Generation script to automatically create a .vbs/.hta/.js payload for use inside a Microsoft Office document. Will create the DDEAUTO function to download and execute your payload using powershell or mshta that you can paste inside a Word document. That function can also be copy and pasted from Word to trigger in One Note/Outlook email/Outlook Calendar/Outlook Task. 
		* [Office DDEAUTO attacks - Will Genovese](http://willgenovese.com/office-ddeauto-attacks/)
* **DLL**
	* [DLL Tricks with VBA to Improve Offensive Macro Capability](https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/)
	* [DLL Execution via Excel.Application RegisterXLL() method](https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52)
		* A DLL can be loaded and executed via Excel by initializing the Excel.Application COM object and passing a DLL to the RegisterXLL method. The DLL path does not need to be local, it can also be a UNC path that points to a remote WebDAV server.
	* [ExcelDllLoader](https://github.com/3gstudent/ExcelDllLoader)
		* Execute DLL via the Excel.Application object's RegisterXLL() method
* **Excel**
	* [Insert an object in your Excel spreadsheet - support.office](https://support.office.com/en-us/article/Insert-an-object-in-your-Excel-spreadsheet-e73867b2-2988-4116-8d85-f5769ea435ba)
* **HTA**
	* [Malicious HTAs - trustedsec](https://www.trustedsec.com/2015/07/malicious-htas/)
	* [Exploiting CVE-2017-0199: HTA Handler Vulnerability](https://www.mdsec.co.uk/2017/04/exploiting-cve-2017-0199-hta-handler-vulnerability/)
	* [CVE-2017-0199 Toolkit](https://github.com/bhdresh/CVE-2017-0199)
	* [CVE-2017-0199: In the Wild Attacks Leveraging HTA Handler - Fireeye](https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html)
* **InfoPath**
	* [THE {PHISHING} {PATH} TO {INFO} WE MISSED](http://blog.obscuritylabs.com/the-phishing-path-to-info-we-missed/)
		* TL;DR: InfoPath is a fantastic way to run custom C# code, and we missed it as an attack vector sadly. At the moment it has been deprecated, but don't fret it's still everywhere!
	* [Resources for learning InfoPath - support.office.com](https://support.office.com/en-ie/article/Resources-for-learning-InfoPath-40227252-43A7-4E7A-97C6-29EC4B7E7B93)
	* [InfoPhish](https://github.com/InfoPhish/InfoPhish)
* **Macros**
	* **Articles/Blogposts/Writeups**
		* [Luckystrike: An Evil Office Document Generator](https://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator)
		* [How To: Empire’s Cross Platform Office Macro](https://www.blackhillsinfosec.com/empires-cross-platform-office-macro/)
		* [Excel macros with PowerShell](https://4sysops.com/archives/excel-macros-with-powershell/)
		* [Multi-Platform Macro Phishing Payloads](https://medium.com/@malcomvetter/multi-platform-macro-phishing-payloads-3b688e8eff68)
		* [Running Macros via ActiveX Controls - greyhathacker.net](http://www.greyhathacker.net/?p=948)
		* [Abusing native Windows functions for shellcode execution - ropgadget](http://ropgadget.com/posts/abusing_win_functions.html)
		* [Microsoft Office – Payloads in Document Properties - pentestlab.blog](https://pentestlab.blog/2017/12/15/microsoft-office-payloads-in-document-properties/)
	* **Tools**
		* **Generators**
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
		* **Samples**
			* [RobustPentestMacro](https://github.com/mgeeky/RobustPentestMacro)
				* This is a rich-featured Visual Basic macro code for use during Penetration Testing assignments, implementing various advanced post-exploitation techniques like sandbox evasion, WMI persistence and page substitution. Intended to be able to infect both Windows and Mac OS X Office platforms by implementing platform-detection logic.
			* [CVE-2017-8759-Exploit-sample](https://github.com/vysec/CVE-2017-8759-Exploit-sample)
				* Flow of the exploit: Word macro runs in the Doc1.doc file. The macro downloads a badly formatted txt file over wsdl, which triggers the WSDL parser log. Then the parsing log results in running mshta.exe which in turn runs a powershell commands that runs mspaint.exe
		* **Obfuscation**
			* [VBad](https://github.com/Pepitoh/VBad)
				* VBad is fully customizable VBA Obfuscation Tool combined with an MS Office document generator. It aims to help Red & Blue team for attack or defense.
* **OLE**
	* [Phishing with Empire](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
	* [Attacking Interoperability: An OLE Edition](https://www.blackhat.com/docs/us-15/materials/us-15-Li-Attacking-Interoperability-An-OLE-Edition.pdf)
* **Protected View**
	* [What is Protected View? - support.office.com](https://support.office.com/en-us/article/What-is-Protected-View-d6f09ac7-e6b9-4495-8e43-2bbcdbcb6653)
	* [Phishing against Protected View](https://enigma0x3.net/2017/07/13/phishing-against-protected-view/)
* **subDoc**
	* [Abusing Microsoft Word Features for Phishing: “subDoc”](https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc/)
	* [SubDocumentReference class - msdn.ms](https://msdn.microsoft.com/en-us/library/office/documentformat.openxml.wordprocessing.subdocumentreference.aspx?cs-save-lang=1&cs-lang=vb#Syntax)
* **Temporary File Drop**
	* [Demonstration of the Windows/Office "Insecure Temporary File Dropping" Vulnerability - justhaifeil](https://justhaifei1.blogspot.com/2014/08/demonstration-of-windowsoffice-insecure.html)
* **TNEF**
	* [Transport Neutral Encapsulation Format - Wikipedia](https://en.wikipedia.org/wiki/Transport_Neutral_Encapsulation_Format)
* **VBA**
	* [RobustPentestMacro](https://github.com/mgeeky/RobustPentestMacro)
		* This is a rich-featured Visual Basic macro code for use during Penetration Testing assignments, implementing various advanced post-exploitation techniques.
* **XLL**
	* [Hello World XLL](https://github.com/edparcell/HelloWorldXll)
		* This is a simple XLL, showing how to create an XLL from scratch.
	* [xllpoc](https://github.com/MoooKitty/xllpoc)
		* A small project that aggregates community knowledge for Excel XLL execution, via xlAutoOpen() or PROCESS_ATTACH.



------------------
### Setting up a Server
* [Mail Servers Made Easy - Inspired-Sec](https://blog.inspired-sec.com/archive/2017/02/14/Mail-Server-Setup.html)
* [Postfix-Server-Setup](https://github.com/n0pe-sled/Postfix-Server-Setup)
	* "Setting up a phishing server is a very long and tedious process. It can take hours to setup, and can be compromised in minutes. The esteemed gentlemen @cptjesus and @Killswitch_GUI have already made leaps and bounds in this arena. I took everything that I learned from them on setting up a server, and applied it to a bash script to automate the process.""


------------------
### <a name="talks"></a>Talks/Presentations
* [Three Years of Phishing - What We've Learned - Mike Morabito](http://www.irongeek.com/i.php?page=videos/centralohioinfosec2015/tech105-three-years-of-phishing-what-weve-learned-mike-morabito)
	* Cardinal Health has been aggressively testing and training users to recognize and avoid phishing emails. This presentation covers 3 years of lessons learned from over 18,000 employees tested, 150,000 individual phishes sent, 5 complaints, thousands of positive comments, and a dozen happy executives. Learn from actual phishing templates what works well, doesn,t work at all, and why? See efficient templates for education and reporting results.
* [Ichthyology: Phishing as a Science - BH USA 2017](https://www.youtube.com/watch?v=Z20XNp-luNA&app=desktop)
* [Modern Evasion Techniques Jason Lang - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)
	* As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.
* [Phishing Like The Pros - Luis “Connection” Santana - Derbycon 2013](https://www.irongeek.com/i.php?page=videos/derbycon3/1305-phishing-like-the-pros-luis-connection-santana)
	* This talk will discuss phishing techniques used by professionals during phishing campaigns and introduce “PhishPoll”, a PHP-based phishing framework for creating, managing, and tracking phishing campaigns.
* [MetaPhish - Valsmith, Colin Ames, and David Kerb - DEF CON 17](https://www.youtube.com/watch?v=3DYOMkkTK4A)


------------------
### <a name="pretext"></a> Phishing Pre-texts
* [Phishing Pretexts](https://github.com/L4bF0x/PhishingPretexts)
	* A library of pretexts to use on offensive phishing engagements. Orginially presented at Layer8 by @L4bF0x and @RizzyRong.
	* [Video Presentation](https://www.youtube.com/watch?v=D21E_2sXqmo)
	* [Slides](https://goo.gl/U6qiiy)
* [RealBusinessmen](http://realbusinessmen.com/)
	* All Business, All the Time.
