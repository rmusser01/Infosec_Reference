# Phishing

----------------------------------
## Table of Contents
* [General](#general)
	- [Articles/Blogposts]
	- [Papers]
	- [Writeups]
* [Phishing Frameworks](#framework)
* [Tools](#tools)
* [Microsoft Outlook/Exchange Related](#msoutlook)
* [Microsoft Office](#msoffice)
* [Setting up a Server](#settingup)
* [Talks/Presentations](#talks)




------------------
### <a name="general">General</a>
* **General**
	* [Phishing - wikipedia](http://www.en.wikipedia.org/wiki/Phishing):
		* ‚ÄúPhishing is the attempt to acquire sensitive information such as usernames, passwords, and credit card details (and sometimes, indirectly, money) by masquerading as a trustworthy entity in an electronic communication.‚Äù
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
	* [Email Delivery ‚Äì What Pen Testers Should Know - cs](https://blog.cobaltstrike.com/2013/10/03/email-delivery-what-pen-testers-should-know/)
	* [What‚Äôs the go-to phishing technique or exploit? - cs](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
	* [Phishing, Lateral Movement, SCADA, OH MY!](https://web.archive.org/web/20160408193653/http://www.idzer0.com/?p=210)
	* [Phishing with Empire - Enigma0x3](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
	* [Phishing for ‚ÄúAccess‚Äù - rvrsh3ll's blog](http://www.rvrsh3ll.net/blog/phishing/phishing-for-access/)
	* [Cross-Site Phishing](http://blog.obscuritylabs.com/merging-web-apps-and-red-teams/)
	* [Email Notification on shell connectback MSF Plugin](https://hansesecure.de/howto-msf-email/)
		* [Code](https://github.com/HanseSecure/metasploit-modules)
	* [How to Bypass Safe Link/Attachment Processing of ATP - support.knowbe4.com](https://support.knowbe4.com/hc/en-us/articles/115004326408-How-to-Bypass-Safe-Link-Attachment-Processing-of-ATP)
	* [ClickOnce (Twice or Thrice): A Technique for Social Engineering and (Un)trusted Command Execution - bohops](https://bohops.com/2017/12/02/clickonce-twice-or-thrice-a-technique-for-social-engineering-and-untrusted-command-execution/)
	* [ClickOnce Security and Deployment - docs.ms](https://docs.microsoft.com/en-us/visualstudio/deployment/clickonce-security-and-deployment?view=vs-2015)
	* [Abusing Misconfigured Cloud Email Providers for Enhanced Phishing Campaigns - und3rf10w.blogspot](https://und3rf10w.blogspot.com/2017/07/abusing-misconfigured-cloud-email.html)
	* [Next Gen Phishing ñ Leveraging Azure Information Protection - Oddvar Moe](https://www.trustedsec.com/2019/04/next-gen-phishing-leveraging-azure-information-protection/)
		* In this blog post, I will go over how to use Azure Information Protection (AIP) to improve phishing campaigns from the perspective of an attacker. The idea came during an engagement where I was having trouble getting phishing emails into usersí inboxes without being caught by a sandbox on the way. During this engagement, it struck me like a bolt of lightning that I could use AIP (also known as Rights Management Service) to protect the attachments and even the email so that only the designated recipient could open it. That way, it would not matter if the sandbox got the file since it will not be possible for it to read the contents.
* **Papers**
	* [Tab Napping - Phishing](http://www.exploit-db.com/papers/13950/)
	* [Skeleton in the closet. MS Office vulnerability you didn‚Äôt know about](https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about)
		* Microsoft Equation Editor Exploit writeup
	* [MetaPhish Paper](https://www.blackhat.com/presentations/bh-usa-09/SMITH_VAL/BHUSA09-Smith-MetaPhish-PAPER.pdf)
	* [MetaPhish - Defcon17](https://www.defcon.org/images/defcon-17/dc-17-presentations/Valsmith/defcon-17-valsmith-metaphish-wp.pdf)
* **Talks & Presentations**
	* [Phishing for Funds: Understanding Business Email Compromise - Keith Turpin - BHA17](https://www.youtube.com/watch?v=_gk4i33lriY&list=PLH15HpR5qRsWx4qw9ZlgmisHOcKG4ZcRS&index=11)
		* Business Email Compromise (aka CEO fraud) is a rapidly expanding cybercrime in which reported cases jumped 1300% from 2015 to 2016. This financial fraud scheme can target any market segment or organization regardless of size. Thousands of organizations from more than 100 countries have reported losses. The reasons for this surge is simple - it makes money.
* **Writeups**
	* [How do I phish? ‚Äì Advanced Email Phishing Tactics - Pentest Geek](https://www.pentestgeek.com/2013/01/30/how-do-i-phish-advanced-email-phishing-tactics/)
	* [Real World Phishing Techniques - Honeynet Project](http://www.honeynet.org/book/export/html/89)
	* [Phishing with Maldocs - n00py](https://www.n00py.io/2017/04/phishing-with-maldocs/)
	* [Tabnabbing - An art of phishing - securelayer7](http://blog.securelayer7.net/tabnabbing-art-phishing/)
	* [Add-In Opportunities for Office Persistence](https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/)
		* This post will explore various opportunities for gaining persistence through native Microsoft Office functionality.  It was inspired by Kostas Lintovois‚Äô similar work which identified ways to persist in transient Virtual Desktop Infrastructure (VDI) environments through adding a VBA backdoor to Office template files 
	* [One Template To Rule 'Em All](https://labs.mwrinfosecurity.com/publications/one-template-to-rule-em-all/)
		* This presentation discussed how Office security settings and templates can be abused to gain persistence in VDI implementations where traditional techniques relying on the file system or the Registry are not applicable. Additionally, it was described how the introduction of application control and anti-exploitation technologies may affect code execution in locked down environments and how these controls can be circumvented through the use of VBA.
	* [Spear Phishing 101 - inspired-sec.com](https://blog.inspired-sec.com/archive/2017/05/07/Phishing.html)
	* [There is a shell in your lunch-box by Rotimi Akinyele](https://hakin9.org/shell-lunch-box-rotimi-akinyele/)
	* [Advanced USB key phishing: Bypass airgap, drop, pwn using macro_pack - Emeric Nasi](http://blog.sevagas.com/?Advanced-USB-key-phishing)
* **Phishing Pre-texts**
	* [Phishing Pretexts](https://github.com/L4bF0x/PhishingPretexts)
		* A library of pretexts to use on offensive phishing engagements. Orginially presented at Layer8 by @L4bF0x and @RizzyRong.
		* [Video Presentation](https://www.youtube.com/watch?v=D21E_2sXqmo)
		* [Slides](https://goo.gl/U6qiiy)
	* [RealBusinessmen](http://realbusinessmen.com/)
	s	* All Business, All the Time.



----------
### <a name="documentation"> Documentation
* **Dynamic Data Exchange(DDE)**
	* [About Dynamic Data Exchange - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dataxchg/about-dynamic-data-exchange)
	* [Dynamic Data Exchange - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dataxchg/dynamic-data-exchange)
		* This section provides guidelines for implementing dynamic data exchange for applications that cannot use the Dynamic Data Exchange Management Library (DDEML). 
	* [Dynamic Data Exchange - docs.ms](https://docs.microsoft.com/en-us/windows/desktop/dataxchg/dynamic-data-exchange)
		* This section provides guidelines for implementing dynamic data exchange for applications that cannot use the Dynamic Data Exchange Management Library (DDEML). 
* **DomainKeys Identified Mail**
	* [DomainKeys Identified Mail - Wikipedia](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail)
* **Domain Message Authentication, Reporting, and Conformance - DMARC**
	* [DMARC - Wikipedia](https://en.wikipedia.org/wiki/DMARC)
	* [Domain-based Message Authentication, Reporting, and Conformance (DMARC) - RFC7489](https://tools.ietf.org/html/rfc7489)
* **Factur-X**
	* [Factur-X](http://fnfe-mpe.org/factur-x/factur-x_en/)
		* Factur-X is a Franco-German standard for hybrid e-invoice (PDF for users and XML data for process automation), the first implementation of the European Semantic Standard EN 16931 published by the European Commission on October 16th 2017. Factur-X is the same standard than ZUGFeRD 2.0.
		* Factur-X is at the same time a full readable invoice in a PDF A/3 format, containing all information useful for its treatment, especially in case of discrepancy or absence of automatic matching with orders and / or receptions, and a set of invoice data presented in an XML structured file conformant to EN16931 (syntax CII D16B), complete or not, allowing invoice process automation.
	* [Factur-X Python library - github](https://github.com/invoice-x/factur-x-ng)
		* Factur-X is a EU standard for embedding XML representations of invoices in PDF files. This library provides an interface for reading, editing and saving the this metadata.
* **HTA**
	* [HTML Application - Wikipedia](https://en.wikipedia.org/wiki/HTML_Application)
	* [Learn About Scripting for HTML Applications (HTAs) - technet.ms](https://technet.microsoft.com/en-us/scriptcenter/dd742317.aspx)
	* [Extreme Makeover: Wrap Your Scripts Up in a GUI Interface - technet.ms](https://technet.microsoft.com/en-us/library/ee692768.aspx)
* **Object Linking and Embedding**
	* [Object Linking and Embedding - Wikipedia](https://en.wikipedia.org/wiki/Object_Linking_and_Embedding)
	* [OLE - msdn.ms](https://msdn.microsoft.com/en-us/library/df267wkc.aspx)
	* [[MS-OLEDS]: Object Linking and Embedding (OLE) Data Structures - msdn.ms](https://msdn.microsoft.com/en-us/library/dd942265.aspx)
	* [Insert an object in your Excel spreadsheet - support.office](https://support.office.com/en-us/article/Insert-an-object-in-your-Excel-spreadsheet-e73867b2-2988-4116-8d85-f5769ea435ba)
* **Office Open XML Format**
	* [Introducing the Office (2007) Open XML File Formats - docs.ms](https://docs.microsoft.com/en-us/previous-versions/office/developer/office-2007/aa338205(v=office.12)#office2007aboutnewfileformat_structureoftheofficexmlformats)
* **Protected View**
	* [What is Protected View? - support.office.com](https://support.office.com/en-us/article/What-is-Protected-View-d6f09ac7-e6b9-4495-8e43-2bbcdbcb6653)
* **ScriptControl**
	* [Using ScriptControl Methods - docs.ms](https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-6.0/aa227637(v=vs.60))
		* The ScriptControl contains methods to execute code, add code and objects to the scripting engine, and reset the scripting engine to its initial state.
* **Sender Policy Framework - SPF**
	* [Sender Policy Framework - Wikipedia](https://en.wikipedia.org/wiki/Sender_Policy_Framework)
* **SMTP Strict Transport Security** 
	* [SMTP Strict Transport Security](https://lwn.net/Articles/684462/)
* **Subdocument Reference**
	* [SubDocumentReference class - msdn.ms](https://msdn.microsoft.com/en-us/library/office/documentformat.openxml.wordprocessing.subdocumentreference.aspx?cs-save-lang=1&cs-lang=vb#Syntax)
* **Transport Neutral Encapsulation Format**
	* [Transport Neutral Encapsulation Format - Wikipedia](https://en.wikipedia.org/wiki/Transport_Neutral_Encapsulation_Format)
* **VBA**
	* [[MS-OVBA]: Office VBA File Format Structure - msdn.ms](https://msdn.microsoft.com/en-us/library/cc313094(v=office.12).aspx)
		* Specifies the Office VBA File Format Structure, which describes the Microsoft Visual Basic for Applications (VBA) File Format for Microsoft Office 97, Microsoft Office 2000, Microsoft Office XP, Microsoft Office 2003, and the 2007 Microsoft Office system. This specification also describes a storage that contains a VBA project, which contains embedded macros and custom forms for use in Office documents.
	* [[MS-VBAL]: VBA Language Specification](https://msdn.microsoft.com/en-us/library/dd361851.aspx)
		* Specifies the VBA Language, which defines the implementation-independent and operating system-independent programming language that is required to be supported by all conforming VBA implementations. This specification also defines all features and behaviors of the language that are required to exist and behave identically in all conforming implementations.
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
* [Mercure](https://github.com/atexio/mercure)
	* Mercure is a tool for security managers who want to teach their colleagues about phishing.

------------------
### <a name="tools"></a>Tools
* **Cloning**
	* [Cooper](https://github.com/chrismaddalena/Cooper)
		* Cooper simplifies the process of cloning a target website or email for use in a phishing campaign. Just find a URL or download the raw contents of an email you want to use and feed it to Cooper. Cooper will clone the content and then automatically prepare it for use in your campaign. Scripts, images, and CSS can be modified to use direct links instead of relative links, links are changed to point to your phishing server, and forms are updated to send data to you -- all in a matter of seconds. Cooper is cross-platform and should work with MacOS, Linux, and Windows.
* **Defense**
	* [IsThisLegit](https://github.com/duo-labs/isthislegit)
		* IsThisLegit is a dashboard and Chrome extension that makes it easy to receive, analyze, and respond to phishing reports.
* **Domains**
	* [CatMyFish](https://github.com/Mr-Un1k0d3r/CatMyFish)
		* Search for categorized domain that can be used during red teaming engagement. Perfect to setup whitelisted domain for your Cobalt Strike beacon C&C.  It relies on expireddomains.net to obtain a list of expired domains. The domain availability is validated using checkdomain.com
	* [CatPhish](https://github.com/ring0lab/catphish)
		* Generate similar-looking domains for phishing attacks. Check expired domains and their categorized domain status to evade proxy categorization. Whitelisted domains are perfect for your C2 servers.
* **Email Harvesting**
	* [PhishBait](https://github.com/hack1thu7ch/PhishBait)
		* Tools for harvesting email addresses for phishing attacks
	* [Email Address Harvesting for Phishing](http://www.shortbus.ninja/email-address-harvesting-for-phishing-attacks/)
* **Local Phishing**
	* [Ask and ye shall receive - Impersonating everyday applications for profit - FoxIT](https://www.fox-it.com/en/insights/blogs/blog/phishing-ask-and-ye-shall-receive/)
	* [Invoke-CredentialPhisher](https://github.com/fox-it/Invoke-CredentialPhisher)
		* The first one is a powershell script to send toast notifications on behalf on an (installed) application or the computer itself. The user will be asked to supply credentials once they click on the notification toast. The second one is a Cobalt Strike module to launch the phishing attack on connected beacons.
	* [Phishing for Credentials: If you want it, just ask! - enigma0x3](http://enigma0x3.net/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)
	* [iOS Privacy: steal.password - Easily get the user's Apple ID password, just by asking - Felix Krause](https://krausefx.com/blog/ios-privacy-stealpassword-easily-get-the-users-apple-id-password-just-by-asking)
* **Payloads**
	* [Social-Engineering-Payloads - t3ntman](https://github.com/t3ntman/Social-Engineering-Payloads)
	* [backdoorppt](https://github.com/r00t-3xp10it/backdoorppt)
		* transform your payload.exe into one fake word doc (.ppt)
	* [EmbedInHTML](https://github.com/Arno0x/EmbedInHTML)
		* What this tool does is taking a file (any type of file), encrypt it, and embed it into an HTML file as resource, along with an automatic download routine simulating a user clicking on the embedded ressource. Then, when the user browses the HTML file, the embedded file is decrypted on the fly, saved in a temporary folder, and the file is then presented to the user as if it was being downloaded from the remote site. Depending on the user's browser and the file type presented, the file can be automatically opened by the browser.
	* [malicious_file_maker](https://github.com/carnal0wnage/malicious_file_maker)
		* malicious file maker/sender to create and send malicious attachments to test your email filter/alerting
	* [VBA ScriptControl to run Java Script Function](https://www.experts-exchange.com/questions/28190006/VBA-ScriptControl-to-run-Java-Script-Function.html)
	* [JS2PDFInjector](https://github.com/cornerpirate/JS2PDFInjector)
		* Use this tool to Inject a JavaScript file into a PDF file.
	* [RTF_11882_0802](https://github.com/Ridter/RTF_11882_0802)
	    * PoC for CVE-2018-0802 And CVE-2017-11882
	* [CVE-2018-8420 | MS XML Remote Code Execution Vulnerability - portal.msrc.ms](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8420)
	* [Microsoft Windows MSHTML Engine - 'Edit' Remote Code Execution/CVE:2019-0541](https://www.exploit-db.com/exploits/46536)
	* [Abusing native Windows functions for shellcode execution - ropgadget](http://ropgadget.com/posts/abusing_win_functions.html)
	* **HTA**
		* [Hacking around HTA Files](http://blog.sevagas.com/?Hacking-around-HTA-files)
		* [LethalHTA - A new lateral movement technique using DCOM and HTA - ](https://codewhitesec.blogspot.com/2018/07/lethalhta.html)	* [Demiguise](https://github.com/nccgroup/demiguise)
			* The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page, the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user.
		* [morphHTA - Morphing Cobalt Strike's evil.HTA](https://github.com/vysec/morphHTA)
		* [LethalHTA](https://github.com/codewhitesec/LethalHTA)
			* "Repo for our Lateral Movement technique using DCOM and HTA."
* **Recon**
	* [hackability](https://github.com/PortSwigger/hackability)
		* Rendering Engine Hackability Probe performs a variety of tests to discover what the unknown rendering engine supports. To use it simply extract it to your web server and visit the url in the rendering engine you want to test. The more successful probes you get the more likely the target engine is vulnerable to attack.
	* [Image-Cache-Logger](https://github.com/kale/image-cache-logger)
		* A simple tool to see when other services/clients like Gmail open an image and test if they are storing it within their cache.
* **SMTP Server**
	* [Papercut](https://github.com/changemakerstudios/papercut)
		* Simple Desktop SMTP Server
* **Templates**
	* [SimplyTemplate](https://github.com/killswitch-GUI/SimplyTemplate)
		* Phishing Template Generation Made Easy. The goal of this project was to hopefully speed up Phishing Template Gen as well as an easy way to ensure accuracy of your templates. Currently my standard Method of delivering emails is the Spear Phish in Cobalt strike so you will see proper settings for that by defaul
* **User Profiling**
	* [DeviceDetector.NET](https://github.com/totpero/DeviceDetector.NET)
		* The Universal Device Detection library will parse any User Agent and detect the browser, operating system, device used (desktop, tablet, mobile, tv, cars, console, etc.), brand and model.


------------------
### <a name="msoutlook"></a>Microsoft Outlook/Exchange Stuff/Office 365
* **General**
	* [Outlook Home Page ‚Äì Another Ruler Vector](https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/)
	* [Outlook Forms and Shells](https://sensepost.com/blog/2017/outlook-forms-and-shells/)
	* [Exchange Versions, Builds & Dates](https://eightwone.com/references/versions-builds-dates/)
	* [Microsoft Support and Recovery Assistant for Office 365](https://testconnectivity.microsoft.com/)
	* [Elevating your security with Office 365 clients. - BRK3143](https://www.youtube.com/watch?v=BGpQ8S2-Oss&feature=youtu.be&t=372&app=desktop)
* **Articles/Blogposts/Writeups**
	* [Office 365 Vulnerable to Brute Force Attack via Powershell - Tyler(2018)](https://cssi.us/office-365-brute-force-powershell/)
* **Bypass**
	* [How to bypass Web-Proxy Filtering](https://www.blackhillsinfosec.com/?p=5831)
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
* **General**
	* [office-exploit-case-study](https://github.com/houjingyi233/office-exploit-case-study)
		* I collect some office vuln recent years.Many samples are malware used in the real world,please study them in virtual machine.Take responsibility yourself if you use them for illegal purposes.Samples should match hash in corresponding paper if mentioned.	* [Next Gen Office Malware v2.0 - Greg Linares Dagmar Knechtel - Hushcon17](https://prezi.com/view/eZ3CSNMxPMOfIWEHwTje/)
	* [VB2018 paper: Office bugs on the rise - Gabor Szappanos](https://www.virusbulletin.com/virusbulletin/2018/12/vb2018-paper-office-bugs-rise/)
	* [Next Gen Office Malware v2.0 - Greg Linares Dagmar Knechtel - Hushcon17](https://prezi.com/view/eZ3CSNMxPMOfIWEHwTje/)
	* [Office Document Macros, OLE, Actions, DDE Payloads and Filter Bypass - Pwndizzle](https://pwndizzle.blogspot.com.es/2017/03/office-document-macros-ole-actions-dde.html)
	* [MSWord - Obfuscation with Field Codes - Staaldraad](https://staaldraad.github.io/2017/10/23/msword-field-codes/)
	* [Analysis of the Attack Surface of Microsoft Office from a User's Perspective](https://0b3dcaf9-a-62cb3a1a-s-sites.googlegroups.com/site/zerodayresearch/Analysis_of_the_Attack_Surface_of_Microsoft_Office_from_User_Perspective_final.pdf)
	* [Document Tracking: What You Should Know - justhaifei1](https://justhaifei1.blogspot.com/2013/10/document-tracking-what-you-should-know.html)
	* [ Microsoft Office ñ NTLM Hashes via Frameset - pentestlab.blog](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)
	* [EXD: An attack surface for Microsoft Office](https://www.fortinet.com/blog/threat-research/exd-an-attack-surface-for-microsoft-office.html)
	* [Microsoft Office ñ Payloads in Document Properties - pentestlab.blog](https://pentestlab.blog/2017/12/15/microsoft-office-payloads-in-document-properties/)
		* Fortinet has discovered a potential attack surface for Microsoft office via EXD file. After a malformed or specifically crafted EXD file was placed in an expected location, it could trigger a remote code execution when a document with ActiveX is opened with office applications.
	* [Persisting with Microsoft Office: Abusing Extensibility Options - William Knowles](https://labs.mwrinfosecurity.com/assets/BlogFiles/WilliamKnowles-MWR-44con-PersistingWithMicrosoftOffice.pdf)
	* [Abusing Microsoft Office Online Video - blog.cymulate](https://blog.cymulate.com/abusing-microsoft-office-online-video)
		* Cymulateís research team has discovered a way to abuse the Online Video feature on Microsoft Word to execute malicious code
	* [Office Document Macros, OLE, Actions, DDE Payloads and Filter Bypass - PwnDizzle](https://pwndizzle.blogspot.com/2017/03/office-document-macros-ole-actions-dde.html)
	* [Persisting with Microsoft Office: Abusing Extensibility Options - William Knowles](https://labs.mwrinfosecurity.com/assets/BlogFiles/WilliamKnowles-MWR-44con-PersistingWithMicrosoftOffice.pdf)
	* [Demonstration of the Windows/Office "Insecure Temporary File Dropping" Vulnerability - justhaifeil](https://justhaifei1.blogspot.com/2014/08/demonstration-of-windowsoffice-insecure.html)
	* [Analysis of the Attack Surface of Microsoft Office from a User's Perspective](https://0b3dcaf9-a-62cb3a1a-s-sites.googlegroups.com/site/zerodayresearch/Analysis_of_the_Attack_Surface_of_Microsoft_Office_from_User_Perspective_final.pdf)
	* [EXD: An attack surface for Microsoft Office](https://www.fortinet.com/blog/threat-research/exd-an-attack-surface-for-microsoft-office.html)
		* Fortinet has discovered a potential attack surface for Microsoft office via EXD file. After a malformed or specifically crafted EXD file was placed in an expected location, it could trigger a remote code execution when a document with ActiveX is opened with office applications.
	* **Inbuilt Functions**
		* [Variable Object (Word) - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Word-VBA/articles/variable-object-word)
		* [Using ScriptControl Methods - docs.ms](https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-6.0/aa227637(v=vs.60))
			* The ScriptControl contains methods to execute code, add code and objects to the scripting engine, and reset the scripting engine to its initial state.
	* **Access**
		* [Phishing for ìAccessî - Changing Phishing Tactics Require Closer User and Defender Attention - Steve Borosh](https://medium.com/rvrsh3ll/phishing-for-access-554105b0901e)
		* [MAccess ñ Bypassing Office macro warnings - kaiosec](https://kaiosec.com/blog/maccess.html)
		* [Changing Phishing Tactics Require Closer User and Defender Attention - nuix.com](https://www.nuix.com/blog/changing-phishing-tactics-require-closer-user-and-defender-attention)
	* **Excel**
		* **Articles/Blogposts/Writeups**
			* [When Scriptlets Attack: Excelís Alternative to DDE Code Execution - David Wells](https://www.lastline.com/labsblog/when-scriptlets-attack-excels-alternative-to-dde-code-execution/)
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
		* [10 Places to Stick Your UNC Path - Karl Fossan](https://blog.netspi.com/10-places-to-stick-your-unc-path/)
		* [ Microsoft Office ‚Äì NTLM Hashes via Frameset - pentestlab.blog](https://pentestlab.blog/2017/12/18/microsoft-office-ntlm-hashes-via-frameset/)
		* [WordSteal](https://github.com/0x09AL/WordSteal)
			* This script will create a POC that will steal NTML hashes from a remote computer. Do not use this for illegal purposes.The author does not keep responsibility for any illegal action you do. Microsoft Word has the ability to include images from remote locations.This is an undocumented feature but was found used by malware creators to include images through http for statistics.We can also include remote files to a SMB server and the victim will authenticate with his logins credentials.
	* **PowerPoint**
		* [Phishing with PowerPoint - BHIS](https://www.blackhillsinfosec.com/phishing-with-powerpoint/)
		* [PowerPoint and Custom Actions - Sean Wilson](https://cofense.com/powerpoint-and-custom-actions/)
	* **OSX**
		* [Sylk + XLM = Code execution on Office 2011 for Mac - Pieter Celeen](https://outflank.nl/blog/2018/10/12/sylk-xlm-code-execution-on-office-2011-for-mac/)
* **Creating Documents**
	* [EvilClippy](https://github.com/outflanknl/EvilClippy)
		* A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows.
		* [Blogpost](https://outflank.nl/blog/2019/05/05/evil-clippy-ms-office-maldoc-assistant/)
	* [MacroCreator](https://github.com/Arno0x/PowerShellScripts/tree/master/MacroCreator)
		* Invoke-MacroCreator is a powershell Cmdlet that allows for the creation of an MS-Word document embedding a VBA macro with various payload delivery and execution capabilities.
	* [Office-DDE-Payloads - 0xdeadbeefJERKY](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads)
		* Collection of scripts and templates to generate Word and Excel documents embedded with the DDE, macro-less command execution technique described by @\_staaldraad and @0x5A1F (blog post link in References section below). Intended for use during sanctioned red team engagements and/or phishing campaigns.
* **DDE**
	* **Blogposts/Writeups**
		* [Exploiting Office native functionality: Word DDE edition](https://www.securityforrealpeople.com/2017/10/exploiting-office-native-functionality.html)
		* [Excel DDE Walkthrough](https://github.com/merrillmatt011/Excel_DDE_Walkthrough/blob/master/Excel_DDE_Walkthrough.pdf)
		* [Macro-less Code Exec in MSWord -  Etienne Stalmans, Saif El-Sherei](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
		* [The Current State of DDE - Office DDE Attacks from an Offensive and Defensive Perspective - @0xdeadbeefJERKY](https://medium.com/@0xdeadbeefJERKY/the-current-state-of-dde-a62fd3277e9)
		* [ Microsoft Office ñ DDE Attacks - pentestlab.blog](https://pentestlab.blog/2018/01/16/microsoft-office-dde-attacks/)
		* [ Microsoft Office ‚Äì DDE Attacks - pentestlab.blog](https://pentestlab.blog/2018/01/16/microsoft-office-dde-attacks/)
		* [Abusing Microsoft Office DDE - SecuritySift](https://www.securitysift.com/abusing-microsoft-office-dde/)
		* [PowerShell, C-Sharp and DDE The Power Within](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
			* aka Exploiting MS16-032 via Excel DDE without macros.
		* [Macroless DOC malware that avoids detection with Yara rule - Furoner.CAT](https://furoner.wordpress.com/2017/10/17/macroless-malware-that-avoids-detection-with-yara-rule/)
		* [PowerShell, C-Sharp and DDE The Power Within - sensepost](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
		* [Microsoft Office ñ DDE Attacks - pentestlab.blog](https://pentestlab.blog/2018/01/16/microsoft-office-dde-attacks/)
		* [Abusing Microsoft Office DDE - SecuritySift](https://www.securitysift.com/abusing-microsoft-office-dde/)
		* [Malicious Excel DDE Execution with ML AV Bypass and Persistence - hyperiongray](https://blog.hyperiongray.com/excel-dde-exploitation-and-ml-av-bypass/)
		* [Abusing Microsoft Office DDE - Mike Czumak](https://www.securitysift.com/abusing-microsoft-office-dde/)
		* [The Current State of DDE - Office DDE Attacks from an Offensive and Defensive Perspective - @0xdeadbeefJERKY](https://medium.com/@0xdeadbeefJERKY/the-current-state-of-dde-a62fd3277e9)
		* [The Current State of DDE - 0xdeadbeefjerky](2018/1)](https://0xdeadbeefjerky.github.io/2018/01/29/state-of-dde.html)
		* [PowerShell, C-Sharp and DDE The Power Within - sensepost(2016)](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
	* **Payload Creation/Generation**
		* [DDE Payloads - Panagiotis Gkatziroulis](https://medium.com/red-team/dde-payloads-16629f4a2fcd)
		* [CACTUSTORCH_DDEAUTO](https://github.com/xillwillx/CACTUSTORCH_DDEAUTO)
			* OFFICE DDEAUTO Payload Generation script to automatically create a .vbs/.hta/.js payload for use inside a Microsoft Office document. Will create the DDEAUTO function to download and execute your payload using powershell or mshta that you can paste inside a Word document. That function can also be copy and pasted from Word to trigger in One Note/Outlook email/Outlook Calendar/Outlook Task. 
		* [Office DDEAUTO attacks - Will Genovese](http://willgenovese.com/office-ddeauto-attacks/)
	* **Payload Obfuscation**
		* [MSWord - Obfuscation with Field Codes - Staaldraad](https://staaldraad.github.io/2017/10/23/msword-field-codes/)
		* [Malicious Excel DDE Execution with ML AV Bypass and Persistence - hyperiongray.com](https://blog.hyperiongray.com/excel-dde-exploitation-and-ml-av-bypass/)
		* [Three New DDE Obfuscation Methods - reversinglabs.com](https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation)
* **DLL**
	* [DLL Tricks with VBA to Improve Offensive Macro Capability](https://labs.mwrinfosecurity.com/blog/dll-tricks-with-vba-to-improve-offensive-macro-capability/)
	* [DLL Execution via Excel.Application RegisterXLL() method](https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52)
		* A DLL can be loaded and executed via Excel by initializing the Excel.Application COM object and passing a DLL to the RegisterXLL method. The DLL path does not need to be local, it can also be a UNC path that points to a remote WebDAV server.
	* [ExcelDllLoader](https://github.com/3gstudent/ExcelDllLoader)
		* Execute DLL via the Excel.Application object's RegisterXLL() method
* **Embeds**
	* [Abusing Microsoft Office Online Video(2018) - Avihai Ben-Yossef](https://blog.cymulate.com/abusing-microsoft-office-online-video)
* **Exploits**
	* [CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199)
		* Exploit toolkit CVE-2017-0199 - v4.0 is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft Office RCE. It could generate a malicious RTF/PPSX file and deliver metasploit / meterpreter / other payload to victim without any complex configuration.
	* [PowerShell, C-Sharp and DDE The Power Within](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/)
		* aka Exploiting MS16-032 via Excel DDE without macros.
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
* **LoL**
	* [Unsanitized file validation leads to Malicious payload download via Office binaries. - Reegun](https://medium.com/@reegun/unsanitized-file-validation-leads-to-malicious-payload-download-via-office-binaries-202d02db7191)
* **Macros**
	* **Articles/Blogposts/Writeups**
		* [Luckystrike: An Evil Office Document Generator](https://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator)
		* [How To: Empire‚Äôs Cross Platform Office Macro](https://www.blackhillsinfosec.com/empires-cross-platform-office-macro/)
		* [Excel macros with PowerShell](https://4sysops.com/archives/excel-macros-with-powershell/)
		* [Multi-Platform Macro Phishing Payloads](https://medium.com/@malcomvetter/multi-platform-macro-phishing-payloads-3b688e8eff68)
		* [Abusing native Windows functions for shellcode execution - ropgadget](http://ropgadget.com/posts/abusing_win_functions.html)
		* [Microsoft Office ñ Payloads in Document Properties - pentestlab.blog](https://pentestlab.blog/2017/12/15/microsoft-office-payloads-in-document-properties/)
		* [Running Macros via ActiveX Controls - greyhathacker.net](http://www.greyhathacker.net/?p=948)
		* [MAccess ñ Bypassing Office macro warnings - kaiosec](https://kaiosec.com/blog/maccess.html)
		* [Microsoft Office ‚Äì Payloads in Document Properties - pentestlab.blog](https://pentestlab.blog/2017/12/15/microsoft-office-payloads-in-document-properties/)
		* [Building an Office macro to spoof parent processes and command line arguments(2019) - Christophe Tafani-Dereeper](https://blog.christophetd.fr/building-an-office-macro-to-spoof-process-parent-and-command-line/)
		* [Direct shellcode execution in MS Office macros - scriptjunkie.us](https://www.scriptjunkie.us/2012/01/direct-shellcode-execution-in-ms-office-macros/)
	* **ActiveX**
		* [Having Fun with ActiveX Controls in Microsoft Word - Marcello Salvati](https://www.blackhillsinfosec.com/having-fun-with-activex-controls-in-microsoft-word/)
		* [Running Macros via ActiveX Controls - Parvez](http://www.greyhathacker.net/?p=948)
		* [Running Macros via ActiveX Controls - greyhathacker.net](http://www.greyhathacker.net/?p=948)
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
			* [macro_pack](https://github.com/sevagas/macro_pack)
				* macro_pack is a tool by @EmericNasi used to automatize obfuscation and generation of MS Office documents for pentest, demo, and social engineering assessments. The goal of macro_pack is to simplify exploitation, antimalware bypass, and automatize the process from vba generation to final Office document generation.
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
	* [Microsoft Powerpoint as Malware Dropper - Marco Ramilli](https://marcoramilli.blogspot.com/2018/11/microsoft-powerpoint-as-malware-dropper.html)
	* [Office Document Macros, OLE, Actions, DDE Payloads and Filter Bypass - pwndizzle](http://pwndizzle.blogspot.com.es/2017/03/office-document-macros-ole-actions-dde.html)
	* [#OLEOutlook - bypass almost every Corporate security control with a pointíníclick GUI - Kevin Beaumont](https://doublepulsar.com/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0?gi=18b1f4a3ca13)
* **OS X**
	* [Escaping the Microsoft Office Sandbox: a faulty regex, allows malicious code to escape and persist](https://objective-see.com/blog/blog_0x35.html)
	* [Word to Your Mac - analyzing a malicious word document targeting macOS users - Patrick Wardle](https://objective-see.com/blog/blog_0x3A.html)
	* [New Attack, Old Tricksõ analyzing a malicious document with a mac-specific payload - Patrick Wardle](https://objective-see.com/blog/blog_0x17.html)
* **Protected View**
	* [What is Protected View? - support.office.com](https://support.office.com/en-us/article/What-is-Protected-View-d6f09ac7-e6b9-4495-8e43-2bbcdbcb6653)
	* [Phishing against Protected View](https://enigma0x3.net/2017/07/13/phishing-against-protected-view/)
	* [Understanding The Microsft Office 2013 Protected-View Sandbox - Yong Chuan, Kho (2015)](https://labs.mwrinfosecurity.com/assets/BlogFiles/UNDERSTANDING-THE-MICROSOFT-OFFICE-2013-PROTECTED-VIEW-SANDBOX-WP3.pdf)
	* [Corrupting Memory In Microsoft Office Protected-View Sandbox - Yong Chuan Koh(MS BlueHat '17)](https://labs.f-secure.com/assets/BlogFiles/mwri-corrupting-memory-in-ms-office-protected-view-v2.pdf)
		* The MS Office Protected-View is unlike any other sandboxes; it aims to provide only a text-view of the document contents and therefore does not have to provide full functionalities of the application. As a result, the broker -sandbox Inter-Process Communication (IPC) attack surface is greatly reduced. However this does not mean there are no vulnerabilities. This talk discussed the methodology for fuzzing this IPC attack surface, from the test-case generation to the discovery and analysis of CVE-2017-8502 and CVE-2017-8692.
* **Shellcode**
	* [CallByName Function - docs.ms](https://docs.microsoft.com/en-us/office/vba/Language/Reference/User-Interface-Help/callbyname-function)
	* [CallByName Function - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Language-Reference-VBA/articles/callbyname-function)
		* Executes a method of an object, or sets or returns a property of an object. SyntaxCallByName( object, procname, calltype,[args()])
	* [Abusing native Windows functions for shellcode execution - ropgadget](http://ropgadget.com/posts/abusing_win_functions.html)
	* [trigen](https://github.com/karttoon/trigen)
		* Trigen is a Python script which uses different combinations of Win32 function calls in generated VBA to execute shellcode.
* **subDoc**
	* [Abusing Microsoft Word Features for Phishing: ìsubDocî](https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc/)
* **subDoc**
	* [Abusing Microsoft Word Features for Phishing: ‚ÄúsubDoc‚Äù](https://rhinosecuritylabs.com/research/abusing-microsoft-word-features-phishing-subdoc/)
	* [SubDocumentReference class - msdn.ms](https://msdn.microsoft.com/en-us/library/office/documentformat.openxml.wordprocessing.subdocumentreference.aspx?cs-save-lang=1&cs-lang=vb#Syntax)
* **Talks & Presentations**
	* [MS Office file format sorcery - Stan Hegt, Pieter Ceelen(TR19)](https://www.youtube.com/watch?v=iXvvQ5XML7g)
* **Temporary File Drop**
	* [Demonstration of the Windows/Office "Insecure Temporary File Dropping" Vulnerability - justhaifeil](https://justhaifei1.blogspot.com/2014/08/demonstration-of-windowsoffice-insecure.html)
* **TNEF**
	* [Transport Neutral Encapsulation Format - Wikipedia](https://en.wikipedia.org/wiki/Transport_Neutral_Encapsulation_Format)
* **VBA**
	* **101**
		* [VBA Stomp](https://vbastomp.com/)
		* [Variable Object (Word) - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Word-VBA/articles/variable-object-word)
		* [CallByName Function - msdn.ms](https://msdn.microsoft.com/en-us/VBA/Language-Reference-VBA/articles/callbyname-function)
			* Executes a method of an object, or sets or returns a property of an object. SyntaxCallByName( object, procname, calltype,[args()])
	* **Articles/Blogposts/Writeups**
		* [Malicious VBA Office Document Without Source Code - Didier Stevens](https://isc.sans.edu/diary/Malicious+VBA+Office+Document+Without+Source+Code/24870)
		* [VBA Macros Pest Control - Philippe Lagadec](https://www.decalage.info/files/THC17_Lagadec_Macro_Pest_Control2.pdf)
		* [VBA ScriptControl to run Java Script Function](https://www.experts-exchange.com/questions/28190006/VBA-ScriptControl-to-run-Java-Script-Function.html)
		* [VBA Macro with Environmental Keying and Encryption(2019) - Hunnic Cyber](https://blog.hunniccyber.com/vba-macro-with-environmental-keying-and-encryption/)
		* [MS Office File Formats ó Advanced Malicious Document (Maldoc) Techniques - Kirk Sayre, Harold Ogden, Carrie Roberts](https://medium.com/walmartlabs/ms-office-file-formats-advanced-malicious-document-maldoc-techniques-b5f948950fdf)
		* [Evasive VBA ó Advanced Maldoc Techniques - Kirk Sayre, Harold Ogden, Carrie Roberts](https://medium.com/walmartlabs/evasive-vba-advanced-maldoc-techniques-1365e9373f80)
		* [VBA Stomping ó Advanced Maldoc Techniques - Kirk Sayre, Harold Ogden, Carrie Roberts](https://medium.com/walmartlabs/vba-stomping-advanced-maldoc-techniques-612c484ab278)
		* [VBA Project Locked; Project is Unviewable - Carrie Roberts](https://medium.com/walmartlabs/vba-project-locked-project-is-unviewable-4d6a0b2e7cac)
	* **Macros**
		* [RobustPentestMacro](https://github.com/mgeeky/RobustPentestMacro)
			* This is a rich-featured Visual Basic macro code for use during Penetration Testing assignments, implementing various advanced post-exploitation techniques.
	* **Tools**
		* [VBA Dynamic Hook](https://github.com/eset/vba-dynamic-hook)
			* Dynamically analyzes VBA macros inside Office documents by hooking function calls
		* [mraptor](https://github.com/decalage2/oletools/wiki/mraptor)
			* mraptor is a tool designed to detect most malicious VBA Macros using generic heuristics. Unlike antivirus engines, it does not rely on signatures.
			* [blogpost](http://decalage.info/mraptor)
		* [olevba](https://github.com/decalage2/oletools/wiki/olevba)
			* olevba is a script to parse OLE and OpenXML files such as MS Office documents (e.g. Word, Excel), to detect VBA Macros, extract their source code in clear text, and detect security-related patterns such as auto-executable macros, suspicious VBA keywords used by malware, anti-sandboxing and anti-virtualization techniques, and potential IOCs (IP addresses, URLs, executable filenames, etc). It also detects and decodes several common obfuscation methods including Hex encoding, StrReverse, Base64, Dridex, VBA expressions, and extracts IOCs from decoded strings.
		* [pcodedmp.py](https://github.com/bontchev/pcodedmp)
			* A VBA p-code disassembler
		* [trigen](https://github.com/karttoon/trigen)
			* Trigen is a Python script which uses different combinations of Win32 function calls in generated VBA to execute shellcode.
* **Word Fields**
	* [MS Office In Wonderland - Stan Hegt & Pieter Ceelen(BH Asia2019)](https://i.blackhat.com/asia-19/Thu-March-28/bh-asia-Hegt-MS-Office-in-Wonderland.pdf)
	* [MS Word field abuse(2019) - Pieter Celeen](https://outflank.nl/blog/2019/04/02/ms-word-field-abuse/)
	* [Detecting and Protecting Against Word Field Code Abuse - Mark E. Soderlund(2003)](https://www.giac.org/paper/gsec/2624/detecting-protecting-word-field-code-abuse/104497)
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
* [Phishing Like The Pros - Luis ‚ÄúConnection‚Äù Santana - Derbycon 2013](https://www.irongeek.com/i.php?page=videos/derbycon3/1305-phishing-like-the-pros-luis-connection-santana)
	* This talk will discuss phishing techniques used by professionals during phishing campaigns and introduce ‚ÄúPhishPoll‚Äù, a PHP-based phishing framework for creating, managing, and tracking phishing campaigns.
* [MetaPhish - Valsmith, Colin Ames, and David Kerb - DEF CON 17](https://www.youtube.com/watch?v=3DYOMkkTK4A)
* [Phishing for Funds: Understanding Business Email Compromise - Keith Turpin - BH Asia2017](https://www.youtube.com/watch?v=_gk4i33lriY&list=PLH15HpR5qRsWx4qw9ZlgmisHOcKG4ZcRS&index=11)
	* Business Email Compromise (aka CEO fraud) is a rapidly expanding cybercrime in which reported cases jumped 1300% from 2015 to 2016. This financial fraud scheme can target any market segment or organization regardless of size. Thousands of organizations from more than 100 countries have reported losses. The reasons for this surge is simple - it makes money. 





------------------
### <a name="pretext"></a> 
* [Phishing Pretexts](https://github.com/L4bF0x/PhishingPretexts)
	* A library of pretexts to use on offensive phishing engagements. Orginially presented at Layer8 by @L4bF0x and @RizzyRong.
	* [Video Presentation](https://www.youtube.com/watch?v=D21E_2sXqmo)
	* [Slides](https://goo.gl/U6qiiy)
* [RealBusinessmen](http://realbusinessmen.com/)
	* All Business, All the Time.


* [Skeleton in the closet. MS Office vulnerability you didnít know about - Embedi](https://embedi.org/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about/)
