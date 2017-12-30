# Phishing

### TOC

* [General](#general)
* [Phishing Frameworks](#framework)
* [Phishing Guides](#guides)
* [Phishing Writeups](#writeup)

### Cull

* [Client Identification Mechanisms](http://www.chromium.org/Home/chromium-security/client-identification-mechanisms)

### General

* General

  * [Phishing - wikipedia](http://www.en.wikipedia.org/wiki/Phishing)

    * Phishing is the attempt to acquire sensitive information such as
      usernames, passwords, and credit card details (and sometimes, indirectly,
      money) by masquerading as a trustworthy entity in an electronic
      communication.

  * [Post exploitation trick - Phish users for creds on domains, from their own box](https://enigma0x3.wordpress.com/2015/01/21/phishing-for-credentials-if-you-want-it-just-ask/)

* Articles/Blogposts

  * [Top 10 Email Subjects for Company Phishing Attacks](http://www.pandasecurity.com/mediacenter/security/top-10-email-subjects-phishing-attacks/)
  * [Some Tips for Legitimate Senders to Avoid False Positives - Apache SpamAssassin](https://wiki.apache.org/spamassassin/AvoidingFpsForSenders)
  * [Email Delivery What Pen Testers Should Know - cs](https://blog.cobaltstrike.com/2013/10/03/email-delivery-what-pen-testers-should-know/)
  * [Whats the go-to phishing technique or exploit? - cs](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
  * [Phishing, Lateral Movement, SCADA, OH MY!](https://web.archive.org/web/20160408193653/http://www.idzer0.com/?p=210)

* Papers

  * [Tab Napping - Phishing](http://www.exploit-db.com/papers/13950/)
  * [Skeleton in the closet. MS Office vulnerability you didnt know about](https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about)
    * Microsoft Equation Editor Exploit writeup
  * [MetaPhish Paper](https://www.blackhat.com/presentations/bh-usa-09/SMITH_VAL/BHUSA09-Smith-MetaPhish-PAPER.pdf)

* Writeups

  * [How do I phish? Advanced Email Phishing Tactics - Pentest Geek](https://www.pentestgeek.com/2013/01/30/how-do-i-phish-advanced-email-phishing-tactics/)
  * [Real World Phishing Techniques - Honeynet Project](http://www.honeynet.org/book/export/html/89)

### Documentation

* [Sender Policy Framework - Wikipedia](https://en.wikipedia.org/wiki/Sender_Policy_Framework)
* [DomainKeys Identified Mail - Wikipedia](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail)
* [DMARC - Wikipedia](https://en.wikipedia.org/wiki/DMARC)
* [Domain-based Message Authentication, Reporting, and Conformance (DMARC) - RFC7489](https://tools.ietf.org/html/rfc7489)
* [SPF, DKIM, and DMARC Demystified - McAfee](https://jira.sakaiproject.org/secure/attachment/43722/sb-spf-dkim-dmarc-demystified.pdf)
* [Add commands to your presentation with action buttons](https://support.office.com/en-us/article/Add-commands-to-your-presentation-with-action-buttons-7db2c0f8-5424-4780-93cb-8ac2b6b5f6ce)

  * Add commands to your presentation with action buttons

* [SMTP Strict Transport Security](https://lwn.net/Articles/684462/)

### framework Phishing Frameworks:

* [Phishing Frenzy](http://www.phishingfrenzy.com/)

  * Phishing Frenzy is an Open Source Ruby on Rails application that is
    leveraged by penetration testers to manage email phishing campaigns. The
    goal of the project is to streamline the phishing process while still
    providing clients the best realistic phishing campaign possible. This goal
    is obtainable through campaign management, template reuse, statistical
    generation, and other features the Frenzy has to offer.

* [sptoolkit](https://github.com/sptoolkit/sptoolkit)

  * Simple Phishing Toolkit is a super easy to install and use phishing
    framework built to help Information Security professionals find human
    vulnerabilities

* [sptoolkit-rebirth](https://github.com/simplephishingtoolkit/sptoolkit-rebirth)

  * sptoolkit hasn't been actively developed for two years. As it stands, it's a
    brilliant peice of software, and the original developers are pretty damn
    awesome for creating it. But we'd like to go further, and bring sptoolkit up
    to date. We've tried contacting the developers, but to no avail. We're
    taking matters into our own hands now.

* [KingPhisher](https://github.com/securestate/king-phisher)

  * King Phisher is a tool for testing and promoting user awareness by
    simulating real world phishing attacks. It features an easy to use, yet very
    flexible architecture allowing full control over both emails and server
    content. King Phisher can be used to run campaigns ranging from simple
    awareness training to more complicated scenarios in which user aware content
    is served for harvesting credentials.

* [Gophish](https://github.com/gophish/gophish)

  * Gophish is an open-source phishing toolkit designed for businesses and
    penetration testers. It provides the ability to quickly and easily setup and
    execute phishing engagements and security awareness training.
  * [gophish documentation](https://getgophish.com/documentation/)

* [TackleBox](https://github.com/trailofbits/tacklebox)
* [king-phisher](https://github.com/securestate/king-phisher)

  * Phishing Campaign Toolkit

#### Tools - Cloning

* [Cooper](https://github.com/chrismaddalena/Cooper)

  * Cooper simplifies the process of cloning a target website or email for use
    in a phishing campaign. Just find a URL or download the raw contents of an
    email you want to use and feed it to Cooper. Cooper will clone the content
    and then automatically prepare it for use in your campaign. Scripts, images,
    and CSS can be modified to use direct links instead of relative links, links
    are changed to point to your phishing server, and forms are updated to send
    data to you -- all in a matter of seconds. Cooper is cross-platform and
    should work with MacOS, Linux, and Windows.

#### Tools - Domains

* [CatMyFish](https://github.com/Mr-Un1k0d3r/CatMyFish)

  * Search for categorized domain that can be used during red teaming
    engagement. Perfect to setup whitelisted domain for your Cobalt Strike
    beacon C&C. It relies on expireddomains.net to obtain a list of expired
    domains. The domain availability is validated using checkdomain.com

* [CatPhish](https://github.com/ring0lab/catphish)

  * Generate similar-looking domains for phishing attacks. Check expired domains
    and their categorized domain status to evade proxy categorization.
    Whitelisted domains are perfect for your C2 servers.

### Tools - Email Harvesting

* [PhishBait](https://github.com/hack1thu7ch/PhishBait)

  * Tools for harvesting email addresses for phishing attacks

* [Email Address Harvesting for Phishing](http://www.shortbus.ninja/email-address-harvesting-for-phishing-attacks/)

### Tools - Frameworks

* [Cartero](https://github.com/Section9Labs/Cartero)

  * Cartero is a modular project divided into commands that perform independent
    tasks (i.e. Mailer, Cloner, Listener, AdminConsole, etc...). In addition
    each sub-command has repeatable configuration options to configure and
    automate your work.

* [FiercePhish](https://github.com/Raikia/FiercePhish)

  * FiercePhish is a full-fledged phishing framework to manage all phishing
    engagements. It allows you to track separate phishing campaigns, schedule
    sending of emails, and much more

### Tools - Payloads

* [Demiguise](https://github.com/nccgroup/demiguise)

  * The aim of this project is to generate .html files that contain an encrypted
    HTA file. The idea is that when your target visits the page, the key is
    fetched and the HTA is decrypted dynamically within the browser and pushed
    directly to the user.

* [morphHTA - Morphing Cobalt Strike's evil.HTA](https://github.com/vysec/morphHTA)
* [Social-Engineering-Payloads - t3ntman](https://github.com/t3ntman/Social-Engineering-Payloads)

### Tools - Recon

* [hackability](https://github.com/PortSwigger/hackability)

  * Rendering Engine Hackability Probe performs a variety of tests to discover
    what the unknown rendering engine supports. To use it simply extract it to
    your web server and visit the url in the rendering engine you want to test.
    The more successful probes you get the more likely the target engine is
    vulnerable to attack.

### Tools - Templates

* [SimplyTemplate](https://github.com/killswitch-GUI/SimplyTemplate)

  * Phishing Template Generation Made Easy. The goal of this project was to
    hopefully speed up Phishing Template Gen as well as an easy way to ensure
    accuracy of your templates. Currently my standard Method of delivering
    emails is the Spear Phish in Cobalt strike so you will see proper settings
    for that by defaul

### Microsoft Outlook/Exchange Stuff

* [Exchange Versions, Builds & Dates](https://eightwone.com/references/versions-builds-dates/)
* [Outlook and Exchange for the Bad Guys Nick Landers - Derbycon6](https://www.youtube.com/watch?v=cVhc9VOK5MY)
* [Microsoft Support and Recovery Assistant for Office 365](https://testconnectivity.microsoft.com/)
* Bypass

  * [How to bypass Web-Proxy Filtering](https://www.blackhillsinfosec.com/?p=5831)

* Outlook Rules

  * [Malicious Outlook Rules](https://silentbreaksecurity.com/malicious-outlook-rules/)
  * [EXE-less Malicious Outlook Rules - BHIS](https://www.blackhillsinfosec.com/?p=5544)

* Tools

  * [MailRaider](https://github.com/xorrior/EmailRaider)
  * [Phishery](https://github.com/ryhanson/phishery)
    * An SSL Enabled Basic Auth Credential Harvester with a Word Document
      Template URL Injector \* MailRaider is a tool that can be used to
      browse/search a user's Outlook folders as well as send phishing emails
      internally using their Outlook client.

### MS Office

* [Next Gen Office Malware v2.0 - Greg Linares Dagmar Knechtel - Hushcon17](https://prezi.com/view/eZ3CSNMxPMOfIWEHwTje/)
* DDE 
  * [Exploiting Office native functionality: Word DDE edition](https://www.securityforrealpeople.com/2017/10/exploiting-office-native-functionality.html)

* Macros

  * [Malicious Macro Generator](https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator)
    * Simple utility design to generate obfuscated macro that also include a AV
      / Sandboxes escape mechanism.
  * [macphish](https://github.com/cldrn/macphish)
    * Office for Mac Macro Payload Generator
  * [SimplyTemplate](https://github.com/killswitch-GUI/SimplyTemplate)
    * Phishing Template Generation Made Easy. The goal of this project was to
      hopefully speed up Phishing Template Gen as well as an easy way to ensure
      accuracy of your templates. Currently my standard Method of delivering
      emails is the Spear Phish in Cobalt strike so you will see proper settings
      for that by default.
  * [RobustPentestMacro](https://github.com/mgeeky/RobustPentestMacro)
    * This is a rich-featured Visual Basic macro code for use during Penetration
      Testing assignments, implementing various advanced post-exploitation
      techniques.
  * [Generate MS Office Macro Malware Script](https://github.com/enigma0x3/Generate-Macro/blob/master/Generate-Macro.ps1)
    * Standalone Powershell script that will generate a malicious Microsoft
      Office document with a specified payload and persistence method

* [InfoPhish](https://github.com/InfoPhish/InfoPhish)
* [luckystrike](https://github.com/Shellntel/luckystrike)

  * A PowerShell based utility for the creation of malicious Office macro
    documents.

* [VBad](https://github.com/Pepitoh/VBad)

  * VBad is fully customizable VBA Obfuscation Tool combined with an MS Office
    document generator. It aims to help Red & Blue team for attack or defense.

### Talks/Presentations

* [Three Years of Phishing - What We've Learned - Mike Morabito](http://www.irongeek.com/i.php?page=videos/centralohioinfosec2015/tech105-three-years-of-phishing-what-weve-learned-mike-morabito)

  * Cardinal Health has been aggressively testing and training users to
    recognize and avoid phishing emails. This presentation covers 3 years of
    lessons learned from over 18,000 employees tested, 150,000 individual
    phishes sent, 5 complaints, thousands of positive comments, and a dozen
    happy executives. Learn from actual phishing templates what works well,
    doesn,t work at all, and why? See efficient templates for education and
    reporting results.

* [Ichthyology: Phishing as a Science - BH USA 2017](https://www.youtube.com/watch?v=Z20XNp-luNA&app=desktop)
* [Modern Evasion Techniques Jason Lang - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)

  * As pentesters, we are often in need of working around security controls. In
    this talk, we will reveal ways that we bypass in-line network defenses, spam
    filters (in line and cloud based), as well as current endpoint solutions.
    Some techniques are old, some are new, but all work in helping to get a
    foothold established. Defenders: might want to come to this one.

* [Phishing Like The Pros - Luis Connection Santana - Derbycon 2013](https://www.irongeek.com/i.php?page=videos/derbycon3/1305-phishing-like-the-pros-luis-connection-santana)

  * This talk will discuss phishing techniques used by professionals during
    phishing campaigns and introduce PhishPoll, a PHP-based phishing framework
    for creating, managing, and tracking phishing campaigns.

* [MetaPhish - Valsmith, Colin Ames, and David Kerb - DEF CON 17](https://www.youtube.com/watch?v=3DYOMkkTK4A)
