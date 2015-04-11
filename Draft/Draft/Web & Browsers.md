##Web, Web Applications & Browsers




TOC

General
Cull
CMSs

Web Application Attacks & Write-ups
WebShells

11

###General

[Postcards from a Post-XSS World - Michael Zalewski](http://lcamtuf.coredump.cx/postxss/#dangling-markup-injection)
* This page is a rough collection of notes on some of the fundamental alternatives to direct script injection that would be available to attackers following the universal deployment of CSP or other security mechanisms designed to prevent the execution of unauthorized scripts. I hope to demonstrate that in many cases, the capabilities offered by these alternative methods are highly compatible with the goals of contemporary XSS attacks. 

[Javascript De-Obfuscation Tools Redux](http://www.kahusecurity.com/2014/javascript-deobfuscation-tools-redux/)
* Back in 2011, I took a look at several tools used to deobfuscate Javascript. This time around I will use several popular automated and semi-automated/manual tools to see how they would fare against today’s obfuscated scripts with the least amount of intervention.



[Unphp.net php decoder](http://www.unphp.net/decode/)

[Various forms of encoding/decoding web app](http://yehg.net/encoding/)


###Cull



[Oracle SQL Injection Guides & Whitepapers](https://haiderm.com/oracle-sql-injection-guides-and-whitepapers/)


http://www.grymoire.com/Security/Hardware.html

prompt.ml

[Client Identification Mechanisms](http://www.chromium.org/Home/chromium-security/client-identification-mechanisms)

Clickjacking attacks


[Hacking with Pictures - Syscan2015](http://www.slideshare.net/saumilshah/hacking-with-pictures-syscan-2015)



https://xss-game.appspot.com/

XSS game http://escape.alf.nu/



###Educational
[Intro to content Security Policy](www.html5rocks.com/en/tutorials/security/content-security-policy/)



###General Tools

[ParrotNG](https://github.com/ikkisoft/ParrotNG/releases)
* ParrotNG is a Java-based tool for automatically identifying vulnerable SWF files, built on top of swfdump. One JAR, two flavors: command line tool and Burp Pro Passive Scanner Plugin.

[HTTPie - curl for humans](https://github.com/jakubroztocil/httpie)
* HTTPie (pronounced aych-tee-tee-pie) is a command line HTTP client. Its goal is to make CLI interaction with web services as human-friendly as possible. It provides a simple http command that allows for sending arbitrary HTTP requests using a simple and natural syntax, and displays colorized output. HTTPie can be used for testing, debugging, and generally interacting with HTTP servers.

[leaps - shared text editing in Golang](https://github.com/denji/leaps)
* Leaps is a service for hosting collaboratively edited documents using operational transforms to ensure zero-collision synchronization across any number of editing clients.

[HTTrack - Website Copier](https://www.httrack.com/)
* It allows you to download a World Wide Web site from the Internet to a local directory, building recursively all directories, getting HTML, images, and other files from the server to your computer. HTTrack arranges the original site's relative link-structure. Simply open a page of the "mirrored" website in your browser, and you can browse the site from link to link, as if you were viewing it online. HTTrack can also update an existing mirrored site, and resume interrupted downloads. HTTrack is fully configurable, and has an integrated help system. 

[lan-js](https://github.com/jvennix-r7/lan-js)
* Probe LAN devices from a web browser.

[OWASP Mantra](http://www.getmantra.com/hackery/)
* “OWASP Mantra is a powerful set of tools to make the attacker's task easier”




###Brute Force/Fuzzing

[Dirbuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
* DirBuster is a multi threaded java application designed to brute force directories and files names on web/application servers. Often is the case now of what looks like a web server in a state of default installation is actually not, and has pages and applications hidden within. DirBuster attempts to find these.

[Go Buster](https://github.com/OJ/gobuster)
* Directory/file busting tool written in Go 
* Recursive, CLI-based, no java runtime

[WFuzz](https://code.google.com/p/wfuzz/
Wfuzz is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked (directories, servlets, scripts, etc), bruteforce GET and POST parameters for checking different kind of injections (SQL, XSS, LDAP,etc), bruteforce Forms parameters (User/Password), Fuzzing,etc

###CMS's
[Drupal Security Checklist](https://github.com/gfoss/attacking-drupal/blob/master/presentation/drupal-security-checklist.pdf)

[Drupal Attack Scripts](https://github.com/gfoss/attacking-drupal)
* Set of brute force scripts and Checklist

[CMSExplorer](https://code.google.com/p/cms-explorer/)
* CMS Explorer is designed to reveal the the specific modules, plugins, components and themes that various CMS driven web sites are running. Additionally, CMS Explorer can be used to aid in security testing. While it performs no direct security checks, the "explore" option can be used to reveal hidden/library files which are not typically accessed by web clients but are nonetheless accessible. This is done by retrieving the module's current source tree and then requesting those file names from the target system. These requests can be sent through a distinct proxy to help "bootstrap" security testing tools like Burp, Paros, Webinspect, etc. 

JoomScan: https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project
Joomla! is probably the most widely-used CMS out there due to its flexibility, user-friendlinesss, extensibility to name a few.So, watching its vulnerabilities and adding such vulnerabilities as KB to Joomla scanner takes ongoing activity.It will help web developers and web masters to help identify possible security weaknesses on their deployed Joomla! sites. No web security scanner is dedicated only one CMS. 

[Droopescan](https://github.com/droope/droopescan)
* A plugin-based scanner that aids security researchers in identifying issues with several CMSs, mainly Drupal & Silverstripe.

[Sparty - Sharepoint/Frontpage Auditing Tool](https://github.com/alias1/sparty)
* Sparty is an open source tool written in python to audit web applications using sharepoint and frontpage architecture. The motivation behind this tool is to provide an easy and robust way to scrutinize the security configurations of sharepoint and frontpage based web applications. Due to the complex nature of these web administration software, it is required to have a simple and efficient tool that gathers information, check access permissions, dump critical information from default files and perform automated exploitation if security risks are identified. A number of automated scanners fall short of this and Sparty is a solution to that.

[WPScan](https://github.com/wpscanteam/wpscan)
* WPScan is a black box WordPress vulnerability scanner. 

[BlindElephant Web Application Fingerprinter](http://blindelephant.sourceforge.net/)
* The BlindElephant Web Application Fingerprinter attempts to discover the version of a (known) web application by comparing static files at known locations against precomputed hashes for versions of those files in all all available releases. The technique is fast, low-bandwidth, non-invasive, generic, and highly automatable. 


###Site/Webapp Scanners
[skipfish](https://code.google.com/p/skipfish/)
* Skipfish is an active web application security reconnaissance tool. It prepares an interactive sitemap for the targeted site by carrying out a recursive crawl and dictionary-based probes. The resulting map is then annotated with the output from a number of active (but hopefully non-disruptive) security checks. The final report generated by the tool is meant to serve as a foundation for professional web application security assessments. 

[wikto](https://github.com/sensepost/wikto)
* Wikto is Nikto for Windows - but with a couple of fancy extra features including Fuzzy logic error code checking, a back-end miner, Google assisted directory mining and real time HTTP request/response monitoring. Wikto is coded in C# and requires the .NET framework. 

[RAWR - Rapid Assessment of Web Resources](https://bitbucket.org/al14s/rawr/wiki/Home)

[Arachni Web Scanner](http://www.arachni-scanner.com/)
* Arachni is an Open Source, feature-full, modular, high-performance Ruby framework aimed towards helping penetration testers and administrators evaluate the security of web applications.  It is smart, it trains itself by monitoring and learning from the web application's behavior during the scan process and is able to perform meta-analysis using a number of factors in order to correctly assess the trustworthiness of results and intelligently identify (or avoid) false-positives. 


###Web Proxies
[Burpsuite](http://portswigger.net/burp/)
* Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities. 

[C02](https://code.google.com/p/burp-co2/)
* Co2 includes several useful enhancements bundled into a single Java-based Burp Extension. The extension has it's own configuration tab with multiple sub-tabs (for each Co2 module). Modules that interact with other Burp tools can be disabled from within the Co2 configuration tab, so there is no need to disable the entire extension when using just part of the functionality. 

[ZAP - Zed Attack Proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
* The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications.  It is designed to be used by people with a wide range of security experience and as such is ideal for developers and functional testers who are new to penetration testing.  ZAP provides automated scanners as well as a set of tools that allow you to find security vulnerabilities manually.

[Paros - Web Proxy](http://sourceforge.net/projects/paros/)
* A Java based HTTP/HTTPS proxy for assessing web application vulnerability. It supports editing/viewing HTTP messages on-the-fly. Other featuers include spiders, client certificate, proxy-chaining, intelligent scanning for XSS and SQL injections etc.



###Web Shells
[Weevely](https://github.com/epinna/weevely3)
* Weevely is a command line web shell dinamically extended over the network at runtime used for remote administration and pen testing. It provides a weaponized telnet-like console through a PHP script running on the target, even in restricted environments.  The low footprint agent and over 30 modules shape an extensible framework to administrate, conduct a pen-test, post-exploit, and audit remote web accesses in order to escalate privileges and pivot deeper in the internal networks.
* [Getting Started](https://github.com/epinna/weevely3/wiki#getting-started)

[b374k shell 3.2](https://github.com/b374k/b374k)
* This PHP Shell is a useful tool for system or web administrator to do remote management without using cpanel, connecting using ssh, ftp etc. All actions take place within a web browser







 







###Non-Attack Writeups
[Security and Open Redirects  Impact of 301-ing people in 2013](https://makensi.es/rvl/openredirs/#/)

[DOM Clobbering Attack](http://www.thespanner.co.uk/2013/05/16/dom-clobbering/)



###Securing Web Applications/Checklists


[Center for Internet Security Apache Server 2.4 Hardening Guide](https://benchmarks.cisecurity.org/tools2/apache/CIS_Apache_HTTP_Server_2.4_Benchmark_v1.1.0.pdf)

[Securing Web Application Technologies Checklist](http://www.securingthehuman.org/developer/swat)

[OWASP Testing Checklist](https://www.owasp.org/index.php/Testing_Checklist)

[WebAppSec Testing Checklist](http://tuppad.com/blog/wp-content/uploads/2012/03/WebApp_Sec_Testing_Checklist.pdf)

[OWASP Web Application Security Testing Cheat Sheet](https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet)

[Magical Code Injection Rainbow Framework](https://github.com/SpiderLabs/MCIR)
* The Magical Code Injection Rainbow! MCIR is a framework for building configurable vulnerability testbeds. MCIR is also a collection of configurable vulnerability testbeds. Has testing lessons for xss/csrf/sql


###Web Application Firewalls


[ModSecurity](https://github.com/SpiderLabs/ModSecurity)
* ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx that is developed by Trustwave's SpiderLabs. It has a robust event-based programming language which provides protection from a range of attacks against web applications and allows for HTTP traffic monitoring, logging and real-time analys

[Shadow Daemon](https://shadowd.zecure.org/overview/introduction/)
* Shadow Daemon is a collection of tools to detect, protocol and prevent attacks on web applications. Technically speaking, Shadow Daemon is a web application firewall that intercepts requests and filters out malicious parameters. It is a modular system that separates web application, analysis and interface to increase security, flexibility and expandability. Shadow Daemon is free software. It is released under the license GPLv2, so its source code can be examined, modified and distributed by everyone.

[Bypassing WAFs](http://www.nethemba.com/bypassing-waf.pdf)



###Web Application Attacks & Write-ups

[Relative Path Overwrite Explanation/Writeup](http://www.thespanner.co.uk/2014/03/21/rpo/)
* RPO (Relative Path Overwrite) is a technique to take advantage of relative URLs by overwriting their target file. To understand the technique we must first look into the differences between relative and absolute URLs. An absolute URL is basically the full URL for a destination address including the protocol and domain name whereas a relative URL doesn’t specify a domain or protocol and uses the existing destination to determine the protocol and domain.

[Attacking Adobe ColdFusion](http://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html)

[ColdFusion Security Resources](https://www.owasp.org/index.php/ColdFusion_Security_Resources)

[ColdFusion for Penetration Testers](http://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers)




###LFI & RFI

[LFI Local File Inclusion Techniques (paper)](http://www.ush.it/2008/08/18/lfi2rce-local-file-inclusion-to-remote-code-execution-advanced-exploitation-proc-shortcuts/) 
* This paper exposes the ability from the attacker standpoint to use /proc in order to exploit LFI (Local File Inclusion) vulnerabilities. While using /proc for such aim is well known this one is a specific technique that was not been previously published as far as we know. A tool to automatically exploit LFI using the shown approach is released accordingly. 
* [Update: a third (known) technique has been dissected here](http://www_ush_it/2008/07/09/local-file-inclusion-lfi-of-session-files-to-root-escalation/ ) 

[Liffy](https://github.com/rotlogix/liffy)
* Liffy is a Local File Inclusion Exploitation tool. 

###XSS
[Writing an XSS Worm](http://blog.gdssecurity.com/labs/2013/5/8/writing-an-xss-worm.html)

[3 Types of XSS](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting)
	* Dom-based
	* Reflected
	* Persistent

[Cross Frame Scripting](https://www.owasp.org/index.php/Cross_Frame_Scripting)

[Cross Site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29


##(NO)SQL Injection
[SQL Injection Cheat Sheet](http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/)

[SQL Injection wiki](http://www.sqlinjectionwiki.com/)

[SQL Injection Knowledge Base](http://websec.ca/kb/sql_injection#MySQL_Testing_Injection)

[Pen Testing MongoDB](http://www.irongeek.com/i.php?page=videos/derbycon4/t408-making-mongo-cry-attacking-nosql-for-pen-testers-russell-butturini)

[Laduanum](http://laudanum.sourceforge.net/)
* “Laudanum is a collection of injectable files, designed to be used in a pentest when SQL injection flaws are found and are in multiple languages for different environments.They provide functionality such as shell, DNS query, LDAP retrieval and others.”

[Making Mongo Cry Attacking NoSQL for Pen Testers Russell Butturini](https://www.youtube.com/watch?v=NgsesuLpyOg)

[MongoDB: Typical Security Weaknesses in a NoSQL DB](http://blog.spiderlabs.com/2013/03/mongodb-security-weaknesses-in-a-typical-nosql-database.html)




SQLi Lab lessons
From: https://github.com/Audi-1/sqli-labs
SQLI-LABS is a platform to learn SQLI Following labs are covered for GET and POST scenarios: 
Error Based Injections (Union Select) 
String
Integer
Error Based Injections (Double Injection Based)
BLIND Injections: 1.Boolian Based 2.Time Based
Update Query Injection.
Insert Query Injections.
Header Injections. 1.Referer based. 2.UserAgent based. 3.Cookie based.
Second Order Injections
Bypassing WAF 
Bypassing Blacklist filters Stripping comments Stripping OR & AND Stripping SPACES and COMMENTS Stripping UNION & SELECT
Impidence mismatch
Bypass addslashes()
Bypassing mysql_real_escape_string. (under special conditions)
Stacked SQL injections.
Secondary channel extraction




Attacking Browsers
[White Lightning Attack Platform](https://github.com/TweekFawkes/White_Lightning/tree/master/var/www)

[BeEF Browser Exploitation Framework](http://beefproject.com/

[Technical analysis of client identification mechanisms](http://www.chromium.org/Home/chromium-security/client-identification-mechanisms) 




###HTML 5


[SH5ARK](http://sh5ark.professionallyevil.com)
* The Securing HTML5 Assessment Resource Kit, or SH5ARK, is an open source project that provides a repository of HTML5 features, proof-of-concept attack code, and filtering rules. The purpose of this project is to provide a single repository that can be used to collect sample code of vulnerable HTML5 features, actual attack code, and filtering rules to help prevent attacks and abuse of these features. The intent of the project is to bring awareness to the opportunities that HTML5 is providing for attackers, to help identify these attacks, and provide measures for preventing them

* [Presentation on SH5ARK](https://www.youtube.com/watch?v=1ZZ-vIwmWx4)

* [GetSH5ARK here](http://sourceforge.net/projects/sh5ark/)


###Papers

[The Spy in the Sandbox – Practical Cache Attacks in Javascript](http://iss.oy.ne.ro/SpyInTheSandbox.pdf)
* We present the first micro-architectural side-channel at- tack which runs entirely in the browser. In contrast to other works in this genre, this attack does not require the attacker to install any software on the victim’s machine – to facilitate the attack, the victim needs only to browse to an untrusted webpage with attacker-controlled con- tent. This makes the attack model highly scalable and ex- tremely relevant and practical to today’s web, especially since most desktop browsers currently accessing the In- ternet are vulnerable to this attack. Our attack, which is an extension of the last-level cache attacks of Yarom et al. [23], allows a remote adversary recover information belonging to other processes, other users and even other virtual machines running on the same physical host as the victim web browser. We describe the fundamentals behind our attack, evaluate its performance using a high bandwidth covert channel and finally use it to construct a system-wide mouse/network activity logger. Defending against this attack is possible, but the required counter- measures can exact an impractical cost on other benign uses of the web browser and of the computer.

[Self-Exfiltration: The Dangers of Browser-Enforced Information Flow Control](http://ericchen.me/self_exfiltration.pdf)
* Abstract —Since the early days of Netscape, browser vendors and web security researchers have restricted out-going data based on its destination. The security argument accompanying these mechanisms is that they prevent sensitive user data from being sent to the attacker’s domain. However, in this paper, we show that regulating web information flow based on its destination server is an inherently flawed security practice. It is vulnerable to self-exfiltration attacks, where an adversary stashes stolen information in the database of a whitelisted site, then later independently connects to the whitelisted site to retrieve the information. We describe eight existing browser security mechanisms that are vulnerable to these “self-exfiltration” attacks. Furthermore, we discovered at least one exfiltration channel for each of the Alexa top 100 websites. None of the existing information flow control mechanisms we surveyed are sufficient to protect data from being leaked to the attacker. Our goal is to prevent browser vendors and researchers from falling into this trap by designing more systems that are vulnerable to self-exfiltration.

[The Devil is in the Constants: Bypassing Defenses in Browser JIT Engines](http://users.ics.forth.gr/~elathan/papers/ndss15.pdf)
* Abstract —Return-oriented programming (ROP) has become the dominant form of vulnerability exploitation in both user and kernel space. Many defenses against ROP exploits exist, which can significantly raise the bar against attackers. Although protecting existing code, such as applications and the kernel, might be possible, taking countermeasures against dynamic code, i.e., code that is generated only at run-time, is much harder. Attackers have already started exploiting Just-in-Time (JIT) engines, available in all modern browsers, to introduce their (shell)code (either native code or re-usable gadgets) during JIT compilation, and then taking advantage of it. Recognizing this immediate threat, browser vendors started employing defenses for hardening their JIT engines. In this paper, we show that—no matter the employed defenses—JIT engines are still exploitable using solely dynamically generated gadgets. We demonstrate that dynamic ROP payload construction is possible in two modern web browsers without using any of the available gadgets contained in the browser binary or linked libraries. First, we exploit an open source JIT engine (Mozilla Firefox) by feeding it malicious JavaScript, which once processed generates all re- quired gadgets for running any shellcode successfully. Second, we exploit a proprietary JIT engine, the one in the 64-bit Microsoft Internet Explorer, which employs many undocumented, specially crafted defenses against JIT exploitation. We manage to bypass all of them and create the required gadgets for running any shellcode successfully. All defensive techniques are documented in this paper to assist other researchers. Furthermore, besides showing how to construct ROP gadgets on-the-fly, we also show how to discover them on-the-fly, rendering current randomization schemes ineffective. Finally, we perform an analysis of the most important defense currently employed, namely constant blinding , which shields all three-byte or larger immediate values in the JIT buffer for hindering the construction of ROP gadgets. Our analysis suggests that extending constant blinding to all immediate values (i.e., shielding 1-byte and 2-byte constants) dramatically decreases the JIT engine’s performance, introducing up to 80% additional instructions.

[Cookieless Monster: Exploring the Ecosystem of Web-based Device Fingerprinting](http://securitee.org/files/cookieless_sp2013.pdf)
* Abstract —The web has become an essential part of our society and is currently the main medium of information delivery. Billions of users browse the web on a daily basis, and there are single websites that have reached over one billion user accounts. In this environment, the ability to track users and their online habits can be very lucrative for advertising companies, yet very intrusive for the privacy of users. In this paper, we examine how web-based device fingerprint- ing currently works on the Internet. By analyzing the code of three popular browser-fingerprinting code providers, we reveal the techniques that allow websites to track users without the need of client-side identifiers. Among these techniques, we show how current commercial fingerprinting approaches use questionable practices, such as the circumvention of HTTP proxies to discover a user’s real IP address and the installation of intrusive browser plugins. At the same time, we show how fragile the browser ecosystem is against fingerprinting through the use of novel browser- identifying techniques. With so many different vendors involved in browser development, we demonstrate how one can use diversions in the browsers’ implementation to distinguish successfully not only the browser-family, but also specific major and minor versions. Browser extensions that help users spoof the user-agent of their browsers are also evaluated. We show that current commercial approaches can bypass the extensions, and, in addition, take advantage of their shortcomings by using them as additional fingerprinting features.

[SSL/TLS Interception Proxies and Transitive Trust](http://media.blackhat.com/bh-eu-12/Jarmoc/bh-eu-12-Jarmoc-SSL_TLS_Interception-WP.pdf)
* Secure Sockets Layer (SSL) [ 1 ] and its successor Transport Layer Security (TLS) [ 2 ] have become key components of the modern Internet . The privacy, integrity, and authenticity [ 3 ] [ 4 ] provided by these protocols are critical to allowing sensitive communications to occur . Without these systems, e - commerce, online banking , and business - to - business exchange of information would likely be far less frequent. Threat actors have also recognized the benefits of transport security, and they are increasingly turning to SSL to hide their activities . Advanced Persistent Threat ( APT ) attackers [ 5 ] , botnets [ 6 ] , and eve n commodity web attacks can leverage SSL encryption to evade detection. To counter these tactics, organizations are increasingly deploying security controls that intercept end - to - end encrypted channels. Web proxies, data loss prevention ( DLP ) systems, spec ialized threat detection solutions, and network intrusion prevention systems ( N IPS ) offer functionality to intercept, inspect , and filter encrypted traffic. Similar functionality is present in lawful intercept systems and solutions enabling the broad surve illance of encrypted communications by governments. Broadly classified as “SSL/TLS interception proxies ,” these solutions act as a “ man in the middle , ” violating the end - to - end security promises of SSL. This type of interception comes at a cost . Intercepti ng SSL - encrypted connections sacrifices a degree of privacy and integrity for the benefit of content inspection, often at the risk of authenticity and endpoint validation . Implementers and designers of SSL interception proxies should consider these risks and understand how their systems operate in unusual circumstances


[Scriptless Attacks – Stealing the Pie Without Touching the Sill](http://www.syssec.rub.de/media/emma/veroeffentlichungen/2012/08/16/scriptlessAttacks-ccs2012.pdf)
* Due to their high practical impact, Cross-Site Scripting (X SS) attacks have attracted a lot of attention from the security community members. In the same way, a plethora of more or less effective defense techniques have been proposed, ad- dressing the causes and effects of XSS vulnerabilities. As a result, an adversary often can no longer inject or even execute arbitrary scripting code in several real-life scen arios. In this paper, we examine the attack surface that remains after XSS and similar scripting attacks are supposedly mit- igated by preventing an attacker from executing JavaScript code. We address the question of whether an attacker really needs JavaScript or similar functionality to perform attac ks aiming for information theft. The surprising result is that an attacker can also abuse Cascading Style Sheets (CSS) in combination with other Web techniques like plain HTML, inactive SVG images or font files. Through several case studies, we introduce the so called scriptless attacks and demonstrate that an adversary might not need to execute code to preserve his ability to extract sensitive informati on from well protected websites. More precisely, we show that an attacker can use seemingly benign features to build side channel attacks that measure and exfiltrate almost arbitrar y data displayed on a given website. We conclude this paper with a discussion of potential mit- igation techniques against this class of attacks. In additi on, we have implemented a browser patch that enables a website to make a vital determination as to being loaded in a de- tached view or pop-up window. This approach proves useful for prevention of certain types of attacks we here discuss.






###Miscellaneous

[unindexed](https://github.com/mroth/unindexed/blob/master/README.md)
* The site is constantly searching for itself in Google, over and over and over, 24 hours a day. The instant it finds itself in Google search results, the site will instantaneously and irrevocably securely delete itself. Visitors can contribute to the public content of the site, these contributions will also be destroyed when the site deletes itself.

[COWL: A Confinement System for the Web](http://cowl.ws/)
* Robust JavaScript confinement system for modern web browsers. COWL introduces label-based mandatory access control to browsing contexts (pages, iframes, etc.) in a way that is fully backward-compatible with legacy web content. 
[Paper](http://www.scs.stanford.edu/~deian/pubs/stefan:2014:protecting.pdf)


