# Web, Web Applications & Browsers

Web TOC
* General](#general)
* [Purposely Vulnerable Web Apps](#pvuln)
* [Securing Web Applications Checklists](#checklist)
* [Talks & Presentations](#talks)
* [General Tools](#generalt)
* [Different Typs of Web Based Attacks](#difatk)
	* [Abuse of Functionality](#abuse)
	* [Brute Force Fuzzing](#brute)
	* [Attacking Continous Integration Systems](#ci)
	* [Cross-Site-Request Forgery](#csrf)
	* [De/Encoders](#encode)
	* [Data Structure Attacks](#dsa)
	* [Embedded Malicious Code](#emc)
	* [Exploitation of Authentication](#eoa) 
	* [Injection Based Attacks](#ija)
		* OS Command Injection 
		* (NO)SQL Injection
	* [JNDI](#jndi)
	* [Java Serialization Attacks](#jsa) 
	* [JSON Web Tokens](#jwt)
	* [LFI & RFI](#lrfi)
	* [Path Traversal Attacks](#pta)
	* [Server Side Request Forgery](#ssrf)
	* [Server Side Include](#ssi)
	* [Server Side Template Injection](#ssti)
	* [Timing Attacks](#timing)
	* [Web Shells](#shells)
	* [XSS](#xss)
* [API Stuff](#api)
* [Attacking Browsers](#atkb)
* [CMS Specific Tools](#cms)
* [HTML5](#html5)
* [Javascript](#javascript)
* [Java Server Faces](#jsf)
* [REST & Web Services](#rest)
* [PHP](#php)
* [Ruby](#ruby)
* [Scraping](#scraping)
* [Site/WebApp Scanners](#scanners)
* [Web Sockets](#websocket)
* [Web Proxies](#webproxy)
* [Web Application Firewalls(WAFs)](#waf)
	* [Bypassing WAFs](#bwaf)
* [Web Application Attack Writeups](#writeups)
* [Non-Attack Writeups](#nonwriteup)
* [Papers](#papers)
* [Miscellaneous](#misc)
* [Burp Stuff/Plugins](#burp)
* [AWS stuff](#aws)
* [Google Compute Cloud/AppEngine](#gcc)




#### Sort
* Fix ToC
* Add CSP
	* [Intro to content Security Policy](http://www.html5rocks.com/en/tutorials/security/content-security-policy/)
* Add SOAP
* Clickjack(ing)
* Websockets

* [HackerOne H1-212 Capture the Flag Solution - Corben Douglas](http://www.sxcurity.pro/H1-212%20CTF%20Solution.pdf)
* [Detecting and Exploiting the HTTP PUT Method](http://www.smeegesec.com/2014/10/detecting-and-exploiting-http-put-method.html)
* [AngularJS Security Documentation](https://docs.angularjs.org/guide/security)
* [Hacking with Pictures - Syscan2015](http://www.slideshare.net/saumilshah/hacking-with-pictures-syscan-2015)
* [File scanner web app (Part 1 of 5): Stand-up and webserver](http://0xdabbad00.com/2013/09/02/file-scanner-web-app-part-1-of-5-stand-up-and-webserver/)
* [ebay.com: RCE using CCS](http://secalert.net/#ebay-rce-ccs)
* [Abusing Google App Scripting Through Social Engineering](http://www.redblue.team/2017/02/abusing-google-app-scripting-through.html)
* [Unrestricted File Upload Security Testing - Aptive](https://www.aptive.co.uk/blog/unrestricted-file-upload-testing/)

* [Cross Site History Manipulation - OWASP](https://www.owasp.org/index.php/Cross_Site_History_Manipulation_(XSHM))

* **Reflected File Download**
	* [Reflected File Download - A New Web Attack Vector - BHEU 2014](https://www.youtube.com/watch?v=dl1BJUNk8V4)
		* Skip to 19:24 for technical content
	* [Paper](https://drive.google.com/file/d/0B0KLoHg_gR_XQnV4RVhlNl96MHM/view)

* [How to configure Json.NET to create a vulnerable web API](https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html)

* **Struts**
	* [Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution](https://www.exploit-db.com/exploits/41570/)
* [Tricks to improve web app excel export attacks - Jerome Smith - CamSec2016](https://www.slideshare.net/exploresecurity/camsec-sept-2016-tricks-to-improve-web-app-excel-export-attacks)

https://github.com/stephenbradshaw/breakableflask
https://github.com/JasonHinds13/hackable
https://github.com/omarkurt/flask-injection
* [Fingerprinter](https://github.com/erwanlr/Fingerprinter)
	*  CMS/LMS/Library etc Versions Fingerprinter. This script's goal is to try to find the version of the remote application/third party script etc by using a fingerprinting approach.


#### End Sort



----------------
### <a name="general">General</a>
* **101**
* **Cheat Sheets**
	* [Attack Surface Analysis Cheat Sheet](https://www.owasp.org/index.php/Attack_Surface_Analysis_Cheat_Sheet)
* **Documentation**
	* [DOM - Standard](https://dom.spec.whatwg.org/)
	* [DOM Living Standard](https://dom.spec.whatwg.org/)
	* [HTML 5 Standards](http://w3c.github.io/html/)
	* [Transport Layer Security (TLS) Extensions](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
	* [Web IDL Standards](https://heycam.github.io/webidl/)
	* [Object MetaInformation](https://www.w3.org/Protocols/HTTP/Object_Headers.html#public)
* **Educational**
	* [The Tale of a Fameless but Widespread Web Vulnerability Class - Veit Hailperin](https://www.youtube.com/watch?v=5qA0CtS6cZ4)
		* Two keys components account for finding vulnerabilities of a certain class: awareness of the vulnerability and ease of finding the vulnerability. Cross-Site Script Inclusion (XSSI) vulnerabilities are not mentioned in the de facto standard for public attention - the OWASP Top 10. Additionally there is no public tool available to facilitate finding XSSI. The impact reaches from leaking personal information stored, circumvention of token-based protection to complete compromise of accounts. XSSI vulnerabilities are fairly wide spread and the lack of detection increases the risk of each XSSI. In this talk we are going to demonstrate how to find XSSI, exploit XSSI and also how to protect against XSSI.
	* [Discover DevTools](https://www.codeschool.com/courses/discover-devtools)
		* Learn how Chrome DevTools can sharpen your dev process and discover the tools that can optimize your workflow and make life easier.
	* [Postcards from a Post-XSS World - Michael Zalewski](http://lcamtuf.coredump.cx/postxss/#dangling-markup-injection)
		* This page is a rough collection of notes on some of the fundamental alternatives to direct script injection that would be available to attackers following the universal deployment of CSP or other security mechanisms designed to prevent the execution of unauthorized scripts. I hope to demonstrate that in many cases, the capabilities offered by these alternative methods are highly compatible with the goals of contemporary XSS attacks.
* **General**
	* [OWASP Top Ten Project](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)
		* The OWASP Top 10 is a powerful awareness document for web application security. It represents a broad consensus about the most critical security risks to web applications. Project members include a variety of security experts from around the world who have shared their expertise to produce this list. 
	* [JSFuck](http://www.jsfuck.com/)
		* JSFuck is an esoteric and educational programming style based on the atomic parts of JavaScript. It uses only six different characters to write and execute code.
	* [How to Obscure Any URL](http://www.pc-help.org/obscure.htm)
	* [HTTP Evasion](http://noxxi.de/research/http-evader-explained-8-borderline-robustness.html)	
	* [Big List of Naughty Strings](https://github.com/minimaxir/big-list-of-naughty-strings)
		* The Big List of Naughty Strings is an evolving list of strings which have a high probability of causing issues when used as user-input data. This is intended for use in helping both automated and manual QA testing; useful for whenever your QA engineer walks into a bar.

* **Interesting Attacks that don't fit elsewhere**
	* [Abusing Certificate Transparency Or How To Hack Web Applications BEfore Installation - Hanno Bock](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Hanno-Boeck-Abusing-Certificate-Transparency-Logs.pdf)
	* [Typosquatting programming language package managers](http://incolumitas.com/2016/06/08/typosquatting-package-managers/)
	* **General Reconnaissance Techniques**
		* [Insecure HTTP Header Removal](https://www.aspectsecurity.com/blog/insecure-http-header-removal)
	* **CSV Injection**
		* [From CSV to CMD to qwerty](http://www.exploresecurity.com/from-csv-to-cmd-to-qwerty/)
		* [Comma Separated Vulnerabilities](https://www.contextis.com/blog/comma-separated-vulnerabilities)
			* This post introduces Formula Injection, a technique for exploiting ‘Export to Spreadsheet’ functionality in web applications to attack users and steal spreadsheet contents. It also details a command injection exploit for Apache OpenOffice and LibreOffice that can be delivered using this technique.
		* [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html)




------------------
### <a name="pvuln"></a>Purposely Vulnerable Web Applications/Testing Grounds
* [OWASP Vulnerable Web Applications Directory Project/Pages/Offline](https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project/Pages/Offline)
* [OWASP Juice Shop](https://github.com/bkimminich/juice-shop)
	* OWASP Juice Shop is an intentionally insecure web application written entirely in Javascript which encompasses the entire range of OWASP Top Ten and other severe security flaws.
* [Pwning OWASP Juice Shop](https://leanpub.com/juice-shop)
* [Hackazon](https://github.com/rapid7/hackazon)
	* Hackazon is a free, vulnerable test site that is an online storefront built with the same technologies used in today’s rich client and mobile applications. Hackazon has an AJAX interface, strict workflows and RESTful API’s used by a companion mobile app providing uniquely-effective training and testing ground for IT security professionals. And, it’s full of your favorite vulnerabilities like SQL Injection, cross-site scripting and so on.





----------------
### <a name="checklist">Securing Web Applications/Checklists</a>
* **Attacking**
	* [OWASP Testing Checklist](https://www.owasp.org/index.php/Testing_Checklist)
	* [WebAppSec Testing Checklist](http://tuppad.com/blog/wp-content/uploads/2012/03/WebApp_Sec_Testing_Checklist.pdf)
	* [OWASP Web Application Security Testing Cheat Sheet](https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet)

* **Securing**
	* [Center for Internet Security Apache Server 2.4 Hardening Guide](https://benchmarks.cisecurity.org/tools2/apache/CIS_Apache_HTTP_Server_2.4_Benchmark_v1.1.0.pdf)
	* [Securing Web Application Technologies Checklist](http://www.securingthehuman.org/developer/swat)
	* [Wordpress Security Guide - WPBeginner](http://www.wpbeginner.com/wordpress-security/)
	* [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist/blob/master/README.md)
	* [OWASP Application Security Verification Standard Project(ASVS)](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
		* The OWASP Application Security Verification Standard (ASVS) Project provides a basis for testing web application technical security controls and also provides developers with a list of requirements for secure development. 
	* [Magical Code Injection Rainbow Framework](https://github.com/SpiderLabs/MCIR)
		* The Magical Code Injection Rainbow! MCIR is a framework for building configurable vulnerability testbeds. MCIR is also a collection of configurable vulnerability testbeds. Has testing lessons for xss/csrf/sql





----------------
### <a name="talks"></a>General Talks &  Presentations
* **General**
	* [The Website Obesity Crisis](http://idlewords.com/talks/website_obesity.htm)
	* [The AppSec Starter Kit Timothy De Block](https://www.youtube.com/watch?v=KMz8lWNAUmg)
	* [Attacking Modern SaaS Companies](https://github.com/cxxr/talks/blob/master/2017/nolacon/Attacking%20Modern%20SaaS%20Companies%20%E2%80%93%20NolaCon.pdf)
		* [Presentation](https://www.youtube.com/watch?v=J0otoKRh1Vk&app=desktop)
	* [Server-side browsing considered harmful](http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)
	* [Web Application testing approach and cheating to win Jim McMurry Lee Neely Chelle Clements - Derbycon7](https://www.youtube.com/watch?v=Z8ZAv_EN-9M) 
* **XSS**
	* [DOM Based Angular Sandbox Escapes by Gareth Heyes - BSides Manchester2017](https://www.youtube.com/watch?v=jlSI5aVTEIg&index=16&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)
* **Scanning**
	* [Backslash Powered Scanning: Hunting Unknown Vulnerability Classes](http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html)
		* Existing web scanners search for server-side injection vulnerabilities by throwing a canned list of technology-specific payloads at a target and looking for signatures - almost like an anti-virus. In this document, I'll share the conception and development of an alternative approach, capable of finding and confirming both known and unknown classes of injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering.
	


----------------
### <a name="generalt">General Tools</a>
* **Site Imaging/Taking Pictures**
	* [PowerWebShot](https://github.com/dafthack/PowerWebShot)
		* A PowerShell tool for taking screenshots of multiple web servers quickly.
	* [HTTrack - Website Copier](https://www.httrack.com/)
		* It allows you to download a World Wide Web site from the Internet to a local directory, building recursively all directories, getting HTML, images, and other files from the server to your computer. HTTrack arranges the original site's relative link-structure. Simply open a page of the "mirrored" website in your browser, and you can browse the site from link to link, as if you were viewing it online. HTTrack can also update an existing mirrored site, and resume interrupted downloads. HTTrack is fully configurable, and has an integrated help system. 
	* [Kraken - Web Interface Survey Tool](https://github.com/Sw4mpf0x/Kraken)
		* [Blogpost](https://pentestarmoury.com/2017/01/31/kraken-web-interface-survey-tool/)
* **General**
	* [HTTPie - curl for humans](https://gith*ub.com/jakubroztocil/httpie)
		* HTTPie (pronounced aych-tee-tee-pie) is a command line HTTP client. Its goal is to make CLI interaction with web services as human-friendly as possible. It provides a simple http command that allows for sending arbitrary HTTP requests using a simple and natural syntax, and displays colorized output. HTTPie can be used for testing, debugging, and generally interacting with HTTP servers.
	* [leaps - shared text editing in Golang](https://github.com/denji/leaps)
		* Leaps is a service for hosting collaboratively edited documents using operational transforms to ensure zero-collision synchronization across any number of editing clients.
	* [OWASP Mantra](http://www.getmantra.com/hackery/)
		* “OWASP Mantra is a powerful set of tools to make the attacker's task easier”
	* [dvcs-ripper](https://github.com/kost/dvcs-ripper)
		* Rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr, ... It can rip repositories even when directory browsing is turned off.
	* [Caja](https://developers.google.com/caja/)
		*  The Caja Compiler is a tool for making third party HTML, CSS and JavaScript safe to embed in your website. It enables rich interaction between the embedding page and the embedded applications. Caja uses an object-capability security model to allow for a wide range of flexible security policies, so that your website can effectively control what embedded third party code can do with user data.
	* [Home-Assistant](https://home-assistant.io/)
		* Open Source home automation platform
	* [HTTPLeaks](https://github.com/cure53/HTTPLeaks)
		* HTTPLeaks - All possible ways, a website can leak HTTP requests
	* [SSleuth](https://github.com/sibiantony/ssleuth)
		* A firefox add-on to rate the quality of HTTPS connections
* **JS-based scanning**
	* [lan-js](https://github.com/jvennix-r7/lan-js)
		* Probe LAN devices from a web browser.
	* [sonar.js](https://thehackerblog.com/sonar-a-framework-for-scanning-and-exploiting-internal-hosts-with-a-webpage/)
		* A Framework for Scanning and Exploiting Internal Hosts With a Webpage
* **Recon**
	* **General**
		* [hackability](https://github.com/PortSwigger/hackability)
			* Rendering Engine Hackability Probe performs a variety of tests to discover what the unknown rendering engine supports. To use it simply extract it to your web server and visit the url in the rendering engine you want to test. The more successful probes you get the more likely the target engine is vulnerable to attack.
	* **Content/Folder Discovery**
		* [Tachyon](https://github.com/delvelabs/tachyon)
			* Tachyon is a Fast Multi-Threaded Web Discovery Tool
		* [dirsearch](https://github.com/maurosoria/dirsearch)
			* dirsearch is a simple command line tool designed to brute force directories and files in websites.
	
	* **Web Page**
		* [HTCAP](https://github.com/segment-srl/htcap)
			* htcap is a web application scanner able to crawl single page application (SPA) in a recursive manner by intercepting ajax calls and DOM changes
		* [gethead](https://github.com/httphacker/gethead)
			* HTTP Header Analysis Vulnerability Tool 
	* **Web Server**	
		* [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
		* [httprecon - Advanced Web Server Fingerprinting](https://github.com/scipag/httprecon-win32)
			* The httprecon project is doing some research in the field of web server fingerprinting, also known as http fingerprinting. The goal is the highly accurate identification of given httpd implementations. This is very important within professional vulnerability analysis. Besides the discussion of different approaches and the documentation of gathered results also an implementation for automated analysis is provided. This software shall improve the easyness and efficiency of this kind of enumeration. Traditional approaches as like banner-grabbing, status code enumeration and header ordering analysis are used. However, many other analysis techniques were introduced to increase the possibilities of accurate web server fingerprinting. Some of them were already discussed in the book Die Kunst des Penetration Testing (Chapter 9.3, HTTP-Fingerprinting, pp. 530-550).
	* **Virtual Hosts/VHOSTs**
		* [virtual-host-discovery](https://github.com/jobertabma/virtual-host-discovery)
			* This is a basic HTTP scanner that'll enumerate virtual hosts on a given IP address. During recon, this might help expand the target by detecting old or deprecated code. It may also reveal hidden hosts that are statically mapped in the developer's /etc/hosts file.
		* [blacksheepwall](https://github.com/tomsteele/blacksheepwall)
			* blacksheepwall is a hostname reconnaissance tool




----------------
#### <a name="abuse"></a>Abuse of Functionality
* [jsgifkeylogger](https://github.com/wopot/jsgifkeylogger)
	* a javascript keylogger included in a gif file This is a PoC



----------------
#### <a name="brute">Brute Force/Fuzzing</a>
* [Dirbuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
	* DirBuster is a multi threaded java application designed to brute force directories and files names on web/application servers. Often is the case now of what looks like a web server in a state of default installation is actually not, and has pages and applications hidden within. DirBuster attempts to find these.
* [Go Buster](https://github.com/OJ/gobuster)
	* Directory/file busting tool written in Go 
	* Recursive, CLI-based, no java runtime
* [WFuzz](https://code.google.com/p/wfuzz/)
	* Wfuzz is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked (directories, servlets, scripts, etc), bruteforce GET and POST parameters for checking different kind of injections (SQL, XSS, LDAP,etc), bruteforce Forms parameters (User/Password), Fuzzing,etc
* [dirsearch](https://github.com/maurosoria/dirsearch)
	* dirsearch is a simple command line tool designed to brute force directories and files in websites.
* [Tachyon](https://github.com/delvelabs/tachyon)
		* Tachyon is a Fast Multi-Threaded Web Discovery Tool
* [Syntribos](https://github.com/openstack/syntribos)
	* Given a simple configuration file and an example HTTP request, syntribos can replace any API URL, URL parameter, HTTP header and request body field with a given set of strings. Syntribos iterates through each position in the request automatically. Syntribos aims to automatically detect common security defects such as SQL injection, LDAP injection, buffer overflow, etc. In addition, syntribos can be used to help identify new security defects by automated fuzzing.


----------------
#### Attacking Continous Integration Systems
* [cider - Continuous Integration and Deployment Exploiter](https://github.com/spaceB0x/cider)
	* CIDER is a framework written in node js that aims to harness the functions necessary for exploiting Continuous Integration (CI) systems and their related infrastructure and build chain (eg. Travis-CI, Drone, Circle-CI). Most of the exploits in CIDER exploit CI build systems through open GitHub repositories via malicious Pull Requests. It is built modularly to encourage contributions, so more exploits, attack surfaces, and build chain services will be integrated in the future.
* [Rotten Apple](https://github.com/claudijd/rotten_apple)
	* A tool for testing continuous integration (CI) or continuous delivery (CD) system security
* [Exploiting Continuous Integration (CI) and Automated Build Systems - spaceb0x](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-spaceB0x-Exploiting-Continuous-Integration.pdf)


----------------
#### <a name="csrf"></a>Cross Site Request Forgery (CSRF)
* **101**
	* [Cross Site Request Forgery - OWASP](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29)
* **Articles/Blogposts/Presentations/Talks/Videos**
	* [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)\_Prevention_Cheat_Sheet)
	* [The OWASP Top Ten and ESAPI – Part 5 – Cross Site Request Forgery (CSRF)](http://www.jtmelton.com/2010/05/16/the-owasp-top-ten-and-esapi-part-6-cross-site-request-forgery-csrf/)
	* [Testing for CSRF (OTG-SESS-005) - OWASP](https://www.owasp.org/index.php/Testing_for_CSRF_(OTG-SESS-005)\)
	* [RequestRodeo: Client Side Protection against Session Riding - Martin Johns and Justus Winter - pdf](https://www.owasp.org/images/4/42/RequestRodeo-MartinJohns.pdf)
	* [A most Neglected Fact About CSRF - pdf](http://yehg.net/lab/pr0js/view.php/A_Most-Neglected_Fact_About_CSRF.pdf)
* **Tools**
	* [OWASP CSRFGuard](https://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project)
	* [OWASP CSRFTester](https://www.owasp.org/index.php/Category:OWASP_CSRFTester_Project)
	* [](https://code.google.com/archive/p/pinata-csrf-tool/)



----------------
#### <a name="encode">De/Encoders</a>
* [Unphp.net php decoder](http://www.unphp.net/decode/)
* [Various forms of encoding/decoding web app](http://yehg.net/encoding/)
* [Javascript De-Obfuscation Tools Redux](http://www.kahusecurity.com/2014/javascript-deobfuscation-tools-redux/)
	* Back in 2011, I took a look at several tools used to deobfuscate Javascript. This time around I will use several popular automated and semi-automated/manual tools to see how they would fare against today’s obfuscated scripts with the least amount of intervention.	
* [Javascript Deobfuscator - kahusecurity](http://www.kahusecurity.com/tools/)
* [Revelo - kahusecurity](http://www.kahusecurity.com/tools/)



----------------
#### <a name="dsa">Data Structure Attacks</a>
* --> See XML section
* [Hunting in the Dark - Blind XXE](https://blog.zsec.uk/blind-xxe-learning/)
* [Security Implications of DTD Attacks Against a Wide Range of XML Parsers](https://www.nds.rub.de/media/nds/arbeiten/2015/11/04/spaeth-dtd_attacks.pdf)
* [Comma Separated Vulnerabilities](https://www.contextis.com/blog/comma-separated-vulnerabilities)



----------------
#### Electron
* **Articles**
	* [From Markdown to RCE in Atom](https://statuscode.ch/2017/11/from-markdown-to-rce-in-atom/)
* **Documentation**
	* [Electron Documentation](https://electronjs.org/docs)
	* [Security, Native Capabilities, and Your Responsibility - Electron Documentation](https://electron.atom.io/docs/tutorial/security/)
* **Talks**
	* [MarkDoom: How I Hacked Every Major IDE in 2 Weeks - Matt Austin, LevelUp 2017](https://www.youtube.com/watch?v=nnEnwJbiO-A)
* [As It Stands - Electron Security - 2016](http://blog.scottlogic.com/2016/03/09/As-It-Stands-Electron-Security.html)
* [As It Stands - Update on Electorn Security - 2016](http://blog.scottlogic.com/2016/06/01/An-update-on-Electron-Security.html)
* [Modern Alchemy: Turning XSS into RCE](https://blog.doyensec.com/2017/08/03/electron-framework-security.html)
* [Electron - Build cross platform desktop XSS, it’s easier than you think by Yosuke Hasegawa - [CB16] ](https://www.youtube.com/watch?v=-j1DPPf9Z4U)
* [Electronegativity - A Study of Electron Security - Carettoni](https://www.blackhat.com/docs/us-17/thursday/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security.pdf)
* [Build cross platform desktop XSS, it’s easier than you think by Yosuke Hasegawa - CodeBlue16](https://www.slideshare.net/codeblue_jp/cb16-hasegawa-en)
* [Electron Security Checklist - A guide for developers and auditors - Luca Carettoni](https://www.blackhat.com/docs/us-17/thursday/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security-wp.pdf)




------------------
#### <a name="ear">Execution After(/Open) Redirect (EAR)
* **Execution After Redirect**
	* [Execution After Redirect - OWASP](https://www.owasp.org/index.php/Execution_After_Redirect_(EAR))
	* [Overview of Execution After Redirect Web Application Vulnerabilities](https://adamdoupe.com/blog/2011/04/20/overview-of-execution-after-redirect-web-application-vulnerabilities/)
	* [EARs in the Wild: Large-Scale Analysis of Execution After Redirect Vulnerabilities](https://www.cs.ucsb.edu/~vigna/publications/2013_SAC_EARdetect.pdf)
	* [Fear the EAR: Discovering and Mitigating Execution After Redirect Vulnerabilities](http://cs.ucsb.edu/~bboe/public/pubs/fear-the-ear-ccs2011.pdf)
* **Open Redirect**
	* [Open Redirect Payloads](https://github.com/cujanovic/Open-Redirect-Payloads)
	* [Security and Open Redirects  Impact of 301-ing people in 2013](https://makensi.es/rvl/openredirs/#/)




-------------------
#### <a name="ija">Injection Based Attacks</a>
* [Exploiting ShellShock getting a reverse shell](http://www.fantaghost.com/exploiting-shellshock-getting-reverse-shell)
* [Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)
* [Popular Approaches to Preventing Code Injection Attacks are Dangerously Wrong - AppSecUSA 2017](https://www.youtube.com/watch?v=GjK0bB4K2zA&app=desktop)
* See also: JNDI, JSON, SQLi, XSS



-------------------
#### OS Command Injection
* **General**
	* [Command Injection - OWASP](https://www.owasp.org/index.php/Command_Injection)
* **Testing**
	* [SHELLING](https://github.com/ewilded/shelling)
		* A comprehensive OS command injection payload generator
	* [Testing for Command Injection - OWASP](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013))
	* [How To: Command Injections - Hackerone](https://www.hackerone.com/blog/how-to-command-injections)
	* [Data Exfiltration via Blind OS Command Injection](https://www.contextis.com/blog/data-exfiltration-via-blind-os-command-injection)
* **Tools**
	* [commix](https://github.com/stasinopoulos/commix)
		* Automated All-in-One OS Command Injection and Exploitation Tool
* **Writeups**








-------------------
#### <a name="jndi"></a>JNDI Attack Class
* **General**
	* [What is JNDI ? What is its basic use..? When is it used? - StackOverflow](https://stackoverflow.com/questions/4365621/what-is-jndi-what-is-its-basic-use-when-is-it-used)
	* [Introducing JNDI Injection and LDAP Entry Poisoning](https://community.softwaregrp.com/t5/Security-Research/Introducing-JNDI-Injection-and-LDAP-Entry-Poisoning/ba-p/219821)
* **Testing**
	* [jndipoc](https://github.com/zerothoughts/jndipoc)
		* Proof of concept showing how java byte code can be injected through InitialContext.lookup() calls
* **Tools**
* **Writeups**
	* [Java Naming and Directory Interface - Wikipedia](https://en.wikipedia.org/wiki/Java_Naming_and_Directory_Interface)
	* [A Journey from JNDI-LDAP Manipulation to RCE](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)
	* [Video - A Journey From JNDI/LDAP Manipulation to Remote Code Execution Dream Land - BH USA16](https://www.youtube.com/watch?v=Y8a5nB-vy78)
	* [Fun with JNDI remote code injection](http://zerothoughts.tumblr.com/post/137769010389/fun-with-jndi-remote-code-injection)


-------------------
### <a name="jsa">De-/Serialization Attacks</a>
* **General**
* **Java**
	* [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
	* [Break Fast Serial](https://github.com/GoSecure/break-fast-serial)
		* A proof of concept that demonstrates asynchronous scanning for Java deserialization bugs
	* [SerialKiller: Bypass Gadget Collection](https://github.com/pwntester/SerialKillerBypassGadgetCollection)
		* Collection of Bypass Gadgets that can be used in JVM Deserialization Gadget chains to bypass "Look-Ahead ObjectInputStreams" desfensive deserialization.
	* [ysoserial](https://github.com/frohoff/ysoserial)
	* [The perils of Java deserialization](https://community.hpe.com/t5/Security-Research/The-perils-of-Java-deserialization/ba-p/6838995)
	* [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
		* A cheat sheet for pentesters about Java Native Binary Deserialization vulnerabilities
	* [Java Unmarshaller Security - Turning your data into code execution](https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true)
		* This paper presents an analysis, including exploitation details, of various Java open-source marshalling libraries that allow(ed) for unmarshalling of arbitrary, attacker supplied, types and shows that no matter how this process is performed and what implicit constraints are in place it is prone to similar exploitation techniques.
		* tool from the above paper: [marshalsec](https://github.com/mbechler/marshalsec/)
	* [Reliable discovery and Exploitation of Java Deserialization vulns](https://techblog.mediaservice.net/2017/05/reliable-discovery-and-exploitation-of-java-deserialization-vulnerabilities/)
	* [Pwning Your Java Messaging With De- serialization Vulnerabilities](https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities-wp.pdf)
	* [Java Deserialization Security FAQ](https://christian-schneider.net/JavaDeserializationSecurityFAQ.html)
	* [The Perils of Java Deserialization](http://community.hpe.com/hpeb/attachments/hpeb/off-by-on-software-security-blog/722/1/HPE-SR%20whitepaper%20java%20deserialization%20RSA2016.pdf)
	* [Detecting deserialization bugs with DNS exfiltration](http://gosecure.net/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltration/)
	* [JMET](https://github.com/matthiaskaiser/jmet)
		* JMET was released at Blackhat USA 2016 and is an outcome of Code White's research effort presented in the talk "Pwning Your Java Messaging With Deserialization Vulnerabilities". The goal of JMET is to make the exploitation of the Java Message Service (JMS) easy. In the talk more than 12 JMS client implementations where shown, vulnerable to deserialization attacks. The specific deserialization vulnerabilities were found in ObjectMessage implementations (classes implementing javax.jms.ObjectMessage).
	* [Serianalyzer](https://github.com/mbechler/serianalyzer)
		* A static byte code analyzer for Java deserialization gadget research
	* [Java Deserialization Exploits](https://github.com/CoalfireLabs/java_deserialization_exploits)
		* A collection of Java Deserialization Exploits
* **Python**
	* [Exploiting Python Deserialization Vulnerabilities](https://crowdshield.com/blog.php?name=exploiting-python-deserialization-vulnerabilities)
	* [Exploiting misuse of Python's "pickle"](https://blog.nelhage.com/2011/03/exploiting-pickle/)


	




-------------------
### <a name="jwt"></a>JSON Web Tokens
* **101**
	* [JSON Web Token - Wikipedia](https://en.wikipedia.org/wiki/JSON_Web_Token)
	* [RFC 7159: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
	* [The Anatomy of a JSON Web Token](https://scotch.io/tutorials/the-anatomy-of-a-json-web-token)
* **General**
	* [Friday the 13th: JSON Attacks - Defcon25](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Alvaro-Munoz-JSON-attacks.pdf)
	* [Critical vulnerabilities in JSON Web Token libraries - 2015](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
* **Testing**
	* [Attacking JWT authentication](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)
* **Tools**
	* [json token decode](http://jwt.calebb.net/)
	* [JWT Inspector - FF plugin](https://www.jwtinspector.io/)
		* JWT Inspector is a browser extension that lets you decode and inspect JSON Web Tokens in requests, cookies, and local storage. Also debug any JWT directly from the console or in the built-in UI.
* **Writeups**
	* [How to configure Json.NET to create a vulnerable web API - alphabot](https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html)
	* [🔐 Learn how to use JSON Web Token (JWT) to secure your next Web App! (Tutorial/Example with Tests!!)](https://github.com/dwyl/learn-json-web-tokens)




-------------------
### <a name="lrfi">LFI & RFI</a>
* **101**
	* [File inclusion vulnerability - Wikipedia](https://en.wikipedia.org/wiki/File_inclusion_vulnerability)
* **General**
* **Testing**
	* [Unrestricted File Upload Testing](https://www.aptive.co.uk/blog/unrestricted-file-upload-testing/)
	* [LFI Local File Inclusion Techniques (paper)](http://www.ush.it/2008/08/18/lfi2rce-local-file-inclusion-to-remote-code-execution-advanced-exploitation-proc-shortcuts/)
		* This paper exposes the ability from the attacker standpoint to use /proc in order to exploit LFI (Local File Inclusion) vulnerabilities. While using /proc for such aim is well known this one is a specific technique that was not been previously published as far as we know. A tool to automatically exploit LFI using the shown approach is released accordingly. 
	* [Update: a third (known) technique has been dissected here](http://www_ush_it/2008/07/09/local-file-inclusion-lfi-of-session-files-to-root-escalation/ ) 
	* [psychoPATH - LFI](https://github.com/ewilded/psychoPATH/blob/master/README.md)
		* This tool is a highly configurable payload generator detecting LFI & web root file uploads. Involves advanced path traversal evasive techniques, dynamic web root list generation, output encoding, site map-searching payload generator, LFI mode, nix & windows support plus single byte generator.
* **Tools**
	* [Liffy](https://github.com/rotlogix/liffy)
		* Liffy is a Local File Inclusion Exploitation tool. 
	* [lfi-labs](https://github.com/paralax/lfi-labs)
		* small set of PHP scripts to practice exploiting LFI, RFI and CMD injection vulns
* **Writeups**
	* [Turning LFI into RFI](https://l.avala.mp/?p=241)
		* When configured in a specific way the web application would load the JAR file and search within the file for a class. Interestingly enough, in Java classes you can define a static block that is executed upon the class being processed






-------------------
### NodeJS
* **101**
* **Educational**
	* [NodeGoat](https://github.com/OWASP/NodeGoat)
		* Being lightweight, fast, and scalable, Node.js is becoming a widely adopted platform for developing web applications. This project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
* **Articles/Blogposts/Presentations/Talks/Writeups**	
	* [Reverse shell on a Node.js application](https://wiremask.eu/writeups/reverse-shell-on-a-nodejs-application/)
	* [NodeJS: Remote Code Execution as a Service - Peabnuts123 – Kiwicon 2016](https://www.youtube.com/watch?v=Qvtfagwlfwg)
		* [SLIDES](http://archivedchaos.com/post/153372061089/kiwicon-2016-slides-upload)
* **Tools**
	* [faker.js](https://github.com/Marak/faker.js)
		* generate massive amounts of fake data in Node.js and the browser

-------------------
### <a name="sql"></a>(No)SQL Injection
* **101**
* **General**
	* [SQL Injection wiki](http://www.sqlinjectionwiki.com/)
* **Reference**
	* [SQL Injection Knowledge Base](http://websec.ca/kb/sql_injection#MySQL_Testing_Injection)
	* [SQL Injection Cheat Sheet](http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/)
	* [SQL Injection Cheat Sheet - NetSparker](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Abusing NoSQL Databases - Ming Chow](https://www.defcon.org/images/defcon-21/dc-21-presentations/Chow/DEFCON-21-Chow-Abusing-NoSQL-Databases.pdf)
	* [No SQL, No Injection? - Examining NoSQL Security](https://arxiv.org/pdf/1506.04082.pdf)
	* [NoSQL Injection in Modern Web Applications - petecorey.com](http://www.petecorey.com/blog/2016/03/21/nosql-injection-in-modern-web-applications/)
* **Tools**
	* [sqlmap](https://github.com/sqlmapproject/sqlmap)
	* [jSQL Injection](https://github.com/ron190/jsql-injection)
		* jSQL Injection is a Java application for automatic SQL database injection.
	* [mongoaudit](https://github.com/stampery/mongoaudit)
	* [Laduanum](http://laudanum.sourceforge.net/)
		* “Laudanum is a collection of injectable files, designed to be used in a pentest when SQL injection flaws are found and are in multiple languages for different environments.They provide functionality such as shell, DNS query, LDAP retrieval and others.”
* **Training**
	* [SQLi Lab lessons](https://github.com/Audi-1/sqli-labs)
		* SQLI-LABS is a platform to learn SQLI
* **Writeups**
	* [Use google bots to perform SQL injections on websites](http://blog.sucuri.net/2013/11/google-bots-doing-sql-injection-attacks.html)
	* [Performing sqlmap POST request injection](https://hackertarget.com/sqlmap-post-request-injection/)
* **DB2**
	* [DB2 SQL injection cheat sheet](https://securityetalii.es/2012/05/20/db2-sql-injection-cheat-sheet/)
* **MongoDB**
	* [Attacking MongoDB - ZeroNights2012](http://blog.ptsecurity.com/2012/11/attacking-mongodb.html)
	* [MongoDB Injection - How To Hack MongoDB](http://www.technopy.com/mongodb-injection-how-to-hack-mongodb-html/)
	* [Hacking NodeJS and MongoDB - websecurify](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)
* **MS-SQL**
	* [Pen test and hack microsoft sql server (mssql)](http://travisaltman.com/pen-test-and-hack-microsoft-sql-server-mssql/)
* **MySQL**
* **NoSQL**
	* [Nosql-Exploitation-Framework](https://github.com/torque59/Nosql-Exploitation-Framework)
		* A FrameWork For NoSQL Scanning and Exploitation Framework
	* [Making Mongo Cry Attacking NoSQL for Pen Testers Russell Butturini](https://www.youtube.com/watch?v=NgsesuLpyOg)
	* [MongoDB: Typical Security Weaknesses in a NoSQL DB](http://blog.spiderlabs.com/2013/03/mongodb-security-weaknesses-in-a-typical-nosql-database.html)
	* [MongoDB Pentesting for Absolute Beginners](https://github.com/nixawk/pentest-wiki/blob/master/2.Vulnerability-Assessment/Database-Assessment/mongodb/MongoDB%20Pentesting%20for%20Absolute%20Beginners.pdf)
* **PostgreSQL**
	* [PostgreSQL Pass The Hash protocol design weakness](https://hashcat.net/misc/postgres-pth/postgres-pth.pdf)
* **Oracle SQL**
	* [Oracle SQL Injection Guides & Whitepapers](https://haiderm.com/oracle-sql-injection-guides-and-whitepapers/)









-------------------
### <a name="pta">Path Traversal Attacks</a>
* [Exploiting PHP File Inclusion – Overview](https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/)
* [dotdotpwn](https://github.com/wireghoul/dotdotpwn)
	* It's a very flexible intelligent fuzzer to discover traversal directory vulnerabilities in software such as HTTP/FTP/TFTP servers, Web platforms such as CMSs, ERPs, Blogs, etc.



-------------
### <a name="ssrf"></a>Server Side Request Forgery (SSRF)
* **101**
	* [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
	* [What is Server Side Request Forgery (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)
	* [What is the Server Side Request Forgery Vulnerability & How to Prevent It? - netsparker](https://www.netsparker.com/blog/web-security/server-side-request-forgery-vulnerability-ssrf/)
	* [Vulnerable by Design: Understanding Server-Side Request Forgery - BishopFox](https://www.bishopfox.com/blog/2015/04/vulnerable-by-design-understanding-server-side-request-forgery/)
* **General**
	* [A New Era of SSRF  - Exploiting URL Parser in  Trending Programming Languages](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
* **Writeups**
	* [SSRF VS BUSINESS-CRITICAL APPLICATIONS PART 1: XXE TUNNELING IN SAP NET WEAVER - erpscan](https://erpscan.com/wp-content/uploads/publications/SSRF-vs-Businness-critical-applications-final-edit.pdf)
	* [A New Era of SSRF  - Exploiting URL Parser in  Trending Programming Languages! - Orange Tsai - BH USA 17](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
	* [curl Based SSRF Exploits Against Redis](https://maxchadwick.xyz/blog/ssrf-exploits-against-redis)
	* [Pivoting from blind SSRF to RCE with HashiCorp Consul](http://www.kernelpicnic.net/2017/05/29/Pivoting-from-blind-SSRF-to-RCE-with-Hashicorp-Consul.html)
	* [ How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)
	* [Airbnb – Chaining Third-Party Open Redirect into Server-Side Request Forgery (SSRF) via LivePerson Chat](https://buer.haus/2017/03/09/airbnb-chaining-third-party-open-redirect-into-server-side-request-forgery-ssrf-via-liveperson-chat/)
* **Testing/Tools**
	* [SSRF bible. Cheatsheet](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#heading=h.t4tsk5ixehdd)	
	* [SSRF (Server Side Request Forgery) testing resources](https://github.com/cujanovic/SSRF-Testing/)	
	* [How To: Server-Side Request Forgery (SSRF)](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)
	* [Port scanning with Server Side Request Forgery (SSRF) - acunetix](https://www.acunetix.com/blog/articles/ssrf-vulnerability-used-to-scan-the-web-servers-network/)







-------------------
### <a name="ssi"></a>Server Side Include
* **General**
	* [Server Side Includes - Wikipedia](https://en.wikipedia.org/wiki/Server_Side_Includes)
	* [Server-Side Includes (SSI) Injection - OWASP](https://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection)
* **Testing**
	* [Testing for SSI Injection (OTG-INPVAL-009) - OWASP](https://www.owasp.org/index.php/Testing_for_SSI_Injection_(OTG-INPVAL-009))

-------------------
### <a name="ssti">Server Side Template Injection</a>
* **General**
	* [Server-Side Template Injection: RCE for the modern webapp](https://portswigger.net/knowledgebase/papers/ServerSideTemplateInjection.pdf)
	* [Server-Side Template Injection](http://blog.portswigger.net/2015/08/server-side-template-injection.html)
		* [Video](https://www.youtube.com/watch?v=3cT0uE7Y87s)
		* This paper defines a methodology for detecting and exploiting template injection, and shows it being applied to craft RCE zerodays for two widely deployed enterprise web applications. Generic exploits are demonstrated for five of the most popular template engines, including escapes from sandboxes whose entire purpose is to handle user-supplied templates in a safe way.
* **Purposefully Vulnerable Webapps**
	* [Breakable Flask](https://github.com/stephenbradshaw/breakableflask)
		* A simple vulnerable Flask application.
	* [Hackable](https://github.com/JasonHinds13/hackable)
		* A python flask app that is purposfully vulnerable to SQL injection and XSS Attacks
	* [Injecting Flask - Nvisium](https://nvisium.com/blog/2015/12/07/injecting-flask/) 
* **Writeups**
	* [Exploring SSTI in Flask/Jinja2](https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2/)
	* [Exploring SSTI in Flask/Jinja2, Part II](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
	* [Ruby ERB Template Injection](https://www.trustedsec.com/2017/09/rubyerb-template-injection/)
	* [Remote Code Execution via Server Side Template Injection at OFBiz 13.07.03 (CVE-2016-4462)](https://insinuator.net/2016/07/dilligent-bug/)
	* [Injecting Flask - Nvisium](https://nvisium.com/blog/2015/12/07/injecting-flask/)
	* [Spring Boot RCE](deadpool.sh/2017/RCE-Springs/)
* **Tools**
	* [tplmap](https://github.com/epinna/tplmap)
		* Code and Server-Side Template Injection Detection and Exploitation Tool
	* [Templates Injections - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections)

----------------
### <a name="subres"></a>Subresource Integrity
* **General**
	* [Subresource Integrity - W3C](https://www.w3.org/TR/SRI/)
	* [Subresource Integrity - Mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
	* [Subresource Integrity (SRI) for Validating Web Resources Hosted on Third Party Services (CDNs) - Netsparker](https://www.netsparker.com/blog/web-security/subresource-integrity-SRI-security/)
	* [SRI Hash Generator](https://www.srihash.org/)

----------------
### <a name="swf"></a>SWF
* **General**
	* [The old is new, again. CVE-2011-2461 is back!](https://www.slideshare.net/ikkisoft/the-old-is-new-again-cve20112461-is-back)
		* As a part of an ongoing investigation on Adobe Flash SOP bypass techniques, we identified a vulnerability affecting old releases of the Adobe Flex SDK compiler. Further investigation traced the issue back to a well known vulnerability (CVE20112461), already patched by Adobe. Old vulnerability, let's move on? Not this time. CVE20112461 is a very interesting bug. As long as the SWF file was compiled with a vulnerable Flex SDK, attackers can still use this vulnerability against the latest web browsers and Flash plugin. Even with the most recent updates, vulnerable Flex applications hosted on your domain can be exploited. In this presentation, we will disclose the details of this vulnerability (Adobe has never released all technicalities) and we will discuss how we conducted a large scale analysis on popular websites, resulting in the identification of numerous Alexa Top 50 sites vulnerable to this bug. Finally, we will also release a custom tool and a Burp plugin capable of detecting vulnerable SWF applications. 
	* Advanced Flash Vulnerabilities in Youtube Writeups Series
		* [Advanced Flash Vulnerabilities in Youtube – Part 1](https://opnsec.com/2017/08/advanced-flash-vulnerabilities-in-youtube-part-1/)
		* [Advanced Flash Vulnerabilities in Youtube – Part 2](https://opnsec.com/2017/08/advanced-flash-vulnerabilities-in-youtube-part-2/)
		* [Advanced Flash Vulnerabilities in Youtube – Part 3](https://opnsec.com/2017/08/advanced-flash-vulnerabilities-in-youtube-part-3/)
	* [Decode Adobe Flex AMF protocol](http://blog.dornea.nu/2015/06/22/decode-adobe-flex-amf-protocol/)
* **Securing**
	* [HardenFlash](https://github.com/HaifeiLi/HardenFlash)
		* Patching Flash binary to stop Flash exploits and zero-days
* **Tools**
	* [ParrotNG](https://github.com/ikkisoft/ParrotNG/releases)
		* ParrotNG is a Java-based tool for automatically identifying vulnerable SWF files, built on top of swfdump. One JAR, two flavors: command line tool and Burp Pro Passive Scanner Plugin.
	[deblaze](http://blog.dornea.nu/2015/06/22/decode-adobe-flex-amf-protocol/)
		* Performs method enumeration and interrogation against flash remoting end points.









-------------------
### <a name="timing"></a>Timing Attacks
* [Timing attack - Wikipedia](https://en.wikipedia.org/wiki/Timing_attack)
* [Race conditions on the web ](https://www.josipfranjkovic.com/blog/race-conditions-on-web)
* [Practical Race Condition Vulnerabilities in Web Applications](https://defuse.ca/race-conditions-in-web-applications.htm)
* [Race The Web (RTW)](https://github.com/insp3ctre/race-the-web)
	* Tests for race conditions in web applications by sending out a user-specified number of requests to a target URL (or URLs) simultaneously, and then compares the responses from the server for uniqueness. Includes a number of configuration options.
* [timing_attack](https://github.com/ffleming/timing_attack)
	* Perform timing attacks against web applications
fuse.ca/race-conditions-in-web-applications.htm)
* [Race condition exploit](https://github.com/andresriancho/race-condition-exploit)
	* Tool to help with the exploitation of web application race conditions



-------------------
### Web Hooks
* [Webhooks - pbworks](https://webhooks.pbworks.com/w/page/13385124/FrontPage)
* [WebHook - Wikipedia](https://en.wikipedia.org/wiki/Webhook)
* [Abusing Webhooks for Command and Control - Dimitry Snezhkov - BSides LV 2017](https://www.youtube.com/watch?v=TmLoTrJuung)
	* [octohook](https://github.com/dsnezhkov/octohook)




-------------------
### <a name="shells">Web Shells</a>
* **Articles**
* **Detection**
	* [Case Study: How Backdoors Bypass Security Solutions with Advanced Camouflage Techniques](https://www.incapsula.com/blog/backdoor-malware-analysis-obfuscation-techniques.html)
		* Look at PHP obfuscation methods for webshells
	* [NeoPI](https://github.com/Neohapsis/NeoPI)
		* What is NeoPI? NeoPI is a Python script that uses a variety of statistical methods to detect obfuscated and encrypted content within text/script files. The intended purpose of NeoPI is to aid in the detection of hidden web shell code. The development focus of NeoPI was creating a tool that could be used in conjunction with other established detection methods such as Linux Malware Detect or traditional signature/keyword based searches.
	* [Shell Detector](https://github.com/emposha/Shell-Detector)
		* Shell Detector – is a application that helps you find and identify php/cgi(perl)/asp/aspx shells. Shell Detector has a “web shells” signature database that helps to identify “web shell” up to 99%.
	* [Loki - Simple IOC Scanner](https://github.com/Neo23x0/Loki)
		* Scanner for Simple Indicators of Compromise
* **Tools**
	* [Weevely](https://github.com/epinna/weevely3)
		* Weevely is a command line web shell dinamically extended over the network at runtime used for remote administration and pen testing. It provides a weaponized telnet-like console through a PHP script running on the target, even in restricted environments.  The low footprint agent and over 30 modules shape an extensible framework to administrate, conduct a pen-test, post-exploit, and audit remote web accesses in order to escalate privileges and pivot deeper in the internal networks.
		* [Getting Started](https://github.com/epinna/weevely3/wiki#getting-started)
	* [b374k shell 3.2](https://github.com/b374k/b374k)
		* This PHP Shell is a useful tool for system or web administrator to do remote management without using cpanel, connecting using ssh, ftp etc. All actions take place within a web browser
	* [Simple websockets based webshell](http://ibreak.software/2015/02/18/simple-websockets-based-webshell/)
	* [JSShell](https://github.com/Den1al/JSShell/)
		* An interactive multi-user web based JS shell written in Python with Flask (for server side) and of course Javascript and HTML (client side). It was initially created to debug remote esoteric browsers during tests and research. I'm aware of other purposes this tool might serve, use it at your own responsibility and risk.
	* [htshells](https://github.com/wireghoul/htshells)
		* Self contained web shells and other attacks via .htaccess files.


-------------------
### <a name="xss">XSS</a>
* **101**
	* [3 Types of XSS](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting)
		* Reflected, Persistent, DOM-based
* **General**
	* [Postcards from a Post-XSS World - Michael Zalewski](http://lcamtuf.coredump.cx/postxss/#dangling-markup-injection)
		* This page is a rough collection of notes on some of the fundamental alternatives to direct script injection that would be available to attackers following the universal deployment of CSP or other security mechanisms designed to prevent the execution of unauthorized scripts. I hope to demonstrate that in many cases, the capabilities offered by these alternative methods are highly compatible with the goals of contemporary XSS attacks.
	* [Self XSS: we’re not so different you and I - Mathias Karlsson](https://www.youtube.com/watch?v=l3yThCIF7e4)
	* [XSS Web Filter Bypass list - rvrsh3ll](https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec#file-xxsfilterbypass-lst-L1)
* **Testing**
	* [XSS Test String Dump](https://github.com/zsitro/XSS-test-dump/blob/master/xss.txt)
	* [XSS Filter Bypass List](https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec)
	* [HTML Purifier XSS Attacks Smoketest](http://htmlpurifier.org/live/smoketests/xssAttacks.php)
* **Training**
	* [XSS-Game.appspot](https://xss-game.appspot.com/)
	* [Firing-Range](https://github.com/google/firing-range)
		* Firing Range is a test bed for web application security scanners, providing synthetic, wide coverage for an array of vulnerabilities.
	* [XSSer](https://xsser.03c8.net/)
	* [prompt.ml - XSS Injection Game](http://prompt.ml/about)
	* [alert1 to win - XSS Injection Game](https://alf.nu/)
* **Tools**
	* [xsscrapy](https://github.com/byt3bl33d3r/xsscrapy)
	* [XSS Sniper](https://sourceforge.net/projects/xssniper/)
	* [Xenotix](https://github.com/ajinabraham/OWASP-Xenotix-XSS-Exploit-Framework)
		* OWASP Xenotix XSS Exploit Framework is an advanced Cross Site Scripting (XSS) vulnerability detection and exploitation framework.
	* [xssValidator](https://github.com/nVisium/xssValidator)
		* This is a burp intruder extender that is designed for automation and validation of XSS vulnerabilities. 
	* [Shuriken](https://github.com/shogunlab/shuriken)
		* Cross-Site Scripting (XSS) command line tool for testing lists of XSS payloads on web apps.
* **Writeups**
	* [Writing an XSS Worm](http://blog.gdssecurity.com/labs/2013/5/8/writing-an-xss-worm.html)


 



--------------------
### <a name="api"></a>API Stuff
* **Fuzzing**
	* [Fuzzapi](https://github.com/lalithr95/Fuzzapi/)
		* Fuzzapi is rails application which uses API_Fuzzer and provide UI solution for gem.
	* [Automating API Penetration Testing using fuzzapi - AppSecUSA 2016](https://www.youtube.com/watch?v=43G_nSTdxLk)
* **General**
	* [WebSocket API Standards](https://www.w3.org/TR/2011/WD-websockets-20110929/)
	* [White House Web API Standards](https://github.com/WhiteHouse/api-standards)
		* This document provides guidelines and examples for White House Web APIs, encouraging consistency, maintainability, and best practices across applications. White House APIs aim to balance a truly RESTful API interface with a positive developer experience (DX).
* **Securing**
	* [RESTful API Best Practices and Common Pitfalls](https://medium.com/@schneidenbach/restful-api-best-practices-and-common-pitfalls-7a83ba3763b5)
	* [OWASP API Security Project](https://www.owasp.org/index.php/OWASP_API_Security_Project)
* **Tools**
	* [Postman - chrome plugin](https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop)
	* [restclient - Firefox addon](https://addons.mozilla.org/de/firefox/addon/restclient/)








-------------------
### <a name="atkb"Attacking Browsers</a>
* **General**
	* [White Lightning Attack Platform](https://github.com/TweekFawkes/White_Lightning)
* **Browser Extensions**
	* [Attacking Browser Extensions](https://github.com/qll/attacking-browser-extensions)
	* [Botnet in the Browser: Understanding Threats Caused by Malicious Browser Extensions](https://arxiv.org/pdf/1709.09577.pdf)
	* [An in-depth look into Malicious Browser Extensions(2014)](http://blog.trendmicro.com/trendlabs-security-intelligence/an-in-depth-look-into-malicious-browser-extensions/)
	* [Game of Chromes: Owning the Web with Zombie Chrome Extensions - DEF CON 25 - Tomer Cohen](https://www.youtube.com/watch?v=pR4HwDOFacY)
	* [Chrome-botnet](https://github.com/i-tsvetkov/chrome-botnet)
* **Exploiting**
	* [Smashing The Browser: From Vulnerability Discovery To Exploit](https://github.com/demi6od/Smashing_The_Browser)
		* Goes from introducing a fuzzer to producing an IE11 0day
	* [The Birth of a Complete IE11 Exploit Under the New Exploit Mitigations](https://www.syscan.org/index.php/download/get/aef11ba81927bf9aa02530bab85e303a/SyScan15%20Yuki%20Chen%20-%20The%20Birth%20of%20a%20Complete%20IE11%20Exploit%20Under%20the%20New%20Exploit%20Mitigations.pdf)
	* [BeEF Browser Exploitation Framework](http://beefproject.com/)



----------------
###<a name="cms">CMS specific Tools</a>
* **General**
* **Drupal**
	* [Drupal Security Checklist](https://github.com/gfoss/attacking-drupal/blob/master/presentation/drupal-security-checklist.pdf)
	* [Drupal Attack Scripts](https://github.com/gfoss/attacking-drupal)
		* Set of brute force scripts and Checklist	
	* [Droopescan](https://github.com/droope/droopescan)
		* A plugin-based scanner that aids security researchers in identifying issues with several CMSs, mainly Drupal & Silverstripe.
* **Joomla**
	* [Highly Effective Joomla Backdoor with Small Profile](http://blog.sucuri.net/2014/02/highly-effective-joomla-backdoor-with-small-profile.html)
	* [JoomScan](https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project)
		* Joomla! is probably the most widely-used CMS out there due to its flexibility, user-friendlinesss, extensibility to name a few.So, watching its vulnerabilities and adding such vulnerabilities as KB to Joomla scanner takes ongoing activity.It will help web developers and web masters to help identify possible security weaknesses on their deployed Joomla! sites. No web security scanner is dedicated only one CMS. 
* **Sharepoint**
	* [Sparty - Sharepoint/Frontpage Auditing Tool](https://github.com/alias1/sparty)
		* Sparty is an open source tool written in python to audit web applications using sharepoint and frontpage architecture. The motivation behind this tool is to provide an easy and robust way to scrutinize the security configurations of sharepoint and frontpage based web applications. Due to the complex nature of these web administration software, it is required to have a simple and efficient tool that gathers information, check access permissions, dump critical information from default files and perform automated exploitation if security risks are identified. A number of automated scanners fall short of this and Sparty is a solution to that.
* **Wordpress**
	* [WPScan](https://github.com/wpscanteam/wpscan)
		* WPScan is a black box WordPress vulnerability scanner. 
	* [WPSeku](https://github.com/m4ll0k/WPSeku)
		* Wordpress Security Scanner





--------------
### ColdFusion
* [Attacking Adobe ColdFusion](http://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html)
* [ColdFusion Security Resources](https://www.owasp.org/index.php/ColdFusion_Security_Resources)
* [ColdFusion for Penetration Testers](http://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers)



--------------
### Continous Integration/Delivery/Build Systems
* [Hacking Jenkins Servers With No Password](https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password)
* [Hacking Jenkins - Ideas - Zeroknock](http://zeroknock.blogspot.com/search/label/Hacking%20Jenkins)



----------------
### <a name="html5">HTML 5</a>
* [HTML Standard Documentation](https://html.spec.whatwg.org/multipage/infrastructure.html#unicode-code-point)
* [HTML5 Security Cheatsheet](https://github.com/cure53/H5SC)
* [SH5ARK](http://sh5ark.professionallyevil.com)
	* The Securing HTML5 Assessment Resource Kit, or SH5ARK, is an open source project that provides a repository of HTML5 features, proof-of-concept attack code, and filtering rules. The purpose of this project is to provide a single repository that can be used to collect sample code of vulnerable HTML5 features, actual attack code, and filtering rules to help prevent attacks and abuse of these features. The intent of the project is to bring awareness to the opportunities that HTML5 is providing for attackers, to help identify these attacks, and provide measures for preventing them
	* [Presentation on SH5ARK](https://www.youtube.com/watch?v=1ZZ-vIwmWx4)
	* [GetSH5ARK here](http://sourceforge.net/projects/sh5ark/)


----------------
### <a name="javascript">JavaScript</a>
* **General**
	* [DOM Clobbering Attack](http://www.thespanner.co.uk/2013/05/16/dom-clobbering/)
* **Tools**
	* [JSDetox](http://relentless-coding.org/projects/jsdetox/info)
		* JSDetox is a tool to support the manual analysis of malicious Javascript code. 
	* [Dom Flow - Untangling The DOM For More Easy-Juicy Bugs  - BH USA 2015](https://www.youtube.com/watch?v=kedmtrIEW1k&list=PLH15HpR5qRsXF78lrpWP2JKpPJs_AFnD7&index=111)
	* [Javascript Deobfuscator - kahusecurity](http://www.kahusecurity.com/tools/)
	* [Revelo - kahusecurity](http://www.kahusecurity.com/tools/)
	* [pwn.js](https://github.com/theori-io/pwnjs)
		* A Javascript library for browser exploitation
	* [Retire.js](https://retirejs.github.io/retire.js/)
		* There is a plethora of JavaScript libraries for use on the web and in node.js apps out there. This greatly simplifies, but we need to stay update on security fixes. "Using Components with Known Vulnerabilities" is now a part of the OWASP Top 10 and insecure libraries can pose a huge risk for your webapp. The goal of Retire.js is to help you detect use of version with known vulnerabilities.

----------------
### Java Server Faces (JSF)
* **101**
	* [Java Server Faces - Wikipedia](https://en.wikipedia.org/wiki/JavaServer_Faces)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities - alphabot](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)



--------------
### <a name="php"></a>PHP
* [Browser Security Whitepaper - Cure53](https://cure53.de/browser-security-whitepaper.pdf/)
* [OWASP Proactive Controls 3.0](https://docs.google.com/document/d/1bQKisfXQ2XRwkcUaTvVTR7bpzVgbwIhDA1O6hUbywiY/mobilebasic)
* [Php Codz Hacking](https://github.com/80vul/phpcodz)
	* Writeups of specific PHP vulns
* [PHP Generic Gadget Chains: Exploiting unserialize in unknown environments](https://www.ambionics.io/blog/php-generic-gadget-chains)
* [PHPGGC: PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
	* PHPGGC is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically. When encountering an unserialize on a website you don't have the code of, or simply when trying to build an exploit, this tool allows you to generate the payload without having to go through the tedious steps of finding gadgets and combining them. Currently, the tool supports: Doctrine, Guzzle, Laravel, Monolog, Slim, SwiftMailer.
* [Pwning PHP mail() function For Fun And RCE | New Exploitation Techniques And Vectors](https://exploitbox.io/paper/Pwning-PHP-Mail-Function-For-Fun-And-RCE.html)
* [The unexpected dangers of preg_replace](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace)



#### Code Reuse
* [The ReflectionClass class](https://secure.php.net/ReflectionClass)
* [Autoloading Classes](http://www.php.net/language.oop5.autoload)
* [PHP Autoload Invalid Classname Injection](https://hakre.wordpress.com/2013/02/10/php-autoload-invalid-classname-injection/)
* [Code Reuse Attacks in PHP: Automated POP Chain Generation](https://www.syssec.rub.de/media/emma/veroeffentlichungen/2014/09/10/POPChainGeneration-CCS14.pdf)
	* In  this  paper, we study code reuse attacks in the con- text of PHP-based web applications. We analyze how PHP object injection (POI) vulnerabilities  can  be exploited via property-oriented programming (POP) and perform a systematic analysis of available gadgets in common PHP applications. Furthermore, we introduce an automated approach to statically detect  POI  vulnerabilities  in  object-oriented PHP code. Our approach is also capable of generating POP chains in an automated way. We implemented a prototype of the proposed approach and evaluated it with 10 well-known applications. Overall, we detected 30 new POI vulnerabilities and 28 new gadget chains
* [Utilizing Code Reuse/ROP in PHP Application Exploits - BH 2010](https://www.owasp.org/images/9/9e/Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits.pdf)
* [POP-Exploit](https://github.com/enddo/POP-Exploit)
	* Research into Property Oriented Programming about php applications.


#### De/Serialization
* [serialize - php](http://us3.php.net/serialize)
* [unserialize - php](https://secure.php.net/unserialize)
* [PHP Object Injection](https://www.owasp.org/index.php/PHP_Object_Injection)
* [Writing Exploits For Exotic Bug Classes: unserialize()](https://www.alertlogic.com/blog/writing-exploits-for-exotic-bug-classes-unserialize()/)
* [Is PHP unserialize() exploitable without any 'interesting' methods? - StackOverflow](https://security.stackexchange.com/questions/77549/is-php-unserialize-exploitable-without-any-interesting-methods)
* [Remote code execution via PHP [Unserialize] - notsosecure](https://www.notsosecure.com/remote-code-execution-via-php-unserialize/)


#### Type Juggling
* [Writing Exploits For Exotic Bug Classes: PHP Type Juggling](https://turbochaos.blogspot.com.au/2013/08/exploiting-exotic-bugs-php-type-juggling.html)
* [PHP Magic Tricks: Type Juggling](https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf)
* [PHP’s “Magic Hash” Vulnerability (Or Beware Of Type Juggling)](https://web.archive.org/web/20150530075600/http://blog.astrumfutura.com/2015/05/phps-magic-hash-vulnerability-or-beware-of-type-juggling)



----------------
### Relative Path Overwrite
* [Relative Path Overwrite Explanation/Writeup](http://www.thespanner.co.uk/2014/03/21/rpo/)
	* RPO (Relative Path Overwrite) is a technique to take advantage of relative URLs by overwriting their target file. To understand the technique we must first look into the differences between relative and absolute URLs. An absolute URL is basically the full URL for a destination address including the protocol and domain name whereas a relative URL doesn’t specify a domain or protocol and uses the existing destination to determine the protocol and domain.

----------------
### <a name="rest"></a>REST/SOAP/Web Services(WSDL)
* **Learning/Reference**
	* [RESTful Services, The Web Security Blind Spot](https://www.youtube.com/watch?feature=player_embedded&v=pWq4qGLAZHI#!)
		* [Blogpost](https://xiom.com/2016/10/31/restful-services-web-security-blind-spot/)
		* [Presentation Slides -pdf](https://xiomcom.files.wordpress.com/2016/10/security-testing-for-rest-applications-v6-april-2013.pdf)
	* [Learn REST: A Tutorial](http://rest.elkstein.org/)
	* [Cracking and Fixing REST APIs](http://www.sempf.net/post/Cracking-and-Fixing-REST-APIs)
	* [Cracking and fixing REST services](http://www.irongeek.com/i.php?page=videos/converge2015/track109-cracking-and-fixing-rest-services-bill-sempf)
	* [Representational State Transfer - Wikipedia](https://en.wikipedia.org/wiki/Representational_state_transfer)
	* [Web Services Security Testing Cheat Sheet Introduction - OWASP](https://www.owasp.org/index.php/Web_Service_Security_Testing_Cheat_Sheet)
	* [Service-Oriented-Architecture](https://en.wikipedia.org/wiki/Service-oriented_architecture)
	* [Microservices](https://en.wikipedia.org/wiki/Microservices)
	* [REST and Stateless Session IDs](https://appsandsecurity.blogspot.com/2011/04/rest-and-stateless-session-ids.html)
* **Attacking**
	* [REST Security Cheat Sheet](REST Security Cheat Sheet)
	* [REST Assessment Cheat Sheet](https://www.owasp.org/index.php/REST_Assessment_Cheat_Sheet)
	* [Damn Vulnerable Web Services dvws](https://github.com/snoopysecurity/dvws)
		* Damn Vulnerable Web Services is an insecure web application with multiple vulnerable web service components that can be used to learn real world web service vulnerabilities.
	* [WS-Attacker](https://github.com/RUB-NDS/WS-Attacker)
		* WS-Attacker is a modular framework for web services penetration testing. It is developed by the Chair of Network and Data Security, Ruhr University Bochum (http://nds.rub.de/ ) and the Hackmanit GmbH (http://hackmanit.de/).
	* [WS-Attacks.org](http://www.ws-attacks.org/Welcome_to_WS-Attacks)
		* WS-Attacks.org is not a new web service standard by the OASIS Group or W3C; instead it presents the flaws of today's web service standards and implementations in regard to web service security! WS-Attacks.org aims at delivering the most comprehensive enumeration of all known web service attacks.
	* [Exploiting CVE-2017-8759: SOAP WSDL Parser Code Injection](https://www.mdsec.co.uk/2017/09/exploiting-cve-2017-8759-soap-wsdl-parser-code-injection/)
	* [The S stands for Simple](http://harmful.cat-v.org/software/xml/soap/simple)
		* Satire(Only it's not) of a conversation about SOAP




--------------------------------
### <a name="ruby"></a>Ruby/Ruby on Rails
* **General**
	* [Ruby on Rails Security Guide](http://guides.rubyonrails.org/security.html)
	* [Ruby on Rails Cheatsheet - OWASP](https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet)
	* [Executing commands in ruby](http://blog.bigbinary.com/2012/10/18/backtick-system-exec-in-ruby.html)
	* [Attacking Ruby on Rails Applications - phrack](http://phrack.org/issues/69/12.html#article)
	* [Going AUTH the Rails on a Crazy Train: A Dive into Rails Authentication and Authorization](https://www.blackhat.com/docs/eu-15/materials/eu-15-Jarmoc-Going-AUTH-The-Rails-On-A-Crazy-Train-wp.pdf)
	* [Property Oriented Programming - Applied to Ruby](https://slides.com/benmurphy/property-oriented-programming/fullscreen#/)
	* [Pentesting Django and Rails](https://es.slideshare.net/levigross/pentesting-django-and-rails)
	* [Executing commands in ruby](http://blog.bigbinary.com/2012/10/18/backtick-system-exec-in-ruby.html)
	* [Execution of shell code in Ruby scripts](https://makandracards.com/makandra/1243-execution-of-shell-code-in-ruby-scripts)



-----------------
### <a name="saml"></a>Security Assertion Markup Language (SAML)
* **101**
	* [Security Assertion Markup Language - Wikipedia](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language)
	* [SAML 2.0 - Wikipedia](https://en.wikipedia.org/wiki/SAML_2.0)
* **Articles/Blogposts/Writeups**
	* [With Great Power Comes Great Pwnage](https://www.compass-security.com/fileadmin/Datein/Research/Praesentationen/area41_2016_saml.pdf)
	* [Out of Band  XML External Entity Injection via SAML SSO - Sean Melia](https://seanmelia.files.wordpress.com/2016/01/out-of-band-xml-external-entity-injection-via-saml-redacted.pdf)
	* [Web-based Single Sign-On and the Dangers of SAML XML Parsing](https://blog.sendsafely.com/web-based-single-sign-on-and-the-dangers-of-saml-xml-parsing)
	* [Following the white Rabbit Down the SAML Code](https://medium.com/section-9-lab/following-the-white-rabbit-5e392e3f6fb9)
	* [Evilginx - Advanced Phishing with Two-factor Authentication Bypass](https://breakdev.org/evilginx-advanced-phishing-with-two-factor-authentication-bypass/)
		* [Evilginx - Update 1.0](https://breakdev.org/evilginx-1-0-update-up-your-game-in-2fa-phishing/)
		* [Evilginx - Update 1.1](https://breakdev.org/evilginx-1-1-release/)
* **Golden SAML Attack**
	* [Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Apps](https://www.cyberark.com/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-cloud-apps/)
	* [shimit](https://github.com/cyberark/shimit)
		* In a golden SAML attack, attackers can gain access to an application (any application that supports SAML authentication) with any privileges they desire and be any user on the targeted application. shimit allows the user to create a signed SAMLResponse object, and use it to open a session in the Service Provider. shimit now supports AWS Console as a Service Provider, more are in the works...
* **Tools**
	* [Evilginx](https://github.com/kgretzky/evilginx)
		* Evilginx is a man-in-the-middle attack framework used for phishing credentials and session cookies of any web service. It's core runs on Nginx HTTP server, which utilizes proxy_pass and sub_filter to proxy and modify HTTP content, while intercepting traffic between client and server.
	* [SAMLReQuest Burpsuite Extention](https://insinuator.net/2016/06/samlrequest-burpsuite-extention/)



-----------------
### <a name="scraping"></a>Scraping
* [WeasyPrint](http://weasyprint.org/)
	* WeasyPrint is a visual rendering engine for HTML and CSS that can export to PDF. It aims to support web standards for printing. WeasyPrint is free software made available under a BSD license.
* [Scrapy](https://scrapy.org/)
	* An open source and collaborative framework for extracting the data you need from websites. 







----------------
### <a name="scanners"></a>Site/Webapp Scanners
* [nikto]()
* [Spaghetti - Web Application Security Scanner](https://github.com/m4ll0k/Spaghetti)
	* Spaghetti is an Open Source web application scanner, it is designed to find various default and insecure files, configurations, and misconfigurations. Spaghetti is built on python2.7 and can run on any platform which has a Python environment.
* [skipfish](https://code.google.com/p/skipfish/)
	* Skipfish is an active web application security reconnaissance tool. It prepares an interactive sitemap for the targeted site by carrying out a recursive crawl and dictionary-based probes. The resulting map is then annotated with the output from a number of active (but hopefully non-disruptive) security checks. The final report generated by the tool is meant to serve as a foundation for professional web application security assessments. 
* [wikto](https://github.com/sensepost/wikto)
	* Wikto is Nikto for Windows - but with a couple of fancy extra features including Fuzzy logic error code checking, a back-end miner, Google assisted directory mining and real time HTTP request/response monitoring. Wikto is coded in C# and requires the .NET framework. 
* [RAWR - Rapid Assessment of Web Resources](https://bitbucket.org/al14s/rawr/wiki/Home)
* [Arachni Web Scanner](http://www.arachni-scanner.com/)
	* Arachni is an Open Source, feature-full, modular, high-performance Ruby framework aimed towards helping penetration testers and administrators evaluate the security of web applications.  It is smart, it trains itself by monitoring and learning from the web application's behavior during the scan process and is able to perform meta-analysis using a number of factors in order to correctly assess the trustworthiness of results and intelligently identify (or avoid) false-positives. 
* [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
	* WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1500 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.
* [WATOBO](https://github.com/siberas/watobo)
	* WATABO is a security tool for testing web applications. It is intended to enable security professionals to perform efficient (semi-automated) web application security audits.
* [YASUO](https://github.com/0xsauby/yasuo)
	* Yasuo is a ruby script that scans for vulnerable 3rd-party web applications.
* [CMSExplorer](https://code.google.com/p/cms-explorer/)
	* CMS Explorer is designed to reveal the the specific modules, plugins, components and themes that various CMS driven web sites are running. Additionally, CMS Explorer can be used to aid in security testing. While it performs no direct security checks, the "explore" option can be used to reveal hidden/library files which are not typically accessed by web clients but are nonetheless accessible. This is done by retrieving the module's current source tree and then requesting those file names from the target system. These requests can be sent through a distinct proxy to help "bootstrap" security testing tools like Burp, Paros, Webinspect, etc. 
* [BlindElephant Web Application Fingerprinter](http://blindelephant.sourceforge.net/)
	* The BlindElephant Web Application Fingerprinter attempts to discover the version of a (known) web application by comparing static files at known locations against precomputed hashes for versions of those files in all all available releases. The technique is fast, low-bandwidth, non-invasive, generic, and highly automatable. 
* [ParrotNG](https://github.com/ikkisoft/ParrotNG)
	* ParrotNG is a tool capable of identifying Adobe Flex applications (SWF) vulnerable to CVE-2011-2461
* [OpenDoor](https://github.com/stanislav-web/OpenDoor)
	* OpenDoor OWASP is console multifunctional web sites scanner. This application find all possible ways to login, index of/ directories, web shells, restricted access points, subdomains, hidden data and large backups. The scanning is performed by the built-in dictionary and external dictionaries as well. Anonymity and speed are provided by means of using proxy servers.
* [Tachyon](https://github.com/delvelabs/tachyon)



----------------
### <a name="websocket"></a>Web Sockets
* [The WebSocket Protocol Standard - IETF](https://tools.ietf.org/html/rfc6455)
* [WebSocket Protocol - RFC Draft 17](https://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17)






----------------
### <a name="webproxy">Web Proxies</a>
* [Burpsuite](http://portswigger.net/burp/)
	* Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities. 
* [ZAP - Zed Attack Proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
	* The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications.  It is designed to be used by people with a wide range of security experience and as such is ideal for developers and functional testers who are new to penetration testing.  ZAP provides automated scanners as well as a set of tools that allow you to find security vulnerabilities manually.
* [Paros - Web Proxy](http://sourceforge.net/projects/paros/)
	* A Java based HTTP/HTTPS proxy for assessing web application vulnerability. It supports editing/viewing HTTP messages on-the-fly. Other featuers include spiders, client certificate, proxy-chaining, intelligent scanning for XSS and SQL injections etc.
* [Mallory: Transparent TCP and UDP Proxy](https://intrepidusgroup.com/insight/mallory/)
	* Mallory is a transparent TCP and UDP proxy. It can be used to get at those hard to intercept network streams, assess those tricky mobile web applications, or maybe just pull a prank on your friend.
* [TCP Catcher](http://www.tcpcatcher.org/)
	* TcpCatcher is a free TCP, SOCKS, HTTP and HTTPS proxy monitor server software. 
* [wssip](https://github.com/nccgroup/wssip)
	* Application for capturing, modifying and sending custom WebSocket data from client to server and vice versa.


--------------
### WebRTC
* [STUN IP Address requests for WebRTC](https://github.com/diafygi/webrtc-ips)







----------------
### <a name="waf">Web Application Firewalls(WAFs)</a>
* **WAFs**
	* [ModSecurity](https://github.com/SpiderLabs/ModSecurity)
		* ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx that is developed by Trustwave's SpiderLabs. It has a robust event-based programming language which provides protection from a range of attacks against web applications and allows for HTTP traffic monitoring, logging and real-time analys
	* [Shadow Daemon](https://shadowd.zecure.org/overview/introduction/)
		* Shadow Daemon is a collection of tools to detect, protocol and prevent attacks on web applications. Technically speaking, Shadow Daemon is a web application firewall that intercepts requests and filters out malicious parameters. It is a modular system that separates web application, analysis and interface to increase security, flexibility and expandability. Shadow Daemon is free software. It is released under the license GPLv2, so its source code can be examined, modified and distributed by everyone.
	* [ftw](https://github.com/fastly/ftw)
		* Framework for Testing WAFs (FTW!)
* **Bypassing WAFs**
	* [Bypassing WAFs](http://www.nethemba.com/bypassing-waf.pdf)
	* [WAFPASS](https://github.com/wafpassproject/wafpass)
		* Analysing parameters with all payloads' bypass methods, aiming at benchmarking security solutions like WAF.






----------------
### Web Assembly
* [Web Assembly](http://webassembly.org/)
* [A cartoon intro to WebAssembly Articles](https://hacks.mozilla.org/category/code-cartoons/a-cartoon-intro-to-webassembly/)
* [Lin Clark: A Cartoon Intro to WebAssembly | JSConf EU 2017](https://www.youtube.com/watch?v=HktWin_LPf4&app=desktop)


----------------
### Web Sockets
* [WSSiP: A WebSocket Manipulation Proxy])(https://github.com/nccgroup/wssip)
	* Short for "WebSocket/Socket.io Proxy", this tool, written in Node.js, provides a user interface to capture, intercept, send custom messages and view all WebSocket and Socket.IO communications between the client and server.

----------------
### WebUSB
* **101**
	* [WebUSB API - Sept2017](https://wicg.github.io/webusb/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [WebUSB - How a website could steal data off your phone](https://labs.mwrinfosecurity.com/blog/webusb/)
		* This blog post looks in to the capabilities of WebUSB to understand how it works, the new attack surface, and privacy issues. We will describe the processes necessary to get access to devices and how permissions are handled in the browser. Then we will discuss some security implications and shows, how a website can use WebUSB to establish an ADB connection and effectively compromise a connected Android phone.







----------------
### XML
* [Hunting in the Dark - Blind XXE](https://blog.zsec.uk/blind-xxe-learning/)
* [Leading the Blind to Light! - A Chain to RCE](https://blog.zsec.uk/rce-chain/)
* [What You Didn't Know About XML External Entities Attacks](http://2013.appsecusa.org/2013/wp-content/uploads/2013/12/WhatYouDidntKnowAboutXXEAttacks.pdf)
* [Black Hat EU 2013 - XML Out-of-Band Data Retrieval](https://www.youtube.com/watch?v=eBm0YhBrT_c)
	* [Slides: XML Out-­Of-Band Data Retrieval - BHEU 2013](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)
* [Generic XXE Detection](http://www.christian-schneider.net/GenericXxeDetection.html)
* [Advice From A Researcher: Hunting XXE For Fun and Profit](http://blog.bugcrowd.com/advice-from-a-researcher-xxe/)
* [XXEinjector](https://github.com/enjoiz/XXEinjector)
	* XXEinjector automates retrieving files using direct and out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications
* [Playing with Content-Type – XXE on JSON Endpoints - NETSPI](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
* [FileCry - The New Age of XXE - BH USA 2015](https://www.blackhat.com/docs/us-15/materials/us-15-Wang-FileCry-The-New-Age-Of-XXE.pdf)
* [XXE OOB exploitation at Java 1.7+ - 2014](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html)
* [Security of applications that parse XML (supplementary) - 2009](http://d.hatena.ne.jp/teracc/20090718)
* [XXEInjector](https://github.com/enjoiz/XXEinjector)
	* XXEinjector automates retrieving files using direct and out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications.
* [Exploiting XXE In File Upload Functionality](https://www.blackhat.com/docs/us-15/materials/us-15-Vandevanter-Exploiting-XXE-Vulnerabilities-In-File-Parsing-Functionality.pdf)
* [XML Parser Evaluation - web-in-security.blogspot.de](https://web-in-security.blogspot.de/2016/03/xml-parser-evaluation.html)








----------------
### <a name="papers">Papers
* **General**
	* [The Spy in the Sandbox – Practical Cache Attacks in Javascript](http://iss.oy.ne.ro/SpyInTheSandbox.pdf)
		* We present the first micro-architectural side-channel at- tack which runs entirely in the browser. In contrast to other works in this genre, this attack does not require the attacker to install any software on the victim’s machine – to facilitate the attack, the victim needs only to browse to an untrusted webpage with attacker-controlled con- tent. This makes the attack model highly scalable and ex- tremely relevant and practical to today’s web, especially since most desktop browsers currently accessing the In- ternet are vulnerable to this attack. Our attack, which is an extension of the last-level cache attacks of Yarom et al. [23], allows a remote adversary recover information belonging to other processes, other users and even other virtual machines running on the same physical host as the victim web browser. We describe the fundamentals behind our attack, evaluate its performance using a high bandwidth covert channel and finally use it to construct a system-wide mouse/network activity logger. Defending against this attack is possible, but the required counter- measures can exact an impractical cost on other benign uses of the web browser and of the computer.
	* [Self-Exfiltration: The Dangers of Browser-Enforced Information Flow Control](http://ericchen.me/self_exfiltration.pdf)
		* Abstract —Since the early days of Netscape, browser vendors and web security researchers have restricted out-going data based on its destination. The security argument accompanying these mechanisms is that they prevent sensitive user data from being sent to the attacker’s domain. However, in this paper, we show that regulating web information flow based on its destination server is an inherently flawed security practice. It is vulnerable to self-exfiltration attacks, where an adversary stashes stolen information in the database of a whitelisted site, then later independently connects to the whitelisted site to retrieve the information. We describe eight existing browser security mechanisms that are vulnerable to these “self-exfiltration” attacks. Furthermore, we discovered at least one exfiltration channel for each of the Alexa top 100 websites. None of the existing information flow control mechanisms we surveyed are sufficient to protect data from being leaked to the attacker. Our goal is to prevent browser vendors and researchers from falling into this trap by designing more systems that are vulnerable to self-exfiltration.
	* [The Devil is in the Constants: Bypassing Defenses in Browser JIT Engines](http://users.ics.forth.gr/~elathan/papers/ndss15.pdf)
		* Abstract —Return-oriented programming (ROP) has become the dominant form of vulnerability exploitation in both user and kernel space. Many defenses against ROP exploits exist, which can significantly raise the bar against attackers. Although protecting existing code, such as applications and the kernel, might be possible, taking countermeasures against dynamic code, i.e., code that is generated only at run-time, is much harder. Attackers have already started exploiting Just-in-Time (JIT) engines, available in all modern browsers, to introduce their (shell)code (either native code or re-usable gadgets) during JIT compilation, and then taking advantage of it. Recognizing this immediate threat, browser vendors started employing defenses for hardening their JIT engines. In this paper, we show that—no matter the employed defenses—JIT engines are still exploitable using solely dynamically generated gadgets. We demonstrate that dynamic ROP payload construction is possible in two modern web browsers without using any of the available gadgets contained in the browser binary or linked libraries. First, we exploit an open source JIT engine (Mozilla Firefox) by feeding it malicious JavaScript, which once processed generates all re- quired gadgets for running any shellcode successfully. Second, we exploit a proprietary JIT engine, the one in the 64-bit Microsoft Internet Explorer, which employs many undocumented, specially crafted defenses against JIT exploitation. We manage to bypass all of them and create the required gadgets for running any shellcode successfully. All defensive techniques are documented in this paper to assist other researchers. Furthermore, besides showing how to construct ROP gadgets on-the-fly, we also show how to discover them on-the-fly, rendering current randomization schemes ineffective. Finally, we perform an analysis of the most important defense currently employed, namely constant blinding , which shields all three-byte or larger immediate values in the JIT buffer for hindering the construction of ROP gadgets. Our analysis suggests that extending constant blinding to all immediate values (i.e., shielding 1-byte and 2-byte constants) dramatically decreases the JIT engine’s performance, introducing up to 80% additional instructions.
	* [Cookieless Monster: Exploring the Ecosystem of Web-based Device Fingerprinting](http://securitee.org/files/cookieless_sp2013.pdf)
		* Abstract —The web has become an essential part of our society and is currently the main medium of information delivery. Billions of users browse the web on a daily basis, and there are single websites that have reached over one billion user accounts. In this environment, the ability to track users and their online habits can be very lucrative for advertising companies, yet very intrusive for the privacy of users. In this paper, we examine how web-based device fingerprint- ing currently works on the Internet. By analyzing the code of three popular browser-fingerprinting code providers, we reveal the techniques that allow websites to track users without the need of client-side identifiers. Among these techniques, we show how current commercial fingerprinting approaches use questionable practices, such as the circumvention of HTTP proxies to discover a user’s real IP address and the installation of intrusive browser plugins. At the same time, we show how fragile the browser ecosystem is against fingerprinting through the use of novel browser- identifying techniques. With so many different vendors involved in browser development, we demonstrate how one can use diversions in the browsers’ implementation to distinguish successfully not only the browser-family, but also specific major and minor versions. Browser extensions that help users spoof the user-agent of their browsers are also evaluated. We show that current commercial approaches can bypass the extensions, and, in addition, take advantage of their shortcomings by using them as additional fingerprinting features.
	* [SSL/TLS Interception Proxies and Transitive Trust](http://media.blackhat.com/bh-eu-12/Jarmoc/bh-eu-12-Jarmoc-SSL_TLS_Interception-WP.pdf)
		* Secure Sockets Layer (SSL) [ 1 ] and its successor Transport Layer Security (TLS) [ 2 ] have become key components of the modern Internet . The privacy, integrity, and authenticity [ 3 ] [ 4 ] provided by these protocols are critical to allowing sensitive communications to occur . Without these systems, e - commerce, online banking , and business - to - business exchange of information would likely be far less frequent. Threat actors have also recognized the benefits of transport security, and they are increasingly turning to SSL to hide their activities . Advanced Persistent Threat ( APT ) attackers [ 5 ] , botnets [ 6 ] , and eve n commodity web attacks can leverage SSL encryption to evade detection. To counter these tactics, organizations are increasingly deploying security controls that intercept end - to - end encrypted channels. Web proxies, data loss prevention ( DLP ) systems, spec ialized threat detection solutions, and network intrusion prevention systems ( N IPS ) offer functionality to intercept, inspect , and filter encrypted traffic. Similar functionality is present in lawful intercept systems and solutions enabling the broad surve illance of encrypted communications by governments. Broadly classified as “SSL/TLS interception proxies ,” these solutions act as a “ man in the middle , ” violating the end - to - end security promises of SSL. This type of interception comes at a cost . Intercepti ng SSL - encrypted connections sacrifices a degree of privacy and integrity for the benefit of content inspection, often at the risk of authenticity and endpoint validation . Implementers and designers of SSL interception proxies should consider these risks and understand how their systems operate in unusual circumstances
	* [Scriptless Attacks – Stealing the Pie Without Touching the Sill](http://www.syssec.rub.de/media/emma/veroeffentlichungen/2012/08/16/scriptlessAttacks-ccs2012.pdf)
		* Due to their high practical impact, Cross-Site Scripting (X SS) attacks have attracted a lot of attention from the security community members. In the same way, a plethora of more or less effective defense techniques have been proposed, ad- dressing the causes and effects of XSS vulnerabilities. As a result, an adversary often can no longer inject or even execute arbitrary scripting code in several real-life scen arios. In this paper, we examine the attack surface that remains after XSS and similar scripting attacks are supposedly mit- igated by preventing an attacker from executing JavaScript code. We address the question of whether an attacker really needs JavaScript or similar functionality to perform attac ks aiming for information theft. The surprising result is that an attacker can also abuse Cascading Style Sheets (CSS) in combination with other Web techniques like plain HTML, inactive SVG images or font files. Through several case studies, we introduce the so called scriptless attacks and demonstrate that an adversary might not need to execute code to preserve his ability to extract sensitive informati on from well protected websites. More precisely, we show that an attacker can use seemingly benign features to build side channel attacks that measure and exfiltrate almost arbitrar y data displayed on a given website. We conclude this paper with a discussion of potential mit- igation techniques against this class of attacks. In additi on, we have implemented a browser patch that enables a website to make a vital determination as to being loaded in a de- tached view or pop-up window. This approach proves useful for prevention of certain types of attacks we here discuss.
	* [A Placement Vulnerability Study in Multi-Tenant Public Clouds](https://www.usenix.org/node/191017)
	* [LFI2RCE (Local File Inclusion to Remote Code Execution) advanced exploitation: /proc shortcuts](http://www.ush.it/2008/08/18/lfi2rce-local-file-inclusion-to-remote-code-execution-advanced-exploitation-proc-shortcuts/)
		* This paper exposes the ability from the attacker standpoint to use /proc in order to exploit LFI (Local File Inclusion) vulnerabilities.
	* [Cracking the Lens: Targeting HTTP's Hidden Attack Surface](https://portswigger.net/knowledgebase/papers/CrackingTheLens-whitepaper.pdf)
	* [Browser Security White Paper - Cure53](https://browser-security.x41-dsec.de/X41-Browser-Security-White-Paper.pdf)





----------------
### <a name="misc">Miscellaneous</a>
* [unindexed](https://github.com/mroth/unindexed/blob/master/README.md)
	* The site is constantly searching for itself in Google, over and over and over, 24 hours a day. The instant it finds itself in Google search results, the site will instantaneously and irrevocably securely delete itself. Visitors can contribute to the public content of the site, these contributions will also be destroyed when the site deletes itself.

[COWL: A Confinement System for the Web](http://cowl.ws/)
	* Robust JavaScript confinement system for modern web browsers. COWL introduces label-based mandatory access control to browsing contexts (pages, iframes, etc.) in a way that is fully backward-compatible with legacy web content. 
	* [Paper](http://www.scs.stanford.edu/~deian/pubs/stefan:2014:protecting.pdf)









----------------
### <a name="burp">Burp Stuff/Plugins</a>
* **Tutorials/Tips/Stuff**
	* [OWASP Top 10: Hacking Web Applications with Burp Suite - Chad Furman](https://www.youtube.com/watch?v=2p6twRRXK_o)
	* [Burp Pro : Real-life tips and tricks](https://hackinparis.com/talk-nicolazs-gregoire)
	* [Behind enemy lines: Bug hunting with Burp Infiltrator](http://blog.portswigger.net/2017/06/behind-enemy-lines-bug-hunting-with.html)
	* [Automating Web Apps Input fuzzing via Burp Macros](http://blog.securelayer7.net/automating-web-apps-input-fuzzing-via-burp-macros/)
* **Plugins**
	* [Adapting Burp Extensions for Tailored Pentesting](http://blog.portswigger.net/2017/08/adapting-burp-extensions-for-tailored.html)
	* [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)
		* AuthMatrix is a Burp Suite extension that provides a simple way to test authorization in web applications and web services. 
	* [Autorize](https://github.com/Quitten/Autorize)
		* Autorize is an automatic authorization enforcement detection extension for Burp Suite. It was written in Python by Barak Tawily, an application security expert, and Federico Dotta, a security expert at Mediaservice.net. Autorize was designed to help security testers by performing automatic authorization tests. With the last release now Autorize also perform automatic authentication tests.
	* [backslash-powered-scanner](https://github.com/PortSwigger/backslash-powered-scanner)
		* This extension complements Burp's active scanner by using a novel approach capable of finding and confirming both known and unknown classes of server-side injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering.
	* [burp-rest-api](https://github.com/vmware/burp-rest-api)
		* A REST/JSON API to the Burp Suite security tool.  Upon successfully building the project, an executable JAR file is created with the Burp Suite Professional JAR bundled in it. When the JAR is launched, it provides a REST/JSON endpoint to access the Scanner, Spider, Proxy and other features of the Burp Suite Professional security tool.
	* [BurpSmartBuster](https://github.com/pathetiq/BurpSmartBuster)
		* Looks for files, directories and file extensions based on current requests received by Burp Suite
	* [BurpKit](https://github.com/allfro/BurpKit)
		* BurpKit is a BurpSuite plugin which helps in assessing complex web apps that render the contents of their pages dynamically. It also provides a bi-directional Script bridge API which allows users to create quick one-off BurpSuite plugin prototypes which can interact directly with the DOM and Burp's extender API.
	* [BurpSmartBuster](https://github.com/pathetiq/BurpSmartBuster)
		* A Burp Suite content discovery plugin that add the smart into the Buster!
	* [collaborator-everywhere](https://github.com/PortSwigger/collaborator-everywhere)
		* A Burp Suite Pro extension which augments your proxy traffic by injecting non-invasive headers designed to reveal backend systems by causing pingbacks to Burp Collaborator
	* [C02](https://code.google.com/p/burp-co2/)
		* Co2 includes several useful enhancements bundled into a single Java-based Burp Extension. The extension has it's own configuration tab with multiple sub-tabs (for each Co2 module). Modules that interact with other Burp tools can be disabled from within the Co2 configuration tab, so there is no need to disable the entire extension when using just part of the functionality.
	* [distribute-damage](https://github.com/PortSwigger/distribute-damage)
		* Designed to make Burp evenly distribute load across multiple scanner targets, this extension introduces a per-host throttle, and a context menu to trigger scans from. It may also come in useful for avoiding detection.
	* [HUNT](https://github.com/bugcrowd/HUNT)
		* HUNT is a Burp Suite extension to: 1. Identify common parameters vulnerable to certain vulnerability classes; 2. Organize testing methodologies inside of Burp Suite;
	* [HUNT Burp Suite Extension](https://github.com/bugcrowdlabs/HUNT)
		* HUNT Logo  HUNT is a Burp Suite extension to: 1. Identify common parameters vulnerable to certain vulnerability classes. 2. Organize testing methodologies inside of Burp Suite.
	* [IntruderPayloads](https://github.com/1N3/IntruderPayloads/blob/master/README.md)
	* [Office Open XML Editor - burp extension](https://github.com/maxence-schmitt/OfficeOpenXMLEditor)
	* [ParrotNG - burp plugin](https://portswigger.net/bappstore/bapps/details/f99325340a404c67a8de2ce593824e0e)
	* [PwnBack](https://github.com/k4ch0w/PwnBack)
		* Burp Extender plugin that generates a sitemap of a website using Wayback Machine
	* [SAML Raider](https://github.com/SAMLRaider/SAMLRaider)
		* SAML Raider is a Burp Suite extension for testing SAML infrastructures. It contains two core functionalities: Manipulating SAML Messages and manage X.509 certificates.
	* [swurg](https://github.com/AresS31/swurg)
		* Parses Swagger files into the BurpSuite for automating RESTful API testing – approved by Burp for inclusion in their official BApp Store.





--------------------
### <a name="aws"></a>AWS
* **Attacking**
	* [Gone in 60 Milliseconds - Intrusion and Exfiltration in Server-less Architectures](https://media.ccc.de/v/33c3-7865-gone_in_60_milliseconds)
		* More and more businesses are moving away from monolithic servers and turning to event-driven microservices powered by cloud function providers like AWS Lambda. So, how do we hack in to a server that only exists for 60 milliseconds? This talk will show novel attack vectors using cloud event sources, exploitabilities in common server-less patterns and frameworks, abuse of undocumented features in AWS Lambda for persistent malware injection, identifying valuable targets for pilfering, and, of course, how to exfiltrate juicy data out of a secure Virtual Private Cloud. 
	* [Bucketlist](https://github.com/michenriksen/bucketlist)
		* Bucketlist is a quick project I threw together to find and crawl Amazon S3 buckets and put all the data into a PostgreSQL database for querying.
	* [Penetration Testing AWS Storage: Kicking the S3 Bucket](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/)
	* [AWS pwn](https://github.com/dagrz/aws_pwn)
		* This is a collection of horribly written scripts for performing various tasks related to penetration testing AWS. Please don't be sad if it doesn't work for you. It might be that AWS has changed since a given tool was written or it might be that the code sux. Either way, please feel free to contribute. Most of this junk was written by Daniel Grzelak but there's been plenty of contributions, most notably Mike Fuller.
	* [bucket-stream](https://github.com/eth0izzle/bucket-stream/blob/master/README.md)
		* This tool simply listens to various certificate transparency logs (via certstream) and attempts to find public S3 buckets from permutations of the certificates domain name.	
* **General**
	* [Using DNS to Break Out of Isolated Networks in a AWS Cloud Environment](https://dejandayoff.com/using-dns-to-break-out-of-isolated-networks-in-a-aws-cloud-environment/)
		* Customers can utilize AWS' DNS infrastructure in VPCs (enabled by default). Traffic destined to the AmazonProvidedDNS is traffic bound for AWS management infrastructure and does not egress via the same network links as standard customer traffic and is not evaluated by Security Groups. Using DNS exfiltration, it is possible to exfiltrate data out of an isolated network.
* **Securing**
	* [AWS Security Primer](https://cloudonaut.io/aws-security-primer/#fn:2)
* **Tools**
	* [Scout2](https://github.com/nccgroup/Scout2)
		* Scout2 is a security tool that lets AWS administrators assess their environment's security posture. Using the AWS API, Scout2 gathers configuration data for manual inspection and highlights high-risk areas automatically. Rather than pouring through dozens of pages on the web, Scout2 supplies a clear view of the attack surface automatically.
	* [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)
		* Security Tool to Look For Interesting Files in S3 Buckets
	* [buckethead.py](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/aws-pentest-tools)
		* buckethead.py searches across every AWS region for a variety of bucket names based on a domain name, subdomains, affixes given and more. Currently the tool will only present to you whether or not the bucket exists or if they're listable. If the bucket is listable, then further interrogation of the resource can be done. It does not attempt download or upload permissions currently but could be added as a module in the future. You will need the awscli to run this tool as this is a python wrapper around this tool.

------------------
### <a name="gcc"></a>Google Compute Cloud/AppEngine
* **Articles/Writeups**
	* [G-Jacking AppEngine-based applications - HITB2014](https://conference.hitb.org/hitbsecconf2014ams/materials/D2T1-G-Jacking-AppEngine-based-Applications.pdf)
* **Tools**
* [Introducing G-Scout](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/august/introducing-g-scout/)
	* G-Scout is a tool to help assess the security of Google Cloud Platform (GCP) environment configurations. By leveraging the Google Cloud API, G-Scout automatically gathers a variety of configuration data and analyzes this data to determine security risks. It produces HTML output.
* [Google Cloud Platform Security Tool](https://github.com/nccgroup/G-Scout)



