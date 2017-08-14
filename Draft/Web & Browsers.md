

##Web, Web Applications & Browsers



* [General](#general)
* [Talks & Presentations](#talks)
* [Attacking Browsers](#atkb)
* [XSS](#xss)
* [NO/SQL](#sql)
* [L/RFI](#lrfi)
* [Different Types of Web based attacks](#difatk)
	* [Template Injection](#ssti)
	* [Abuse of Functionality](#)
	* [Data Structure Attacks](#)
	* [Embedded Malicious Code](#emc)
	* [Exploitation of Authentication](#eoa)
	* [Injection Based Attacks](#ija)
	* [Java Deserialization Attacks](#jsa)
	* [Path Traversal Attacks](#pta)
	* [Probabilistic Attacks](#pa)
	* [Protocol Manipulation](#pm)
	* [Resource Depletion](#rd)
	* [Resource Manipulation](#rm)
	* [Sniffing Based](#sb)
	* [Spoofing Based](#spb)
* [CMSs](#cms)
* [Client Web Proxies](#webproxy)
* [Javascript](#javascript)
* [Javascript Encoders/Decoders](#encode)
* [General Encoding/Decoding Tools](#generalencode)
* [Write-ups](#writeups)
* [General Tools](#generalt)
* [WebShells](#shells)
* [Brute Force Tools](#brute)
* [Web Application Firewalls](#waf)
* [Bypassing Web Application Firewalls](#bwaf)
* [Attack Writeups](#writeups)
* [Securing Web Based Applications/Servers](#secure)
* [Non-Attack Writeups](#nonwriteup)
# [CSRF](#csrf)
* [HTML5](#html5)
* [JSON Web Tokens](#jwt)
* Rest
* API Testing
* Web Sockets
* [Miscellaneous](#misc)
* [Securing Web Applications/Security Checklists](#checklists)
* [Burp Plugins/Stuff](#burp)




#### To-add
Java Serialization papers/stuff
DVWA/similar to educational section


#### Sort

http://console-cowboys.blogspot.com/2011/05/web-hacking-video-series-1-automating.html 

http://www.grymoire.com/Security/Hardware.html

prompt.ml

Clickjacking attacks
#### End Sort














### <a name="general">General</a>

[JSFuck](http://www.jsfuck.com/)
* JSFuck is an esoteric and educational programming style based on the atomic parts of JavaScript. It uses only six different characters to write and execute code.
https://blog.netspi.com/sql-server-persistence-part-1-startup-stored-procedures/

[How to Obscure Any URL](http://www.pc-help.org/obscure.htm)

[HTTP Evasion](http://noxxi.de/research/http-evader-explained-8-borderline-robustness.html)

[Learn REST: A Tutorial](http://rest.elkstein.org/)

[Attack Surface Analysis Cheat Sheet](https://www.owasp.org/index.php/Attack_Surface_Analysis_Cheat_Sheet)

[Wordpress Security Guide - WPBeginner](http://www.wpbeginner.com/wordpress-security/)

[AWS Security Primer](https://cloudonaut.io/aws-security-primer/#fn:2)








### Talks &  Presentations

[The Website Obesity Crisis](http://idlewords.com/talks/website_obesity.htm)

[Attacking Modern SaaS Companies](https://github.com/cxxr/talks/blob/master/2017/nolacon/Attacking%20Modern%20SaaS%20Companies%20%E2%80%93%20NolaCon.pdf)
* [Presentation](https://www.youtube.com/watch?v=J0otoKRh1Vk&app=desktop)

[The AppSec Starter Kit Timothy De Block](https://www.youtube.com/watch?v=KMz8lWNAUmg)

[Server-side browsing considered harmful](http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)

[Backslash Powered Scanning: Hunting Unknown Vulnerability Classes](http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html)
*  Existing web scanners search for server-side injection vulnerabilities by throwing a canned list of technology-specific payloads at a target and looking for signatures - almost like an anti-virus. In this document, I'll share the conception and development of an alternative approach, capable of finding and confirming both known and unknown classes of injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering.

[NodeJS: Remote Code Execution as a Service - Peabnuts123 – Kiwicon 2016](https://www.youtube.com/watch?v=Qvtfagwlfwg)
* [SLIDES](http://archivedchaos.com/post/153372061089/kiwicon-2016-slides-upload)




### <a name="edu">Educational</a>

[Intro to content Security Policy](http://www.html5rocks.com/en/tutorials/security/content-security-policy/)

[Client Identification Mechanisms](http://www.chromium.org/Home/chromium-security/client-identification-mechanisms)

[The Tale of a Fameless but Widespread Web Vulnerability Class - Veit Hailperin](https://www.youtube.com/watch?v=5qA0CtS6cZ4)
* Two keys components account for finding vulnerabilities of a certain class: awareness of the vulnerability and ease of finding the vulnerability. Cross-Site Script Inclusion (XSSI) vulnerabilities are not mentioned in the de facto standard for public attention - the OWASP Top 10. Additionally there is no public tool available to facilitate finding XSSI. The impact reaches from leaking personal information stored, circumvention of token-based protection to complete compromise of accounts. XSSI vulnerabilities are fairly wide spread and the lack of detection increases the risk of each XSSI. In this talk we are going to demonstrate how to find XSSI, exploit XSSI and also how to protect against XSSI.



[Hackazon](https://github.com/rapid7/hackazon)
* Hackazon is a free, vulnerable test site that is an online storefront built with the same technologies used in today’s rich client and mobile applications. Hackazon has an AJAX interface, strict workflows and RESTful API’s used by a companion mobile app providing uniquely-effective training and testing ground for IT security professionals. And, it’s full of your favorite vulnerabilities like SQL Injection, cross-site scripting and so on.

[DOM - Standard](https://dom.spec.whatwg.org/)

[HTML 5 Standards](http://w3c.github.io/html/)

[Web IDL Standards](https://heycam.github.io/webidl/)








### <a name="generalt">General Tools</a>

[ParrotNG](https://github.com/ikkisoft/ParrotNG/releases)
* ParrotNG is a Java-based tool for automatically identifying vulnerable SWF files, built on top of swfdump. One JAR, two flavors: command line tool and Burp Pro Passive Scanner Plugin.

[HTTPie - curl for humans](https://gith*ub.com/jakubroztocil/httpie)
* HTTPie (pronounced aych-tee-tee-pie) is a command line HTTP client. Its goal is to make CLI interaction with web services as human-friendly as possible. It provides a simple http command that allows for sending arbitrary HTTP requests using a simple and natural syntax, and displays colorized output. HTTPie can be used for testing, debugging, and generally interacting with HTTP servers.

[leaps - shared text editing in Golang](https://github.com/denji/leaps)
* Leaps is a service for hosting collaboratively edited documents using operational transforms to ensure zero-collision synchronization across any number of editing clients.

[HTTrack - Website Copier](https://www.httrack.com/)
* It allows you to download a World Wide Web site from the Internet to a local directory, building recursively all directories, getting HTML, images, and other files from the server to your computer. HTTrack arranges the original site's relative link-structure. Simply open a page of the "mirrored" website in your browser, and you can browse the site from link to link, as if you were viewing it online. HTTrack can also update an existing mirrored site, and resume interrupted downloads. HTTrack is fully configurable, and has an integrated help system. 

[lan-js](https://github.com/jvennix-r7/lan-js)
* Probe LAN devices from a web browser.

[OWASP Mantra](http://www.getmantra.com/hackery/)
* “OWASP Mantra is a powerful set of tools to make the attacker's task easier”

[WhatWeb](https://github.com/urbanadventurer/WhatWeb)

[Xenotix](https://github.com/ajinabraham/OWASP-Xenotix-XSS-Exploit-Framework)
*  OWASP Xenotix XSS Exploit Framework is an advanced Cross Site Scripting (XSS) vulnerability detection and exploitation framework.

[gethead](https://github.com/httphacker/gethead)
* HTTP Header Analysis Vulnerability Tool 

[SSleuth](https://github.com/sibiantony/ssleuth)
* A firefox add-on to rate the quality of HTTPS connections

[dvcs-ripper](https://github.com/kost/dvcs-ripper)
* Rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr, ... It can rip repositories even when directory browsing is turned off.

[htshells](https://github.com/wireghoul/htshells)
* Self contained web shells and other attacks via .htaccess files.

[AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)
* Security Tool to Look For Interesting Files in S3 Buckets

[timing_attack](https://github.com/ffleming/timing_attack)
* Perform timing attacks against web applications

[Kraken - Web Interface Survey Tool](https://github.com/Sw4mpf0x/Kraken)
* [Blogpost](https://pentestarmoury.com/2017/01/31/kraken-web-interface-survey-tool/)

[PowerWebShot](https://github.com/dafthack/PowerWebShot)
* A PowerShell tool for taking screenshots of multiple web servers quickly.

[hackability](https://github.com/PortSwigger/hackability)
* Rendering Engine Hackability Probe performs a variety of tests to discover what the unknown rendering engine supports. To use it simply extract it to your web server and visit the url in the rendering engine you want to test. The more successful probes you get the more likely the target engine is vulnerable to attack.

[Caja](https://developers.google.com/caja/)
*  The Caja Compiler is a tool for making third party HTML, CSS and JavaScript safe to embed in your website. It enables rich interaction between the embedding page and the embedded applications. Caja uses an object-capability security model to allow for a wide range of flexible security policies, so that your website can effectively control what embedded third party code can do with user data.





#### <a name="difatk">Different Types of Web Based Attacks</a>
As seen on: https://www.owasp.org/index.php/Category:Attack



#### <a name="ssti">Server Side Template Injection</a>

[Server Side Template Injection](http://blog.portswigger.net/2015/08/server-side-template-injection.html)





##### <a name="Abuse of Functionality[#
[jsgifkeylogger](https://github.com/wopot/jsgifkeylogger)
* a javascript keylogger included in a gif file This is a PoC





##### <a name="Data Structure Attacks](#

[EXPLOITING XXE IN FILE UPLOAD FUNCTIONALITY](https://www.blackhat.com/docs/us-15/materials/us-15-Vandevanter-Exploiting-XXE-Vulnerabilities-In-File-Parsing-Functionality.pdf)




##### <a name="emc">Embedded Malicious Code</a>



##### <a name="eoa">Exploitation of Authentication</a>




##### <a name="ija">Injection Based Attacks</a>

[Exploiting ShellShock getting a reverse shell](http://www.fantaghost.com/exploiting-shellshock-getting-reverse-shell)

[commix](https://github.com/stasinopoulos/commix)
* Automated All-in-One OS Command Injection and Exploitation Tool

JNDI Attack Class
[A Journey from JNDI-LDAP Manipulation to RCE](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)

[SHELLING](https://github.com/ewilded/shelling)
* A comprehensive OS command injection payload generator

[Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)




### Cross Site Request Forgery (CSRF)
[Cross Site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29)




##### <a name="jsa">Java/Serialization Attacks</a>

[Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)

[Break Fast Serial](https://github.com/GoSecure/break-fast-serial)
* A proof of concept that demonstrates asynchronous scanning for Java deserialization bugs

[SerialKiller: Bypass Gadget Collection](https://github.com/pwntester/SerialKillerBypassGadgetCollection)
* Collection of Bypass Gadgets that can be used in JVM Deserialization Gadget chains to bypass "Look-Ahead ObjectInputStreams" desfensive deserialization.

[ysoserial](https://github.com/frohoff/ysoserial)


[The perils of Java deserialization](https://community.hpe.com/t5/Security-Research/The-perils-of-Java-deserialization/ba-p/6838995)

[Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
* A cheat sheet for pentesters about Java Native Binary Deserialization vulnerabilities

[Java Unmarshaller Security - Turning your data into code execution](https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true)
* This paper presents an analysis, including exploitation details, of various Java open-source marshalling libraries that allow(ed) for unmarshalling of arbitrary, attacker supplied, types and shows that no matter how this process is performed and what implicit constraints are in place it is prone to similar exploitation techniques.
* tool from the above paper: [marshalsec](https://github.com/mbechler/marshalsec/)

[Reliable discovery and Exploitation of Java Deserialization vulns](https://techblog.mediaservice.net/2017/05/reliable-discovery-and-exploitation-of-java-deserialization-vulnerabilities/)

[Pwning Your Java Messaging With De- serialization Vulnerabilities](https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities-wp.pdf)

[Java Deserialization Security FAQ](https://christian-schneider.net/JavaDeserializationSecurityFAQ.html)

[The Perils of Java Deserialization](http://community.hpe.com/hpeb/attachments/hpeb/off-by-on-software-security-blog/722/1/HPE-SR%20whitepaper%20java%20deserialization%20RSA2016.pdf)

[Detecting deserialization bugs with DNS exfiltration](http://gosecure.net/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltration/)

[JMET](https://github.com/matthiaskaiser/jmet)
* JMET was released at Blackhat USA 2016 and is an outcome of Code White's research effort presented in the talk "Pwning Your Java Messaging With Deserialization Vulnerabilities". The goal of JMET is to make the exploitation of the Java Message Service (JMS) easy. In the talk more than 12 JMS client implementations where shown, vulnerable to deserialization attacks. The specific deserialization vulnerabilities were found in ObjectMessage implementations (classes implementing javax.jms.ObjectMessage).

[Serianalyzer](https://github.com/mbechler/serianalyzer)
* A static byte code analyzer for Java deserialization gadget research

[Java Deserialization Exploits](https://github.com/CoalfireLabs/java_deserialization_exploits)
* A collection of Java Deserialization Exploits








##### <a name="pta">Path Traversal Attacks</a>
[Exploiting PHP File Inclusion – Overview](https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/)






### <a name="javascript">JavaScript</a>
[JSDetox](http://relentless-coding.org/projects/jsdetox/info)
* JSDetox is a tool to support the manual analysis of malicious Javascript code. 

[Dom Flow - Untangling The DOM For More Easy-Juicy Bugs  - BH USA 2015](https://www.youtube.com/watch?v=kedmtrIEW1k&list=PLH15HpR5qRsXF78lrpWP2JKpPJs_AFnD7&index=111)









#### <a name="encode">De/Encoders</a>

[Unphp.net php decoder](http://www.unphp.net/decode/)

[Various forms of encoding/decoding web app](http://yehg.net/encoding/)

[Javascript De-Obfuscation Tools Redux](http://www.kahusecurity.com/2014/javascript-deobfuscation-tools-redux/)
* Back in 2011, I took a look at several tools used to deobfuscate Javascript. This time around I will use several popular automated and semi-automated/manual tools to see how they would fare against today’s obfuscated scripts with the least amount of intervention.	









### <a name="brute">Brute Force/Fuzzing</a>
[Dirbuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
* DirBuster is a multi threaded java application designed to brute force directories and files names on web/application servers. Often is the case now of what looks like a web server in a state of default installation is actually not, and has pages and applications hidden within. DirBuster attempts to find these.

[Go Buster](https://github.com/OJ/gobuster)
* Directory/file busting tool written in Go 
* Recursive, CLI-based, no java runtime

[WFuzz](https://code.google.com/p/wfuzz/
Wfuzz is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked (directories, servlets, scripts, etc), bruteforce GET and POST parameters for checking different kind of injections (SQL, XSS, LDAP,etc), bruteforce Forms parameters (User/Password), Fuzzing,etc

###<a name="cms">CMS's</a>
[Drupal Security Checklist](https://github.com/gfoss/attacking-drupal/blob/master/presentation/drupal-security-checklist.pdf)

[Highly Effective Joomla Backdoor with Small Profile](http://blog.sucuri.net/2014/02/highly-effective-joomla-backdoor-with-small-profile.html)

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

[Big List of Naughty Strings](https://github.com/minimaxir/big-list-of-naughty-strings)
* The Big List of Naughty Strings is an evolving list of strings which have a high probability of causing issues when used as user-input data. This is intended for use in helping both automated and manual QA testing; useful for whenever your QA engineer walks into a bar.









### Site/Webapp Scanners

[nikto]()

[skipfish](https://code.google.com/p/skipfish/)
* Skipfish is an active web application security reconnaissance tool. It prepares an interactive sitemap for the targeted site by carrying out a recursive crawl and dictionary-based probes. The resulting map is then annotated with the output from a number of active (but hopefully non-disruptive) security checks. The final report generated by the tool is meant to serve as a foundation for professional web application security assessments. 

[wikto](https://github.com/sensepost/wikto)
* Wikto is Nikto for Windows - but with a couple of fancy extra features including Fuzzy logic error code checking, a back-end miner, Google assisted directory mining and real time HTTP request/response monitoring. Wikto is coded in C# and requires the .NET framework. 

[RAWR - Rapid Assessment of Web Resources](https://bitbucket.org/al14s/rawr/wiki/Home)

[Arachni Web Scanner](http://www.arachni-scanner.com/)
* Arachni is an Open Source, feature-full, modular, high-performance Ruby framework aimed towards helping penetration testers and administrators evaluate the security of web applications.  It is smart, it trains itself by monitoring and learning from the web application's behavior during the scan process and is able to perform meta-analysis using a number of factors in order to correctly assess the trustworthiness of results and intelligently identify (or avoid) false-positives. 

[WhatWeb](https://github.com/urbanadventurer/WhatWeb)
* WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1500 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.

[WATOBO](https://github.com/siberas/watobo)
* WATABO is a security tool for testing web applications. It is intended to enable security professionals to perform efficient (semi-automated) web application security audits.

[YASUO](https://github.com/0xsauby/yasuo)
* Yasuo is a ruby script that scans for vulnerable 3rd-party web applications.

[WPSeku](https://github.com/m4ll0k/WPSeku)
* Wordpress Security Scanner

[wpscan](https://github.com/wpscanteam/wpscan)

[cms-explorer](https://github.com/FlorianHeigl/cms-explorer)





### <a name="webproxy">Web Proxies</a>

[Burpsuite](http://portswigger.net/burp/)
* Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities. 

[C02](https://code.google.com/p/burp-co2/)
* Co2 includes several useful enhancements bundled into a single Java-based Burp Extension. The extension has it's own configuration tab with multiple sub-tabs (for each Co2 module). Modules that interact with other Burp tools can be disabled from within the Co2 configuration tab, so there is no need to disable the entire extension when using just part of the functionality. 

[ZAP - Zed Attack Proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
* The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications.  It is designed to be used by people with a wide range of security experience and as such is ideal for developers and functional testers who are new to penetration testing.  ZAP provides automated scanners as well as a set of tools that allow you to find security vulnerabilities manually.

[Paros - Web Proxy](http://sourceforge.net/projects/paros/)
* A Java based HTTP/HTTPS proxy for assessing web application vulnerability. It supports editing/viewing HTTP messages on-the-fly. Other featuers include spiders, client certificate, proxy-chaining, intelligent scanning for XSS and SQL injections etc.

[Mallory: Transparent TCP and UDP Proxy](https://intrepidusgroup.com/insight/mallory/)
* Mallory is a transparent TCP and UDP proxy. It can be used to get at those hard to intercept network streams, assess those tricky mobile web applications, or maybe just pull a prank on your friend.

[TCP Catcher](http://www.tcpcatcher.org/)
* TcpCatcher is a free TCP, SOCKS, HTTP and HTTPS proxy monitor server software. 

[wssip](https://github.com/nccgroup/wssip)
* Application for capturing, modifying and sending custom WebSocket data from client to server and vice versa.








### <a name="shells">Web Shells</a>

[Weevely](https://github.com/epinna/weevely3)
* Weevely is a command line web shell dinamically extended over the network at runtime used for remote administration and pen testing. It provides a weaponized telnet-like console through a PHP script running on the target, even in restricted environments.  The low footprint agent and over 30 modules shape an extensible framework to administrate, conduct a pen-test, post-exploit, and audit remote web accesses in order to escalate privileges and pivot deeper in the internal networks.
* [Getting Started](https://github.com/epinna/weevely3/wiki#getting-started)

[b374k shell 3.2](https://github.com/b374k/b374k)
* This PHP Shell is a useful tool for system or web administrator to do remote management without using cpanel, connecting using ssh, ftp etc. All actions take place within a web browser

| **Simple websockets based webshell** | http://ibreak.software/2015/02/18/simple-websockets-based-webshell/





 


### <a name="generalencode">General Encoders/Decoders</a>




### <a name="nonwriteup">Non-Attack Writeups</a>

[Security and Open Redirects  Impact of 301-ing people in 2013](https://makensi.es/rvl/openredirs/#/)

[Postcards from a Post-XSS World - Michael Zalewski](http://lcamtuf.coredump.cx/postxss/#dangling-markup-injection)
* This page is a rough collection of notes on some of the fundamental alternatives to direct script injection that would be available to attackers following the universal deployment of CSP or other security mechanisms designed to prevent the execution of unauthorized scripts. I hope to demonstrate that in many cases, the capabilities offered by these alternative methods are highly compatible with the goals of contemporary XSS attacks.













### <a name="checklist">Securing Web Applications/Checklists</a>


[Center for Internet Security Apache Server 2.4 Hardening Guide](https://benchmarks.cisecurity.org/tools2/apache/CIS_Apache_HTTP_Server_2.4_Benchmark_v1.1.0.pdf)

[Securing Web Application Technologies Checklist](http://www.securingthehuman.org/developer/swat

[OWASP Testing Checklist](https://www.owasp.org/index.php/Testing_Checklist)

[WebAppSec Testing Checklist](http://tuppad.com/blog/wp-content/uploads/2012/03/WebApp_Sec_Testing_Checklist.pdf)


[OWASP Web Application Security Testing Cheat Sheet](https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet)

[Magical Code Injection Rainbow Framework](https://github.com/SpiderLabs/MCIR)
* The Magical Code Injection Rainbow! MCIR is a framework for building configurable vulnerability testbeds. MCIR is also a collection of configurable vulnerability testbeds. Has testing lessons for xss/csrf/sql












### <a name="waf">Web Application Firewalls</a>


[ModSecurity](https://github.com/SpiderLabs/ModSecurity)
* ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx that is developed by Trustwave's SpiderLabs. It has a robust event-based programming language which provides protection from a range of attacks against web applications and allows for HTTP traffic monitoring, logging and real-time analys

[Shadow Daemon](https://shadowd.zecure.org/overview/introduction/)
* Shadow Daemon is a collection of tools to detect, protocol and prevent attacks on web applications. Technically speaking, Shadow Daemon is a web application firewall that intercepts requests and filters out malicious parameters. It is a modular system that separates web application, analysis and interface to increase security, flexibility and expandability. Shadow Daemon is free software. It is released under the license GPLv2, so its source code can be examined, modified and distributed by everyone.

[ftw](https://github.com/fastly/ftw)
* Framework for Testing WAFs (FTW!)



<a name="bwaf">Bypassing Web Application Firewalls</a>
[Bypassing WAFs](http://www.nethemba.com/bypassing-waf.pdf)

[WAFPASS](https://github.com/wafpassproject/wafpass)
* Analysing parameters with all payloads' bypass methods, aiming at benchmarking security solutions like WAF.





### <a name="writeups">Web Application Attack Write-ups</a>

[Hacking with Pictures - Syscan2015](http://www.slideshare.net/saumilshah/hacking-with-pictures-syscan-2015)

[Relative Path Overwrite Explanation/Writeup](http://www.thespanner.co.uk/2014/03/21/rpo/)
* RPO (Relative Path Overwrite) is a technique to take advantage of relative URLs by overwriting their target file. To understand the technique we must first look into the differences between relative and absolute URLs. An absolute URL is basically the full URL for a destination address including the protocol and domain name whereas a relative URL doesn’t specify a domain or protocol and uses the existing destination to determine the protocol and domain.

[Attacking Adobe ColdFusion](http://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html)

[ColdFusion Security Resources](https://www.owasp.org/index.php/ColdFusion_Security_Resources)

[ColdFusion for Penetration Testers](http://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers)

[Abusing Google App Scripting Through Social Engineering](http://www.redblue.team/2017/02/abusing-google-app-scripting-through.html)

[File scanner web app (Part 1 of 5): Stand-up and webserver](http://0xdabbad00.com/2013/09/02/file-scanner-web-app-part-1-of-5-stand-up-and-webserver/)

[PHP Generic Gadget Chains: Exploiting unserialize in unknown environments](https://www.ambionics.io/blog/php-generic-gadget-chains)

[PHPGGC: PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
* PHPGGC is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically. When encountering an unserialize on a website you don't have the code of, or simply when trying to build an exploit, this tool allows you to generate the payload without having to go through the tedious steps of finding gadgets and combining them. Currently, the tool supports: Doctrine, Guzzle, Laravel, Monolog, Slim, SwiftMailer.

[Typosquatting programming language package managers](http://incolumitas.com/2016/06/08/typosquatting-package-managers/)

[Exploiting misuse of Python's "pickle"](https://blog.nelhage.com/2011/03/exploiting-pickle/)

[Hacking Jenkins Servers With No Password](https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password)

[ebay.com: RCE using CCS](http://secalert.net/#ebay-rce-ccs)






### <a name="lrfi">LFI & RFI</a>

[LFI Local File Inclusion Techniques (paper)](http://www.ush.it/2008/08/18/lfi2rce-local-file-inclusion-to-remote-code-execution-advanced-exploitation-proc-shortcuts/)
* This paper exposes the ability from the attacker standpoint to use /proc in order to exploit LFI (Local File Inclusion) vulnerabilities. While using /proc for such aim is well known this one is a specific technique that was not been previously published as far as we know. A tool to automatically exploit LFI using the shown approach is released accordingly. 
* [Update: a third (known) technique has been dissected here](http://www_ush_it/2008/07/09/local-file-inclusion-lfi-of-session-files-to-root-escalation/ ) 

[Liffy](https://github.com/rotlogix/liffy)
* Liffy is a Local File Inclusion Exploitation tool. 

[psychoPATH - LFI](https://github.com/ewilded/psychoPATH/blob/master/README.md)
* This tool is a highly configurable payload generator detecting LFI & web root file uploads. Involves advanced path traversal evasive techniques, dynamic web root list generation, output encoding, site map-searching payload generator, LFI mode, nix & windows support plus single byte generator.





### <a name="xss">XSS</a>
[Writing an XSS Worm](http://blog.gdssecurity.com/labs/2013/5/8/writing-an-xss-worm.html)

[3 Types of XSS](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting)
	* Dom-based
	* Reflected
	* Persistent

[Cross Frame Scripting](https://www.owasp.org/index.php/Cross_Frame_Scripting)

[Shuriken](https://github.com/shogunlab/shuriken)
* Cross-Site Scripting (XSS) command line tool for testing lists of XSS payloads on web apps.


[XSS Filter Bypass List](https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec)

[HTML Purifier XSS Attacks Smoketest](http://htmlpurifier.org/live/smoketests/xssAttacks.php)

[XSS Test String Dump](https://github.com/zsitro/XSS-test-dump/blob/master/xss.txt)

[Firing-Range](https://github.com/google/firing-range)
* Firing Range is a test bed for web application security scanners, providing synthetic, wide coverage for an array of vulnerabilities.

[XSS-Game.appspot](https://xss-game.appspot.com/)

[XSS game - escape.alf.nu](http://escape.alf.nu/)

[Self XSS we’re not so different you and I - Mathias Karlsson](https://www.youtube.com/watch?v=l3yThCIF7e4)

[xsscrapy](https://github.com/byt3bl33d3r/xsscrapy)

[XSSer](https://xsser.03c8.net/)

[XSS Sniper](https://sourceforge.net/projects/xssniper/)






## (NO)SQL Injection
[SQL Injection Cheat Sheet](http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/)

[PostgreSQL Pass The Hash protocol design weakness](https://hashcat.net/misc/postgres-pth/postgres-pth.pdf)

[SQL Injection wiki](http://www.sqlinjectionwiki.com/)

[SQL Injection Knowledge Base](http://websec.ca/kb/sql_injection#MySQL_Testing_Injection)

[sqlmap](https://github.com/sqlmapproject/sqlmap)

[Pen Testing MongoDB](http://www.irongeek.com/i.php?page=videos/derbycon4/t408-making-mongo-cry-attacking-nosql-for-pen-testers-russell-butturini)

[Laduanum](http://laudanum.sourceforge.net/)
* “Laudanum is a collection of injectable files, designed to be used in a pentest when SQL injection flaws are found and are in multiple languages for different environments.They provide functionality such as shell, DNS query, LDAP retrieval and others.”

[Making Mongo Cry Attacking NoSQL for Pen Testers Russell Butturini](https://www.youtube.com/watch?v=NgsesuLpyOg)

[MongoDB: Typical Security Weaknesses in a NoSQL DB](http://blog.spiderlabs.com/2013/03/mongodb-security-weaknesses-in-a-typical-nosql-database.html)

[Oracle SQL Injection Guides & Whitepapers](https://haiderm.com/oracle-sql-injection-guides-and-whitepapers/)

[Nosql-Exploitation-Framework](https://github.com/torque59/Nosql-Exploitation-Framework)
* A FrameWork For NoSQL Scanning and Exploitation Framework

[jSQL Injection](https://github.com/ron190/jsql-injection)
* jSQL Injection is a Java application for automatic SQL database injection.


[SQLi Lab lessons](https://github.com/Audi-1/sqli-labs)
* SQLI-LABS is a platform to learn SQLI

[Performing sqlmap POST request injection](https://hackertarget.com/sqlmap-post-request-injection/)




### Template Injection

[tplmap](https://github.com/epinna/tplmap)
* Code and Server-Side Template Injection Detection and Exploitation Tool





### <a name="atkb"Attacking Browsers</a>
[White Lightning Attack Platform](https://github.com/TweekFawkes/White_Lightning/tree/master/var/www)

[BeEF Browser Exploitation Framework](http://beefproject.com/

[Technical analysis of client identification mechanisms](http://www.chromium.org/Home/chromium-security/client-identification-mechanisms) 

[DOM Clobbering Attack](http://www.thespanner.co.uk/2013/05/16/dom-clobbering/)

[The Birth of a Complete IE11 Exploit Under the New Exploit Mitigations](https://www.syscan.org/index.php/download/get/aef11ba81927bf9aa02530bab85e303a/SyScan15%20Yuki%20Chen%20-%20The%20Birth%20of%20a%20Complete%20IE11%20Exploit%20Under%20the%20New%20Exploit%20Mitigations.pdf)

[Smashing The Browser: From Vulnerability Discovery To Exploit](https://github.com/demi6od/Smashing_The_Browser)
* Goes from introducing a fuzzer to producing an IE11 0day

[Attacking Browser Extensions](https://github.com/qll/attacking-browser-extensions)











### <a name="html5">HTML 5</a>

[SH5ARK](http://sh5ark.professionallyevil.com)
* The Securing HTML5 Assessment Resource Kit, or SH5ARK, is an open source project that provides a repository of HTML5 features, proof-of-concept attack code, and filtering rules. The purpose of this project is to provide a single repository that can be used to collect sample code of vulnerable HTML5 features, actual attack code, and filtering rules to help prevent attacks and abuse of these features. The intent of the project is to bring awareness to the opportunities that HTML5 is providing for attackers, to help identify these attacks, and provide measures for preventing them

* [Presentation on SH5ARK](https://www.youtube.com/watch?v=1ZZ-vIwmWx4)

* [GetSH5ARK here](http://sourceforge.net/projects/sh5ark/)



### JSON Web Tokens

[json token decode](http://jwt.calebb.net/)

[JWT Inspector - FF plugin](https://www.jwtinspector.io/)
* JWT Inspector is a browser extension that lets you decode and inspect JSON Web Tokens in requests, cookies, and local storage. Also debug any JWT directly from the console or in the built-in UI. 

[Attacking JWT authentication](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)

[Critical vulnerabilities in JSON Web Token libraries - 2015](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)










### <a name="papers">Papers

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

[A Placement Vulnerability Study in Multi-Tenant Public Clouds](https://www.usenix.org/node/191017)




















### REST & Web Services

[REST Security Cheat Sheet](REST Security Cheat Sheet)

[REST Assessment Cheat Sheet](https://www.owasp.org/index.php/REST_Assessment_Cheat_Sheet)

[RESTful Services, The Web Security Blind Spot](https://www.youtube.com/watch?feature=player_embedded&v=pWq4qGLAZHI#!)
* [Blogpost](https://xiom.com/2016/10/31/restful-services-web-security-blind-spot/)
* [Presentation Slides -pdf](https://xiomcom.files.wordpress.com/2016/10/security-testing-for-rest-applications-v6-april-2013.pdf)

[Cracking and Fixing REST APIs](http://www.sempf.net/post/Cracking-and-Fixing-REST-APIs)

[Cracking and fixing REST services](http://www.irongeek.com/i.php?page=videos/converge2015/track109-cracking-and-fixing-rest-services-bill-sempf)

[Representational State Transfer - Wikipedia](https://en.wikipedia.org/wiki/Representational_state_transfer)

[Web Services Security Testing Cheat Sheet Introduction - OWASP](https://www.owasp.org/index.php/Web_Service_Security_Testing_Cheat_Sheet)

[Damn Vulnerable Web Services dvws](https://github.com/snoopysecurity/dvws)
* Damn Vulnerable Web Services is an insecure web application with multiple vulnerable web service components that can be used to learn real world web service vulnerabilities.

[Service-Oriented-Architecture](https://en.wikipedia.org/wiki/Service-oriented_architecture)

[Microservices](https://en.wikipedia.org/wiki/Microservices)




### API Stuff

[burp-rest-api](https://github.com/vmware/burp-rest-api)
* A REST/JSON API to the Burp Suite security tool.  Upon successfully building the project, an executable JAR file is created with the Burp Suite Professional JAR bundled in it. When the JAR is launched, it provides a REST/JSON endpoint to access the Scanner, Spider, Proxy and other features of the Burp Suite Professional security tool.

[RESTful API Best Practices and Common Pitfalls](https://medium.com/@schneidenbach/restful-api-best-practices-and-common-pitfalls-7a83ba3763b5)

[OWASP API Security Project](https://www.owasp.org/index.php/OWASP_API_Security_Project)

[WebSocket API Standards](https://www.w3.org/TR/2011/WD-websockets-20110929/)

[Fuzzapi](https://github.com/lalithr95/Fuzzapi/)
* Fuzzapi is rails application which uses API_Fuzzer and provide UI solution for gem.

[White House Web API Standards](https://github.com/WhiteHouse/api-standards)
* This document provides guidelines and examples for White House Web APIs, encouraging consistency, maintainability, and best practices across applications. White House APIs aim to balance a truly RESTful API interface with a positive developer experience (DX).

[Automating API Penetration Testing using fuzzapi - AppSecUSA 2016](https://www.youtube.com/watch?v=43G_nSTdxLk)


### Web Sockets

[The WebSocket Protocol Standard - IETF](https://tools.ietf.org/html/rfc6455)

[WebSocket Protocol - RFC Draft 17](https://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17)




### <a name="misc">Miscellaneous</a>
[unindexed](https://github.com/mroth/unindexed/blob/master/README.md)
* The site is constantly searching for itself in Google, over and over and over, 24 hours a day. The instant it finds itself in Google search results, the site will instantaneously and irrevocably securely delete itself. Visitors can contribute to the public content of the site, these contributions will also be destroyed when the site deletes itself.

[COWL: A Confinement System for the Web](http://cowl.ws/)
* Robust JavaScript confinement system for modern web browsers. COWL introduces label-based mandatory access control to browsing contexts (pages, iframes, etc.) in a way that is fully backward-compatible with legacy web content. 
* [Paper](http://www.scs.stanford.edu/~deian/pubs/stefan:2014:protecting.pdf)

[HardenFlash](https://github.com/HaifeiLi/HardenFlash)
* Patching Flash binary to stop Flash exploits and zero-days














### <a name="burp">Burp Stuff/Plugins</a>

[100 OWASP Top 10 Hacking Web Applications with Burp Suite Chad Furman](https://www.youtube.com/watch?v=2p6twRRXK_o)

[AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)
* AuthMatrix is a Burp Suite extension that provides a simple way to test authorization in web applications and web services. 


[Burp Pro : Real-life tips and tricks](https://hackinparis.com/talk-nicolazs-gregoire)

[Behind enemy lines: Bug hunting with Burp Infiltrator](http://blog.portswigger.net/2017/06/behind-enemy-lines-bug-hunting-with.html)

[BurpSmartBuster](https://github.com/pathetiq/BurpSmartBuster)
* A Burp Suite content discovery plugin that add the smart into the Buster!

[HUNT Burp Suite Extension](https://github.com/bugcrowdlabs/HUNT)
* HUNT Logo  HUNT is a Burp Suite extension to: 1. Identify common parameters vulnerable to certain vulnerability classes. 2. Organize testing methodologies inside of Burp Suite.

[BurpSmartBuster](https://github.com/pathetiq/BurpSmartBuster)
* A Burp Suite content discovery plugin that add the smart into the Buster!

[collaborator-everywhere](https://github.com/PortSwigger/collaborator-everywhere)
* A Burp Suite Pro extension which augments your proxy traffic by injecting non-invasive headers designed to reveal backend systems by causing pingbacks to Burp Collaborator

[backslash-powered-scanner](https://github.com/PortSwigger/backslash-powered-scanner)
* This extension complements Burp's active scanner by using a novel approach capable of finding and confirming both known and unknown classes of server-side injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering.

[distribute-damage](https://github.com/PortSwigger/distribute-damage)
* Designed to make Burp evenly distribute load across multiple scanner targets, this extension introduces a per-host throttle, and a context menu to trigger scans from. It may also come in useful for avoiding detection.