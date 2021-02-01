# The Web, Web Applications & Browsers

## Table of Contents
- [General](#general)
- [Standards](#standards)
  - [Content Security Policy (CSP)](#csp)
  - [Cross-Origin Resource Sharing (CORS)](#cors)
  - [Cookies](#cookies)
  - [Document Object Model (DOM)](#dom)
  - [Hyper Text Markup Language HTML](#html)
  - [Fetch](#fetch)
  - [Hyper Text Transport Protocol (HTTP)](#http)
  - [MIME Sniffing](#msniff)
  - [OAUTH](#oauth)
  - [Same-Origin Policy](#sop)
  - [Security Assertion Markup Language (SAML)](#saml)
  - [Service Workers](#serviceworkers)
  - [Subresource Integrity](#sri)
  - [Secure Sockets Layer/Transport Layer Security (SSL/TLS)](#ssltls)
  - [Streams](#streams)
  - [Uniform Resource Identifier/Locator (URIs/URLs)](#uri)
  - [Web Authentication](#webauthn)
  - [Web Bluetooth](#webbt)
  - [Web Hooks](#webhooks)
  - [Web NFC](#webnfc)
  - [WebRTC](#webrtc)
  - [WebSockets](#websockets)
  - [WebUSB](#webusb)
- [Tactics & Techniques](#tt)
    - [Attacking](#ttatk)
    - [Securing](#ttsec)
    - [Guides & Methodologies](#ttgm)
    - [Testing Writeups](#ttw)
    - [Payloads](#ttpay)
    - [Tactics](#ttt)
    - [General Reconnaissance Techniques](#ttgrt)
      - [General Articles/Methodology Writeups](#gamw)
      - [Tools that didn't fit elsewhere](#ttdfe)
      - [(Almost)Fully Automating Recon](#ttafar)
      - [Attack Surface Reconaissance](#ttasr)
      - [Browser Automation](#ttbo)
      - [DNS](#ttdns)
      - [Enpdoint Discovery](#tted)
      - [Forced Browsing](#ttfb)
      - [HTTP Enumeration](#tthe)
      - [HTTP Fingerprinting](#tthf)
      - [JS-based scanning](#ttjs)
      - [(Sub)Domain Reconnaissance](#sdr)
      - [Technology Identification](#tttid)
      - [Web Scraping](#ttscraping)
      - [User Enumeration](#ttue)
      - [Virtual Hosts](#ttrvhost)
      - [Visual Reconnaissance](#ttvr)
      - [Wordlists](#ttwl)
    - [Vulnerability Scanner](#ttvs)
- [Miscellaneous](#misc)
  - [Burp Stuff/Plugins](#burp)
  - [Cloudflare](#cloudflare)
  - [Bug Bounty Writeups](#bugbounty)
  - [Random](#random)


| [Technologies](#technologies) | [Attacks](#attacks) |
|---  |---  |
| [API Stuff](#api) | [Abuse of Functionality](#abuse) |
| [Web Browsers](#webbrowser) | [Brute Force/Fuzzing](#brute) |
| [Browser Security](#browsersec) | [Attacking Continous Integration Systems](#ci) |
| [HTTPS Certificates & Certificate Transparency](#ct) | [CSV Injection](#csv) |
| [Content Management Systems](#cms) | [Clickjacking](#click) |
| [Continous Integration/Delivery/Build Systems](#cii) | [Cross Protocol Scripting/Request Attack](#cpr) |
| [ColdFusion](#coldfusion) | [Cross Site Content Hijacking](#xshm) |
| [Electron](#electron) | [Cross Site History Manipulation](#xshm) |
| [Flash/SWF](#swf) | [Cross Site Request Forgery (CSRF)](#csrf) |
| [GhostScript](#ghosts) | [Cascading-StyleSheets-related Attacks](#cssi) |
| [GraphQL](#graphql) | [Cross Site WebSocket Hijacking](#cswsh) |
| [Imagemagick](#magick) | [Data Structure Attacks](#dsa) |
| [JavaScript](#javascript) | [Edge Side Include Injection](#esii) |
| [Java Server Faces (JSF)](#jsf) | [Embedded Malicious Code](#emc) |
| [Java Server Pages (JSP)](#jsp) | [Exploitation of Authentication](#eoa) |
| [JSON Web Tokens](#jwt) | [IDN Homograph & Homograph Attacks](#idn) |
| [MIME Sniffing](#mime) | [Insecure Direct Object Reference](#idor) |
| [NodeJS](#nodejs) | [Execution After(/Open) Redirect (EAR)](#ear) |
| [Platform Agnostic Security Token (PASETO)](#paseto) | [File Upload Testing](#file) |
| [PHP](#php) | [HTML Smuggling](#hsmug) |
| [REST/SOAP/Web Services (WSDL)](#rest) | [HTTP Request Smuggling](#httprs) |
| [Ruby/Ruby on Rails](#ruby) | [Image-based Exploitation AKA Exploiting Polyglot features of File standards](#ibe) |
| [Web Assembly](#webasm) | [Injection Based Attacks](#ija) |
| [Secure Sockets Layer / Transport Layer Security](#ssltls) | [OS Command Injection](#osci) |
| [Single Sign-On (SSO)](#sso) | [JNDI Attack Class](#jndi) |
| [Web Application Firewalls (WAFs)](#waf) | [Path Confusion Attacks](#pca) |
| [JS Frameworks](#webframeworks) | [LFI & RFI](#lrfi) |
| [Web Proxies](#webproxy) | [(No)SQL Injection](#sqli) |
| [Web Servers](#webservers) | [Path Traversal Attacks](#pta) |
| [Web Storage](#webstorage) | [Prototype Pollution Attack](#ppa) |
|  | [Reflected File Download](#rfd) |
|  | [Relative Path Overwrite](#rpo) |
|  | [(De-)Serialization Attacks](#serialization) |
|  | [Server Side Request Forgery (SSRF)](#ssrf) |
|  | [Server Side Include](#ssi) |
|  | [Client/Server Side Template Injection](#ssti) |
|  | [Subdomain Hijack/Takeover](#subtake) |
|  | [Website Imaging(Taking Snapshots of WebPages)](#simg) |
|  | [(Bit)/Typo-squatting](#typosquatting) |
|  | [Web Shells](#shells) |
|  | [XSS](#xss) |
|  | [Cross-Site History Manipulation](#xshm) |
|  | [Tabnabbing Attacks](#tabnab) |
|  | [Timing / Race Condition Attacks](#timing) |
|  | [TLS Redirection (and Virtual Host Confusion)](#tls-redirect) |
|  | [TypoSquatting](#typosquat) |
|  | [Web Cache Deception Attack](#webcache) |
|  | [Web Cache Poisoining Attack](#cachepoison) |
|  | [XML](#xml) |


----------------

* **To Do**
	* Identity Providers/SSO Stuff
	* Web Frameworks

----------------
## General <a name="general"></a>

* **101**
	* **Things to Know**
		* OWASP ASVS
		* [OWASP Top Ten Project](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)
			* The OWASP Top 10 is a powerful awareness document for web application security. It represents a broad consensus about the most critical security risks to web applications. Project members include a variety of security experts from around the world who have shared their expertise to produce this list.
		* [The Website Obesity Crisis](http://idlewords.com/talks/website_obesity.htm)
		* [XSS, CSRF, CSP, JWT, WTF? IDK `¯\_(ツ)_/¯` - Dominik Kundel(JSConf Iceland2018)](https://www.youtube.com/watch?v=c6mqdsfWdmE)
			* `Robert'); DROP TABLE Students;--` The little Bobby Tables is embodying the classical fear of SQL injections when building web applications. However, SQL injections are just one aspect of things we need to worry about when building web applications. With the recent popularity of Angular, React and other Single Page Application frameworks we got more logic executing on the front-end create new problems and make you forget about others. In this talk you will learn about XSS, CSRF, CORS, JWT, HTTPS, SPAs, REST APIs and other weird abbreviations, how to protect yourself and your users from the new generation of Bobby Tables.
	* **Articles**
		* [The Basics of Web Application Security - Cade Cairns, Daniel Somerfield(2017)](https://martinfowler.com/articles/web-security-basics.html)
		* [Don't Cross Me! Same Origin Policy and all the "cross" vulns: XSS, CSRF, and CORS - ropnop(2020)](https://speakerdeck.com/ropnop/dont-cross-me-same-origin-policy-and-all-the-cross-vulns-xss-csrf-and-cors?slide=58)
* **Browsers**
	* [Browser-2020](https://github.com/luruke/browser-2020)
		* Things you can do with a browser in 2020
		* It's like, did no one read 'The Tangled Web: A Guide to Securing Modern Web Applications'? Or did they, and their take away was, 'Man, what a bunch of great ideas! Blinking text with no user control? Woah. I'm so on this.'.
		* My point is that it is 2020, and there is no equivalent to NoScript or UBlock Origin in any major browser. Despite this, I can have picture in picture video chats, while also connecting by bluetooth and USB, devices to the browser and having each tab color coded, along with the browser knowing my power level of my device, all according to standards.
		* Google released a paper the day after I made this comment. I stand by my comment.
	* [Oh, the Places You’ll Go! Finding Our Way Back from the Web Platform’sIll-conceived Jaunts - Artur Janc, Mike West(2020)](https://secweb.work/papers/janc2020places.pdf)
		* In this paper, we start from a scattered list of concrete grievances about the web platform based on informal discussions among browser and web security engineers. After reviewing the details of these issues, we work towards a model of the root causes of the problems, categorizing them based on the type of risk they introduce to the platform. We then identify possible solutions for each class of issues, dividing them by the most effective approach to address it. In the end, we arrive at a general blueprint for backing out of these dead ends. We propose a three-pronged approach which includes changing web browser defaults, creating a slew of features for web authors to opt out of dangerous behaviors, and adding new security primitives. We then show how this approach can be practically applied to address each of the individual problems, providing a conceptual framework for solving unsafe legacy web platform behaviors.
	* [How Browsers Work: Behind the scenes of modern web browsers - Tali Garsiel, Paul Irish(2011)](https://www.html5rocks.com/en/tutorials/internals/howbrowserswork/)
* **Other**
	* Cheat Sheets: [Cheat Sheets](Cheats.md)
	* Purposely Vulnerable Web Apps: [Building a Lab](Building_A_Lab.md)

----------------
## Standards <a name="standards"></a>

### Content Security Policy (CSP) <a name="csp"></a>
* **101**
	* [Intro to Content Security Policy](http://www.html5rocks.com/en/tutorials/security/content-security-policy/)
	* [Content Security Policy Level 3 - W3c Oct2018](https://www.w3.org/TR/CSP3/#intro)
	* [Content Security Policy - Wikipedia](https://en.wikipedia.org/wiki/Content_Security_Policy)
	* [Content Security Policy - Google Web Fundamentals](https://developers.google.com/web/fundamentals/security/csp/)
* **Articles/Papers/Talks/Writeups**
	* [GitHub's post-CSP journey - githubengineering](https://githubengineering.com/githubs-post-csp-journey/)
	* [Github's CSP Journey - githubengineering](https://githubengineering.com/githubs-csp-journey/)
	* [ CVE-2018-5175: Universal CSP strict-dynamic bypass in Firefox - Masato Kinugawa](https://mksben.l0.cm/2018/05/cve-2018-5175-firefox-csp-strict-dynamic-bypass.html)
	* [Content Security Policy Level 3 - w3c Feb2019](https://w3c.github.io/webappsec-csp/)
	* [CSP and SVG - c0nrad](https://c0nradsc0rner.com/2016/08/30/csp-and-svg/)
		* "The tl;dr is make sure object-src is ‘none’ if you’re not using it. Using this “attack” you can reflect SVGs to get execution even in a CSP controlled environment. This is just another recipe to add to your books for bypassing CSP (insecure directives, JSONP, base offset, encoding)."
	* [Content Security Policy (CSP) Bypasses - ghostlulz](http://ghostlulz.com/content-security-policy-csp-bypasses/)
	* [How To Bypass CSP By Hiding JavaScript In A PNG Image - @Menin_theMiddle](https://www.secjuice.com/hiding-javascript-in-png-csp-bypass/)
		* "TL;DR - Using HTML Canvas you can hide any JavaScript code (or an entire library) into a PNG image by converting each source code character into a pixel. The image can then be uploaded onto a trusted website like Twitter or Google (usually whitelisted by CSP) and then loaded as a remote image in a HTML document. Finally, by using the canvas getImageData method, it's possible to extract the "hidden JavaScript" from the image and execute it. Sometimes this could lead to a Content-Security-Policy bypass making an attacker able to include an entire and external JavaScript library."
	* [Content-Security-Policy (CSP) Bypass Techniques - Bhavesh Thakur(2020)](https://medium.com/@bhaveshthakur2015/content-security-policy-csp-bypass-techniques-e3fa475bfe5d)

----------------
### Cross-Origin Resource Sharing (CORS) <a name="cors"></a>
* **101**
	* [Cross-Origin Resource Sharing (CORS) - Mozilla Dev Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
	* [CORS Findings: Another Way to Comprehend - Ryan Leese](https://www.trustedsec.com/2018/04/cors-findings/)
	* [Same Origin Policy - dev.mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
	* [Same Origin Policy - W3C](https://www.w3.org/Security/wiki/Same_Origin_Policy)
	* [Cross-Origin Resource Sharing (CORS) - dev.mozilla](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
	* [Cross-Origin Resource Sharing - w3.org](https://www.w3.org/TR/cors/)
		* This document defines a mechanism to enable client-side cross-origin requests. Specifications that enable an API to make cross-origin requests to resources can use the algorithms defined by this specification. If such an API is used on `http://example.org` resources, a resource on `http://hello-world.example` can opt in using the mechanism described by this specification (e.g., specifying `Access-Control-Allow-Origin: http://example.org` as response header), which would allow that resource to be fetched cross-origin from `http://example.org`.
* **Articles/Blogposts/Writeups**
	* [JSON API's Are Automatically Protected Against CSRF, And Google Almost Took It Away.](https://github.com/dxa4481/CORS)
	* [Exploiting Misconfigured CORS (Cross Origin Resource Sharing) - Geekboy](https://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/)
	* [Do You Really Know CORS? - Grzegorz Mirek](https://dzone.com/articles/do-you-really-know-cors)
	* [3 Ways to Exploit Misconfigured Cross-Origin Resource Sharing (CORS) - Pavan Kumar J(2018)](https://www.we45.com/blog/3-ways-to-exploit-misconfigured-cross-origin-resource-sharing-cors)
	* [Three C-Words of Web App Security: Part 1 – CORS - Mic Whitehorn-Gillam(2018)](https://blog.secureideas.com/2018/07/three-c-words-of-web-app-security-part-1-cors.html)
	* [Same-Origin Policy: From birth until today - Alex Nikolova(2019)](https://research.aurainfosec.io/same-origin-policy/)
		* "In this blog post I will talk about Cross-Origin Resource Sharing (CORS) between sites on different domains, and how the web browser’s Same Origin Policy is meant to facilitate CORS in a safe way. I will present data on cross-origin behaviour of various versions of four major browsers, dating back to 2004. I will also talk about recent security bugs (CVE-2018-18511, CVE-2019-5814 and CVE-2019-9797) I discovered in the latest versions of Firefox, Chrome and Opera which allows stealing sensitive images via Cross-Site Request Forgery (CSRF)."
	* [Cross-Origin Resource Sharing (CORS) - Ghostlulz](http://ghostlulz.com/cross-origin-resource-sharing-cors/)
	* [Arbitrary Reflected Origin - Evan J(2016)](https://ejj.io/misconfigured-cors/)
	* [Cross-Origin Read Blocking (CORB) - Google](https://chromium.googlesource.com/chromium/src/+/master/services/network/cross_origin_read_blocking_explainer.md)
		* This document outlines Cross-Origin Read Blocking (CORB), an algorithm by which dubious cross-origin resource loads may be identified and blocked by web browsers before they reach the web page. CORB reduces the risk of leaking sensitive data by keeping it further from cross-origin web pages. In most browsers, it keeps such data out of untrusted script execution contexts. In browsers with Site Isolation, it can keep such data out of untrusted renderer processes entirely, helping even against side channel attacks.
* **Presentations/Talks/Videos**
	* [Exploiting CORS Misconfigurations For Bitcoins And Bounties by James Kettle(AppSecEU 2017)](https://www.youtube.com/watch?v=wgkj4ZgxI4c)
		* Cross-Origin Resource Sharing (CORS) is a mechanism for relaxing the Same Origin Policy to enable communication between websites via browsers. It's already widely understood that certain CORS configurations are dangerous. In this presentation, I'll skim over the old knowledge then coax out and share with you an array of under-appreciated but dangerous subtleties and implications buried in the CORS specification. I'll illustrate each of these with recent attacks on real websites, showing how I could have used them to steal bitcoins from two different exchanges, partially bypass Google's use of HTTPS, and requisition API keys from numerous others. I'll also show how CORS blunders can provide an invaluable link in crafting exploit chains to pivot across protocols, exploit the unexploitable via server and client-side cache poisoning, and even escalate certain open redirects into vulnerabilities that are actually notable.
		* [Blogpost](http://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html)
	* [To CORS! The cause of, and solution to, your SPA problems! - Tim Tomes, Kevin Cody](https://www.irongeek.com/i.php?page=videos/derbycon9/1-06-to-cors-the-cause-of-and-solution-to-your-spa-problems-tim-lanmaster53-tomes-kevin-cody)
		* Cross-Origin Resource Sharing (CORS) is a complex and commonly misunderstood concept that is often implemented wrong for the right reasons. In this talk we will explain the Same-Origin Policy (SOP) and CORS in an easy to understand way. We will then discuss poor implementations of CORS and the resulting issues. We'll continue by releasing research done on a number of development frameworks exposing poorly designed CORS libraries that default to the most dangerous behavior. We'll then demonstrate why all of this matters by conducting a distributed attack against the most common CORS configuration using audience participation and a new tool. Finally, we'll discuss the safest ways to implement CORS. The custom tools used during the talk will be released along with the presentation.
	* [Of CORS it's Exploitable! What's Possible with Cross-Origin Resource Sharing? - Rebecca Deck(CircleCityCon2019)](https://www.irongeek.com/i.php?page=videos/circlecitycon2019/track-1-05-of-cors-its-exploitable-whats-possible-with-cross-origin-resource-sharing-rebecca-deck)
		* Cross-origin resource sharing (CORS) is extremely common on modern web apps, but scanning tools are terrible at analyzing CORS policy. If testers really understand CORS policy, a damaging exploit is often not far away. Is it possible to force a user to do something significant? Does using a GUID offer any protection? Does the authentication mechanism really protect against cross-origin attacks? Is it really risky to allow all origins? Do pre-flight requests always help? CORS requests get tricky very quickly and scanning tools do not have a good understanding of the intricacies that surface during actual application testing. A quick and dirty JavaScript exploit will put the issue to rest and eliminate hours of theoretical debate. This presentation covers how CORS works and how to find misconfigurations. Dozens of actual applications are distilled into examples demonstrate CORS protections and JavaScript code to bypass them. A basic knowledge of CORS and JavaScript will be helpful to understand the exploit code, but no special background is necessary to grasp the basics of CORS configuration.
* **Papers**
* **Tools**
	* [CORStest](https://github.com/RUB-NDS/CORStest/blob/master/README.md)
		* A simple CORS misconfiguration scanner
	* [CORS Exploitation Framework(CEF)](https://github.com/lanmaster53/cef)
		* A proof-of-concept tool for conducting distributed exploitation of permissive CORS configurations.
	* [Corsy](https://github.com/s0md3v/Corsy)
		* Corsy is a lightweight program that scans for all known misconfigurations in CORS implementations.
	* [CorsMe](https://github.com/Shivangx01b/CorsMe)
		* A cors misconfiguration scanner tool based on golang with speed and precision in mind!

----------------
### Cookies <a name="cookies"></a>
* **101**
	* [HTTP cookie - Wikipedia](https://en.wikipedia.org/wiki/HTTP_cookie)
	* [Using HTTP cookies - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
	* [All About Cookies.org](https://www.allaboutcookies.org/cookies/)
* **Articles/Blogposts/Writeups**
	* [Pass the Cookie and Pivot to the Clouds - wunderwuzzi](https://embracethered.com/blog/posts/passthecookie/)
* **Talks/Presentations/Videos**
	* [Baking Your Anomalous Cookies - Jim Allee(NolaCon2019)](https://www.irongeek.com/i.php?page=videos/nolacon2019/nolacon-2019-d-09-baking-your-anomalous-cookies-jim-allee)
		* I hacked Fortnite! Actually it was a vulnerable cookie found on several domains owned by Epic Games that allowed me to hijack traffic of users of their websites, steal session tokens and of course, BeEF hook em'. I will describe my journey from creating a custom cookie fuzzing tool (Anomalous Cookie) to help identify vulnerable cookies, to creating a framework for 'Cookie Baking'. Cookie Baking is the technique of creating or modifying a cookie in a users' local Cookie Jar (this includes stuffing with malicious payloads, affiliate tags, fuzz-strings and more). I will also provide insight into the Bug Bounty process, how Google responded to my request for them to protect local cookies at rest, and how I created WHID-Injected Cookies! ;)

----------------
### Document Object Model (DOM) <a name="dom"></a>
* **101**
	* [DOM - Standard(spec.whatwg)](https://dom.spec.whatwg.org/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
* **Talks & Presentations**
	* [Securing the DOM from the Bottom Up - Mike Samuel(BSides Cleveland2019)](https://www.irongeek.com/i.php?page=videos/bsidescleveland2019/bsides-cleveland-c-01-securing-the-dom-from-the-bottom-up-mike-samuel)
		* 18 years have passed since Cross-Site Scripting (XSS) became the single most common security problem in web applications. Since then, numerous efforts have been proposed to detect, fix or mitigate it, but these piecemeal efforts have not combined to make it easy to produce XSS-free code. This talk explains how Google's security team has achieved a high-level of safety against XSS and related problems by integrating tools to make it easier for developers to produce secure software than vulnerable, and to bound the portion of a codebase that could contribute to a vulnerability. We will show how this works in practice and end with advice on how to achieve the same results on widely-used, open-source stacks and new browser mechanisms that will make it much easier to achieve high-levels of security with good developer experience.

### Hyper Text Markup Language HTML <a name="html"></a>
* **101**
	* [HTML - spec.whatwg.org](https://html.spec.whatwg.org/multipage/)
	* [HTML 5 Standards](http://w3c.github.io/html/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [The HTML Handbook - Flavio Copes](https://www.freecodecamp.org/news/the-html-handbook/)
	* [HTML Punctuation Symbols, Punctuation Entities and ASCII Character Code Reference - toptotal.com](https://www.toptal.com/designers/htmlarrows/punctuation/)

---------------
### Fetch <a name="fetch"></a>
* **101**
	* [Fetch Living Standard — 2019/7/16 - whatwg](https://fetch.spec.whatwg.org/#concept-fetch)
		* The Fetch standard defines requests, responses, and the process that binds them: fetching.

---------------
### Hyper Text Transport Protocol (HTTP) <a name="http"></a>
* **101**
	* [RFC 2068: Hypertext Transfer Protocol -- HTTP/1.1](https://www.ietf.org/rfc/rfc2068.txt)
	* [RFC 2616: Hypertext Transfer Protocol -- HTTP/1.1](https://www.ietf.org/rfc/rfc2616.txt)
	* [http-decision-diagram](https://github.com/for-GET/http-decision-diagram)
		* An activity diagram to describe the resolution of HTTP response status codes, given various headers, implemented via semantical callbacks.
	* [Basics of HTTP - MDN WebDocs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP)
	* [An Overview of HTTP - MDN WebDocs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview)
	* [Robots.txt](http://www.robotstxt.org/)
* **Caching**
	* [RFC 7234: Hypertext Transfer Protocol (HTTP/1.1): Caching](https://httpwg.org/specs/rfc7234.html)
		* The Hypertext Transfer Protocol (HTTP) is a stateless application-level protocol for distributed, collaborative, hypertext information systems. This document defines HTTP caches and the associated header fields that control cache behavior or indicate cacheable response messages.
* **HTTP Headers**
	* **101**
		* [HTTP headers - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
		* [List of HTTP header fields - Wikipedia](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields)
	* **Security Headers**
		* [HTTP Strict Transport Security - cio.gov](https://https.cio.gov/hsts/)
		* [IETF RFC 7034: HTTP Header Field X-Frame-Options](https://tools.ietf.org/html/rfc7034)
		* [OWASP Secure Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)
		* [Guidelines for Setting Security Headers - Isaac Dawson](https://www.veracode.com/blog/2014/03/guidelines-for-setting-security-headers)
		* [HTTP Security Headers - A Complete Guide - Charlie Belmer(2019)](https://nullsweep.com/http-security-headers-a-complete-guide/)
	* **User-Agents**
		* **101**
			* [User-Agent - Wikipedia](https://en.wikipedia.org/wiki/User_agent)
			* [User-Agent - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent)
		* **Tools**
			* [Security Analyser User Agents](https://developers.whatismybrowser.com/useragents/explore/software_type_specific/security-analyser/)
				* We've got 141 Security Analyser User Agents in our database. This is a listing of them.
* **HTTP Methods**
	* [Detecting and Exploiting the HTTP PUT Method](http://www.smeegesec.com/2014/10/detecting-and-exploiting-http-put-method.html)
* **HTTP Objects**
	* [Object MetaInformation](https://www.w3.org/Protocols/HTTP/Object_Headers.html#public)
* **HTTP Parameters**
* **HTTP Pipelining**
	* **101**
		* [HTTP pipelining - Wikipedia](https://en.wikipedia.org/wiki/HTTP_pipelining)
	* **Articles/Blogposts/Writeups**
		* [Using HTTP Pipelining to hide requests - digininja](https://digi.ninja/blog/pipelining.php)
* **HTTP Signatures**
	* [Ensuring Message Integrity with HTTP Signatures - Sathya Bandara(2019)](https://medium.com/@technospace/ensuring-message-integrity-with-http-signatures-86f121ac9823)
	* [Signing HTTP Messages - webconcepts.info](http://webconcepts.info/specs/IETF/I-D/cavage-http-signatures.html)
	* [Digitally Signed HTTP(S) Requests - Adobe Audience Manager](https://docs.adobe.com/content/help/en/audience-manager/user-guide/implementation-integration-guides/receiving-audience-data/real-time-outbound-transfers/digitally-signed-http-requests.html)
* **HTTP Verbs**
	* [RFC 7231: Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content](https://tools.ietf.org/html/rfc7231)
	* [Exploiting HTTP Verbs - Osanda Malith Jayathissa(2015)](https://osandamalith.com/2015/06/14/exploiting-http-verbs/)
* **Syntax & Routing**
	* [RFC 7230: Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing](https://httpwg.org/specs/rfc7230.html)
		* The Hypertext Transfer Protocol (HTTP) is a stateless application-level protocol for distributed, collaborative, hypertext information systems. This document provides an overview of HTTP architecture and its associated terminology, defines the "http" and "https" Uniform Resource Identifier (URI) schemes, defines the HTTP/1.1 message syntax and parsing requirements, and describes related security concerns for implementations.
* **HTTP2**
	* **101**
		* [Introduction to HTTP/2 -  Ilya Grigorik, Surma(Google)](https://developers.google.com/web/fundamentals/performance/http2)
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
		* [HTTP/2 & QUIC - Teaching Good Protocols To Do Bad Things - Catherine (Kate) Pierce, Vyrus(PHV-Defcon2016)](https://www.youtube.com/watch?v=zoHjVrRUFQ4)
			* The meteoric rise of SPDY, HTTP/2, and QUIC has gone largely unremarked upon by most of the security field. QUIC is an application-layer UDP-based protocol that multiplexes connections between endpoints at the application level, rather than the kernel level. HTTP/2 (H2) is a successor to SPDY, and multiplexes different HTTP streams within a single connection. More than 10% of the top 1 Million websites are already using some of these technologies, including much of the 10 highest traffic sites. Whether you multiplex out across connections with QUIC, or multiplex into fewer connections with HTTP/2, the world has changed. We have a strong sensation of Déjà vu with this work and our 2014 Black Hat USA MPTCP research. We find ourselves discussing a similar situation in new protocols with technology stacks evolving faster than ever before, and Network Security is largely unaware of the peril already upon it. This talk briefly introduces QUIC and HTTP/2, covers multiplexing attacks beyond MPTCP, discusses how you can use these techniques over QUIC and within HTTP/2, and discusses how to make sense of and defend against H2/QUIC traffic on your network. We will also demonstrate, and release, some tools with these techniques incorporated.
* **HTTP Parameter Pollution**
	* **101**
		* [HTTP Parameter Pollution - Imperva](https://www.imperva.com/learn/application-security/http-parameter-pollution/)
			* HTTP Parameter Pollution (HPP) is a Web attack evasion technique that allows an attacker to craft a HTTP request in order to manipulate or retrieve hidden information. This evasion technique is based on splitting an attack vector between multiple instances of a parameter with the same name. Since none of the relevant HTTP RFCs define the semantics of HTTP parameter manipulation, each web application delivery platform may deal with it differently. In particular, some environments process such requests by concatenating the values taken from all instances of a parameter name within the request. This behavior is abused by the attacker in order to bypass pattern-based security mechanisms.
	* **Articles/Blogposts/Writeups**	
		* [Client-side HTTP parameter pollution (reflected) - PortSwigger](https://portswigger.net/kb/issues/00501400_client-side-http-parameter-pollution-reflected)
		* [Client-side HTTP parameter pollution (stored) - PortSwigger](https://portswigger.net/kb/issues/00501401_client-side-http-parameter-pollution-stored)
		* [HTTP Parameter Pollution (English) - onehackman(2019)](https://medium.com/@onehackman/http-parameter-pollution-english-90fd5eec7a3b)
	* **Talks/Presentations/Videos**
		* [HTTP Parameter Pollution - Luca Carettoni, Stefano diPaola(OWASP EU09 Poland)](https://owasp.org/www-pdf-archive/AppsecEU09_CarettoniDiPaola_v0.8.pdf)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [HTTP Made Really Easy: A Practical Guide to Writing Clients and Servers - James Marshall(2012)](https://www.jmarshall.com/easy/http/)
	* [HTTP Evasion](http://noxxi.de/research/http-evader-explained-8-borderline-robustness.html)	
* **Tools**
	* [curl](https://curl.haxx.se/)
	* [httpie](https://httpie.org/)
		* user-friendly command-line HTTP client for the API era. It comes with JSON support, syntax highlighting, persistent sessions, wget-like downloads, plugins, and more.
	* [wuzz](https://github.com/asciimoo/wuzz)
		* Interactive cli tool for HTTP inspection.

---------------
### MIME Sniffing <a name="msniff"></a>
* **101**
	* [MIME Sniffing - whatwg.org](https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern)
	* [Media Type Sniffing | draft-ietf-websec-mime-sniff-03](https://tools.ietf.org/html/draft-ietf-websec-mime-sniff-03)
		* Many web servers supply incorrect Content-Type header fields with their HTTP responses. In order to be compatible with these servers, user agents consider the content of HTTP responses as well as the Content-Type header fields when determining the effective media type of the response. This document describes an algorithm for determining the effective media type of HTTP responses that balances security and compatibility considerations
* **Articles/Blogposts/Presentations/Talks/Writeups**

---------------
### OAUTH <a name="oauth"></a>
* **101**
	* [OAuth 2.0 Security Best Current Practice draft-ietf-oauth-security-topics-05 - Expires Sept19,2018](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-05)
		* This document describes best current security practices for OAuth 2.0.. It updates and extends the OAuth 2.0 Security Threat Model to incorporate practical experiences gathered since OAuth 2.0 was published and cover new threats relevant due to the broader application of OAuth 2.0.
	* [OAuth 2.0 Dynamic Client Registration Protocol - rfc7591](https://tools.ietf.org/html/rfc7591)
		* This specification defines mechanisms for dynamically registering OAuth 2.0 clients with authorization servers. Registration requests send a set of desired client metadata values to the authorization server. The resulting registration responses return a client identifier to use at the authorization server and the client metadata values registered for the client. The client can then use this registration information to communicate with the authorization server using the OAuth 2.0 protocol. This specification also defines a set of common client metadata fields and values for clients to use during registration.
	* [The OAuth 2.0 Authorization Framework: JWT Secured Authorization Request - ietf.org](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-15)
		* The authorization request in OAuth 2.0 described in RFC 6749 utilizes query parameter serialization, which means that Authorization Request parameters are encoded in the URI of the request and sent through user agents such as web browsers. While it is easy to implement, it means that (a) the communication through the user agents are not integrity protected and thus the parameters can be tainted, and (b) the source of the communication is not authenticated. Because of these weaknesses, several attacks to the protocol have now been put forward. This document introduces the ability to send request parameters in a JSON Web Token (JWT) instead, which allows the request to be signed with JSON Web Signature (JWS) and encrypted with JSON Web Encryption (JWE) so that the integrity, source authentication and confidentiality property of the Authorization Request is attained. The request can be sent by value or by reference.
	* [OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens - ietf](https://tools.ietf.org/html/draft-ietf-oauth-mtls-07)
		* This document describes Transport Layer Security (TLS) mutual authentication using X.509 certificates as a mechanism for OAuth client authentication to the authorization sever as well as for certificate bound sender constrained access tokens as a method for a protected resource to ensure that an access token presented to it by a given client was issued to that client by the authorization server.
	* [RFC 6819: OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819)
	* [OAuth 2.0 Security Best Current Practice draft-ietf-oauth-security-topics-15](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-15)
* **Articles/Blogposts/Writeups**
	* [Dancing with OAuth: Understanding how Authorization Works - Ashish Mathur](https://medium.com/@imashishmathur/0auth-a142656859c6)
	* [Shining a Light on OAuth Abuse with PwnAuth - Douglas Bienstock](https://www.fireeye.com/blog/threat-research/2018/05/shining-a-light-on-oauth-abuse-with-pwnauth.html)
	* [OAUTH – Everything you wanted to know but not really! - Elaheh Samani, Kevin Watkins](https://sector.ca/sessions/oauth-everything-you-wanted-to-know-but-not-really/)
	* [An Illustrated Guide to OAuth and OpenID Connect - David Neal](https://developer.okta.com/blog/2019/10/21/illustrated-guide-to-oauth-and-oidc)
	* [Analysis of Common Federated Identity Protocols: OpenID Connect vs OAuth 2.0 vs SAML 2.0 - hackedu.io](https://blog.hackedu.io/analysis-of-common-federated-identity-protocols/)
	* [RFC 8693 OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
	* [Introduction to OAuth 2.0 and OpenID Connect - PragmaticWebSecurity](https://courses.pragmaticwebsecurity.com/courses/introduction-to-oauth-2-0-and-openid-connect)
	* [Mastering OAuth 2.0 and OpenID Connect - PragmaticWebSecurity](https://courses.pragmaticwebsecurity.com/bundles/mastering-oauth-oidc)
	* [OAuth 2.0 : Explained - Milind Daftari(2019)](https://medium.com/@milinddaftari/oauth-2-0-explained-d001e5c98ee7)
	* [What's new in OAuth 2.1? - Dan Moore(2020)](https://fusionauth.io/blog/2020/04/15/whats-new-in-oauth-2-1/)
	* [Google Oauth2 API Explained - Pumudu Ruhunage(2020)](https://medium.com/@pumudu88/google-oauth2-api-explained-dbb84ff97079)
* **Presentations/Talks/Videos**
	* [OAuth2: Beyond The Specs - Daniele Timo Second - BSides Lisbon2018](https://www.youtube.com/watch?v=qBxI0bjtJvU&t=0s&list=PLbuNP88_wbNxPkglG6zLUhvzvxvDimuEc&index=7)
		* What if you roll out OAuth, and realize there are a bunch of small things you didn’t consider? It’s what happened to us at Pipedrive, and although it’s likely not over just yet, we’re running smoothly. It’s a good time to share what we’ve learned and save others some time. While building Pipedrive’s marketplace for third-party apps, we transitioned from API token authentication to OAuth, and it’s been an interesting learning experience. In this talk, I will explain how the protocol works, discuss differences in how OAuth is implemented on different platforms, and explain how we managed the transition from API token to OAuth. I will explain how CSRF attacks work in OAuth, how the state parameter can prevent them, how to manage synchronization between server and clients, and what you can run into when you roll out OAuth for dozens of apps.
	* [OAuth 2.0 and OpenID Connect (in plain English) - Nate Barbettini(OktaDev)](https://www.youtube.com/watch?v=996OiexHze0)
	* [Discord Hangout: Practical OAuth Attacks - Scot Berner](https://www.youtube.com/watch?v=wf8apBA6CRc)
		* During this Discord Hangout, Scot Berner (@slobtresix0) provides some background on OAuth and how attackers can use it to gain access to an organization. Scot shows how Microsoft uses OAuth with Microsoft 365 along with how it can be used for social engineering and external attacks.
	* [OAuth: When Things Go Wrong - Aaron Parecki(2019)](https://www.youtube.com/watch?v=H6MxsFMAoP8)
		* [Slides](https://speakerdeck.com/aaronpk/oauth-when-things-go-wrong)
		* Aaron Parecki discusses common security threats when building microservices using OAuth and how to protect yourself. You'll learn about high-profile API security breaches related to OAuth; common implementation patterns for mobile apps, browser-based apps, and web server apps; and the latest best practices around OAuth security being developed by the IETF OAuth working group.
* **Attacking**
	* [The most common OAuth 2.0 Hacks - Okhomiak](https://habr.com/en/post/449182/)
	* [Bypassing GitHub's OAuth flow - Teddy Katz](https://blog.teddykatz.com/2019/11/05/github-oauth-bypass.html)
	* [Practical OAuth Abuse for Offensive Operations – Part 1 - Scot Berner(2020)](https://www.trustedsec.com/blog/practical-oauth-abuse-for-offensive-operations-part-1/)
	* [An offensive guide to the Authorization Code grant - Rami McCarthy](https://research.nccgroup.com/2020/07/07/an-offensive-guide-to-the-authorization-code-grant/)
	* [Bypassing GitHub's OAuth flow - Teddy Katz](https://blog.teddykatz.com/2019/11/05/github-oauth-bypass.html)
	* [ Penetration Tester's Guide to Evaluating OAuth 2.0 — Authorization Code Grants - ](https://maxfieldchen.com/posts/2020-05-17-penetration-testers-guide-oauth-2.html)
	* [OAuth 2.0 Implementation and Security - Haboob](https://www.exploit-db.com/download/48495)
	* [The Wondeful World of OAuth: Bug Bounty Edition - A Bug’z Life(2020)](https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1)
* **Tools**
	* [OAuth 2.0 Playground - Okta](https://oauth.com/playground/)

----------------
### Same-Origin Policy <a name="sop"></a>
* **101**
	* [RFC 6454: The Web Origin Concept](https://tools.ietf.org/html/rfc6454)
		* This document defines the concept of an "origin", which is often used as the scope of authority or privilege by user agents. Typically, user agents isolate content retrieved from different origins to prevent malicious web site operators from interfering with the operation of benign web sites. In addition to outlining the principles that underlie the concept of origin, this document details how to determine the origin of a URI and how to serialize an origin into a string. It also defines an HTTP header field, named "Origin", that indicates which origins are associated with an HTTP request.
	* [Same-origin policy - Mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy)
		* The same-origin policy is a critical security mechanism that restricts how a document or script loaded from one origin can interact with a resource from another origin. It helps isolate potentially malicious documents, reducing possible attack vectors.
	* [Same-origin policy - Wikipedia](https://en.wikipedia.org/wiki/Same-origin_policy)
	* [Same-origin Policy - W3](https://www.w3.org/Security/wiki/Same_Origin_Policy)
* **Articles/Blogposts/Writeups**
	* [Whitepaper: The Definitive Guide to Same-origin Policy - Alex Baker, Ziyahan Albeniz, Emre Iyidogan](https://www.netsparker.com/whitepaper-same-origin-policy/)
	* [Same-Origin Policy: From birth until today - Alex Nikolova](https://research.aurainfosec.io/same-origin-policy/)

----------------
### Security Assertion Markup Language (SAML) <a name="saml"></a>
* **101**
	* [Security Assertion Markup Language - Wikipedia](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language)
	* [SAML 2.0 - Wikipedia](https://en.wikipedia.org/wiki/SAML_2.0)
	* [How SAML 2.0 Authentication Works - Russell Jones](https://gravitational.com/blog/how-saml-authentication-works/)
* **Articles/Blogposts/Writeups**
	* [With Great Power Comes Great Pwnage](https://www.compass-security.com/fileadmin/Datein/Research/Praesentationen/area41_2016_saml.pdf)
	* [Out of Band  XML External Entity Injection via SAML SSO - Sean Melia](https://seanmelia.files.wordpress.com/2016/01/out-of-band-xml-external-entity-injection-via-saml-redacted.pdf)
	* [Web-based Single Sign-On and the Dangers of SAML XML Parsing](https://blog.sendsafely.com/web-based-single-sign-on-and-the-dangers-of-saml-xml-parsing)
	* [Following the white Rabbit Down the SAML Code](https://medium.com/section-9-lab/following-the-white-rabbit-5e392e3f6fb9)
	* [Evilginx - Advanced Phishing with Two-factor Authentication Bypass](https://breakdev.org/evilginx-advanced-phishing-with-two-factor-authentication-bypass/)
		* [Evilginx - Update 1.0](https://breakdev.org/evilginx-1-0-update-up-your-game-in-2fa-phishing/)
		* [Evilginx - Update 1.1](https://breakdev.org/evilginx-1-1-release/)
	* [SAML All the Things! A Deep Dive into SAML SSO - Elijah A. Martin-Merrill](https://blog.rapid7.com/2019/10/03/saml-all-the-things-a-deep-dive-into-saml-sso/)
* **Golden SAML Attack**
	* [Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Apps](https://www.cyberark.com/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-cloud-apps/)
	* [shimit](https://github.com/cyberark/shimit)
		* In a golden SAML attack, attackers can gain access to an application (any application that supports SAML authentication) with any privileges they desire and be any user on the targeted application. shimit allows the user to create a signed SAMLResponse object, and use it to open a session in the Service Provider. shimit now supports AWS Console as a Service Provider, more are in the works...
* **Tools**
	* [Evilginx](https://github.com/kgretzky/evilginx)
		* Evilginx is a man-in-the-middle attack framework used for phishing credentials and session cookies of any web service. It's core runs on Nginx HTTP server, which utilizes proxy_pass and sub_filter to proxy and modify HTTP content, while intercepting traffic between client and server.
	* [SAMLReQuest Burpsuite Extention](https://insinuator.net/2016/06/samlrequest-burpsuite-extention/)

----------------
### Service Workers <a name="serviceworkers"></a>
* **101**
	* [Service Worker - w3c](https://w3c.github.io/ServiceWorker/)
		* This specification describes a method that enables applications to take advantage of persistent background processing, including hooks to enable bootstrapping of web applications while offline.  The core of this system is an event-driven Web Worker, which responds to events dispatched from documents and other sources. A system for managing installation, versions, and upgrades is provided.  The service worker is a generic entry point for event-driven background processing in the Web Platform that is extensible by other specifications.
	* [Web Worker - Wikipedia](https://en.wikipedia.org/wiki/Web_worker)
	* [Web workers vs Service workers vs Worklets - bitsofcode(2018)](https://bitsofco.de/web-workers-vs-service-workers-vs-worklets/)
* **Articles/Blogposts/Writeups**
	* [Service Workers: an Introduction - developers.google](https://developers.google.com/web/fundamentals/primers/service-workers)
	* [Service Worker API - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API)
	* [Using Service Workers - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API/Using_Service_Workers)
	* [ServiceWorker is dangerous - @steike(@2014)](https://alf.nu/ServiceWorker)
	* [Abusing the Service Workers API - Daniel Abeles(2020)](https://blogs.akamai.com/sitr/2020/01/abusing-the-service-workers-api.html)
	* [Stuff I wish I'd known sooner about service workers - Rich Harris](https://gist.github.com/Rich-Harris/fd6c3c73e6e707e312d7c5d7d0f3b2f9)
	* [Service Worker Security FAQ - Chromium.google](https://chromium.googlesource.com/chromium/src/+/master/docs/security/service-worker-security-faq.md)
* **Papers**
	* [Master of Web Puppets: Abusing Web Browsersfor Persistent and Stealthy Computation - Panagiotis Papadopoulos, Panagiotis Ilia, Michalis Polychronakis, Evangelos P. Markatos, Sotiris Ioannidis, Giorgos Vasiliadis(2019)](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_01B-2_Papadopoulos_paper.pdf)
		* In this paper, we demonstrate the powerful capabilitiesthat modern browser APIs provide to attackers by presenting MarioNet: a framework that allows a remote malicious entity toc ontrol a visitor’s browser and abuse its resources for unwantedc omputation or harmful operations, such as cryptocurrency mining, password-cracking, and DDoS. MarioNet relies solely on already available HTML5 APIs, without requiring the installation of any additional software. In contrast to previous browser-based botnets, the persistence and stealthiness characteristics of MarioNet allow the malicious computations to continue in the background of the browser even after the user closes the window or tab of the initially visited malicious website. We present the design, implementation, and evaluation of our prototype system, which is compatible with all major browsers, and discuss potential defense strategies to counter the threat of such persistent in-browser attacks. Our main goal is to raise awareness about this new class of attacks, and inform the design of future browser APIs so that they provide a more secure client-side environment for web applications.
* **Tools**
	* [Service Worker Cookbook](https://serviceworke.rs/)
		* The Service Worker Cookbook is a collection of working, practical examples of using service workers in modern web sites.

----------------
### Subresource Integrity <a name="sri"></a>
* **101**
	* [Subresource Integrity - W3.org](https://www.w3.org/TR/SRI/)
	* [Subresource Integrity - w3c.github.io](https://w3c.github.io/webappsec-subresource-integrity/)
		* This specification defines a mechanism by which user agents may verify that a fetched resource has been delivered without unexpected manipulation.
* **Articles/Blogposts/Writeups**
	* [Subresource Integrity - Mozilla](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
	* [Subresource Integrity (SRI) for Validating Web Resources Hosted on Third Party Services (CDNs) - Netsparker](https://www.netsparker.com/blog/web-security/subresource-integrity-SRI-security/)
* **Tools**
	* [SRI Hash Generator](https://www.srihash.org/)

----------------
### Secure Sockets Layer/Transport Layer Security (SSL/TLS) <a name="ssltls"></a>
* **101**
	* [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Transport Layer Security (TLS) Extensions](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
	* [Mixed content - w3c](https://w3c.github.io/webappsec-mixed-content/)
		* This specification describes how a user agent should handle fetching of content over unencrypted or unauthenticated connections in the context of an encrypted and authenticated document.
* **Attacks Against**
	* [SSL/TLS Interception Proxies and Transitive Trust](http://media.blackhat.com/bh-eu-12/Jarmoc/bh-eu-12-Jarmoc-SSL_TLS_Interception-WP.pdf)
		* Secure Sockets Layer (SSL) and its successor Transport Layer Security (TLS), have become key components of the modern Internet. The privacy, integrity, and authenticity provided by these protocols are critical to allowing sensitive communications to occur. Without these systems, e-commerce, online banking, and business-to-business exchange of information would likely be far less frequent. Threat actors have also recognized the benefits of transport security, and they are increasingly turning to SSL to hide their activities. Advanced Persistent Threat (APT ) attackers, botnets, and eve n commodity web attacks can leverage SSL encryption to evade detection. To counter these tactics, organizations are increasingly deploying security controls that intercept end-to-end encrypted channels. Web proxies, data loss prevention (DLP) systems, specialized threat detection solutions, and network intrusion prevention systems (NIPS) offer functionality to intercept, inspect, and filter encrypted traffic. Similar functionality is present in lawful intercept systems and solutions enabling the broad surveillance of encrypted communications by governments. Broadly classified as “SSL/TLS interception proxies”, these solutions act as a “man-in-the-middle", violating the end-to-end security promises of SSL. This type of interception comes at a cost. Intercepting SSL-encrypted connections sacrifices a degree of privacy and integrity for the benefit of content inspection, often at the risk of authenticity and endpoint validation. Implementers and designers of SSL interception proxies should consider these risks and understand how their systems operate in unusual circumstances

---------------
### Streams <a name="streams"></a>
* **101**
	* [Streams - Dec12 2019](https://streams.spec.whatwg.org)
		* This specification provides APIs for creating, composing, and consuming streams of data that map efficiently to low-level I/O primitives.

---------------
### Uniform Resource Identifier/Locator (URIs/URLs) <a name="uri"></a>
* **101**
	* [RFC5785: Defining Well-Known Uniform Resource Identifiers (URIs)](https://tools.ietf.org/html/rfc5785)
	* [URL Living Standard - spec.whatwg.org](https://url.spec.whatwg.org)
	* [Cool URIs don't change - W3C](https://www.w3.org/Provider/Style/URI)
	https://github.com/IAmStoxe/urlgrab
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [How to Obscure Any URL](http://www.pc-help.org/obscure.htm)
* **Data URIs**
	* **101**
		* [data URI scheme - Wikipedia](https://en.wikipedia.org/wiki/Data_URI_scheme)
			* The data URI scheme is a uniform resource identifier (URI) scheme that provides a way to include data in-line in Web pages as if they were external resources. It is a form of file literal or here document. This technique allows normally separate elements such as images and style sheets to be fetched in a single Hypertext Transfer Protocol (HTTP) request, which may be more efficient than multiple HTTP requests, and used by several browser extensions to package images as well as other multimedia contents in a single HTML file for page saving. As of 2015, data URIs are fully supported by most major browsers, and partially supported in Internet Explorer and Microsoft Edge.
		* [Data URLs - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs)
		* [Data URIs - Chris Coyier](https://css-tricks.com/data-uris/)
	* **Articles/Blogposts/Writeups**
		* [Probably Don’t Base64 SVG - Chris Coyier(2016)](https://css-tricks.com/probably-dont-base64-svg/)
	* **Tools**
		* [Image to data-URI converter - Mike Foskett](https://websemantics.uk/tools/image-to-data-uri-converter/)

---------------
### Web Authentication <a name="webauthn"></a>
* **101**
	* [Web Authentication: An API for accessing Public Key Credentials](https://www.w3.org/TR/webauthn/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Security Concerns Surrounding WebAuthn: Don't Implement ECDAA (Yet) - P.I.E. Staff](https://paragonie.com/blog/2018/08/security-concerns-surrounding-webauthn-don-t-implement-ecdaa-yet)

---------------
### Web Bluetooth <a name="webbt"></a>
* **101**
	* [Web Bluetooth](https://webbluetoothcg.github.io/web-bluetooth/)

----------------
### Web Hooks <a name="webhooks"></a>
* **101**
	* [Webhooks - pbworks](https://webhooks.pbworks.com/w/page/13385124/FrontPage)
	* [WebHook - Wikipedia](https://en.wikipedia.org/wiki/Webhook)
* **Articles/Blogposts/Writeups**
	* [Abusing Webhooks for Command and Control - Dimitry Snezhkov - BSides LV 2017](https://www.youtube.com/watch?v=TmLoTrJuung)
		* [octohook](https://github.com/dsnezhkov/octohook)

---------------
### Web NFC <a name="webnfc"></a>
* **101**
	* [Web NFC](https://w3c.github.io/web-nfc/)

-------------
### WebRTC <a name="webrtc"></a>
* **101**
	* [WebRTC for the Curious: Go beyond the APIs](https://webrtcforthecurious.com/)
		* he WebRTC book that explains everything. WebRTC is a real-time communication framework that makes it easy to build real-time interactions for web and mobile devices.  You will learn about the WebRTC specification and how all the protocols work in depth, not just a tour of the APIs. The book is completely Open Source and available at https://webrtcforthecurious.com and https://github.com/webrtc-for-the-curious/webrtc-for-the-curious Learn the full details of ICE, SCTP, DTLS, SRTP, and how they work together to make up the WebRTC stack.  Hear how WebRTC implementers debug issues with the tools of the trade. Listen to interviews with the authors of foundational WebRTC tech! Hear the motivations and design details that pre-dated WebRTC by 20 years. Explore the cutting edge of what people are building with WebRTC. Learn about interesting use cases and how real-world applications get designed, tested and implemented in production. Written by developers who have written all of this from scratch. We learned it the hard way, now we want to share it with you! This book is vendor agnostic and multiple Open Source projects and companies are involved. We would love to have you involved!
* **Articles/Papers/Talks/Writeups**
* **General**
* **Tools**
	* [STUN IP Address requests for WebRTC](https://github.com/diafygi/webrtc-ips)

---------------
### WebSockets <a name="websockets"></a>
* **101**
	* [The WebSocket Protocol Standard - IETF](https://tools.ietf.org/html/rfc6455)
	* [WebSocket Protocol - RFC Draft 17](https://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17)
	* [Websockets - An Introduction - subudeepak](https://gist.github.com/subudeepak/9897212)
* **Articles/Papers/Talks/Writeups**
	* [What’s wrong with WebSocket APIs? Unveiling vulnerabilities in WebSocket APIs. - Mikhail Egorov](https://speakerdeck.com/0ang3el/whats-wrong-with-websocket-apis-unveiling-vulnerabilities-in-websocket-apis)
	* [Hacking Web Sockets: All Web Pentest Tools Welcomed - VDALabs(2019)](https://vdalabs.com/2019/03/05/hacking-web-sockets-all-web-pentest-tools-welcomed/)
	* [To Fuzz a WebSocket - Andreas Happe(2019)](https://snikt.net/blog/2019/05/22/to-fuzz-a-websocket/)
* **Talks/Presentations/Videos**
	* [Old Tools, New Tricks: Hacking WebSockets - Michael Fowl, Nick Defoe(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/stable-35-old-tools-new-tricks-hacking-websockets-michael-fowl-nick-defoe)
* **Tools**
	* [WSSiP: A WebSocket Manipulation Proxy](https://github.com/nccgroup/wssip)
		* Short for "WebSocket/Socket.io Proxy", this tool, written in Node.js, provides a user interface to capture, intercept, send custom messages and view all WebSocket and Socket.IO communications between the client and server.
	* [Websocket Fuzzer](https://github.com/andresriancho/websocket-fuzzer)
		* A simple websocket fuzzer for application penetration testing.;  HTML5 WebSocket message fuzzer
	* [websocket-harness](https://github.com/VDA-Labs/websocket-harness)
		* This python script can be placed between traditional web penetration testing tools and WebSocket connections, which does translation from HTTP to WebSocket and back. Think of it like a fuzzing harness that is used for native code.

---------------
### WebUSB <a name="webusb"></a>
* **101**
	* [WebUSB API - Sept2017](https://wicg.github.io/webusb/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [WebUSB - How a website could steal data off your phone](https://labs.mwrinfosecurity.com/blog/webusb/)
		* This blog post looks in to the capabilities of WebUSB to understand how it works, the new attack surface, and privacy issues. We will describe the processes necessary to get access to devices and how permissions are handled in the browser. Then we will discuss some security implications and shows, how a website can use WebUSB to establish an ADB connection and effectively compromise a connected Android phone.

----------------
## Technologies <a name="technologies"></a>

### API Stuff <a name="api"></a>
* **101**
	* [OWASP API Security Project](https://owasp.org/www-project-api-security/)
	* [WebSocket API Standards](https://www.w3.org/TR/2011/WD-websockets-20110929/)
	* [API Throwdown: RPC vs REST vs GraphQL - Nate Barbettini(Iterate 2018)](https://www.youtube.com/watch?v=IvsANO0qZEg)
		* Choosing an API design style can be downright daunting. The RPC vs. REST debate has raged for years, and now there's a new kid on the block: GraphQL. Which is right for your application? I'll demystify these API styles in clear terms and help you decide how to design your API.
	* [A brief look at the evolution of interface protocols leading to modern APIs - Luis Augusto Weir(2019)](https://www.soa4u.co.uk/2019/02/a-brief-look-at-evolution-of-interface.html)
* **Reference**
	* [White House Web API Standards](https://github.com/WhiteHouse/api-standards)
		* This document provides guidelines and examples for White House Web APIs, encouraging consistency, maintainability, and best practices across applications. White House APIs aim to balance a truly RESTful API interface with a positive developer experience (DX).
	* **OpenAPI**
		* [The OpenAPI Specification](https://github.com/OAI/OpenAPI-Specification)
			* The OpenAPI Specification (OAS) defines a standard, programming language-agnostic interface description for REST APIs, which allows both humans and computers to discover and understand the capabilities of a service without requiring access to source code, additional documentation, or inspection of network traffic. When properly defined via OpenAPI, a consumer can understand and interact with the remote service with a minimal amount of implementation logic. Similar to what interface descriptions have done for lower-level programming, the OpenAPI Specification removes guesswork in calling a service.
		* [What Is OpenAPI?](https://swagger.io/docs/specification/about/)
* **Building**
	* [Build Simple Restful Api With Python and Flask Part 1 - Mukhammad Ginanjar Azie](https://medium.com/python-pandemonium/build-simple-restful-api-with-python-and-flask-part-1-fae9ff66a706)
	* [Building beautiful REST APIs using Flask, Swagger UI and Flask-RESTPlus](http://michal.karzynski.pl/blog/2016/06/19/building-beautiful-restful-apis-using-flask-swagger-ui-flask-restplus/)
* **Securing**
	* [OWASP API Security Project](https://www.owasp.org/index.php/OWASP_API_Security_Project)
	* [OWASP API Security Top 10](https://github.com/OWASP/API-Security)
	* [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist/)
		* Checklist of the most important security countermeasures when designing, testing, and releasing your API
	* [Code Patterns for API Authorization: Designing for Security - Tanner Prynn(2020)](https://research.nccgroup.com/2020/04/21/code-patterns-for-api-authorization-designing-for-security/)
		* "This post describes some of the most common design patterns for authorization checking in web application code. Comparisons are made between the design patterns to help understand when each pattern makes sense as well as the drawbacks of the pattern. For developers and architects, this post helps you to understand what the different code patterns look like and how to choose between them. For security auditors, the most effective approaches to auditing authorization controls are explained based on which pattern the code uses."
* **Talks & Presentations**
	* [BOLA, IDOR, MA, BFLA. Welcome to the OWASP API Top 10! - Adam Fisher(BSidesSLC 2020)](https://www.youtube.com/watch?v=6Nu1UU2ny2I&list=PLqVzh0_XpLfSJ2Okt38acDdO_xu2zKYmK&index=11&t=0s)
	* [API hacking for the Actually Pretty Inexperienced hacker with Katie Paxton-Fear(OWASP DevSlop)](https://www.youtube.com/watch?v=qqmyAxfGV9c)
	* [API Security: Tokens, Flows and the Big Bad Wolf -  Ingy Youssef(BSidesColombus(2019))](https://www.irongeek.com/i.php?page=videos/bsidescolumbus2019/bsidescmh2019-3-04-api-security-tokens-flows-and-the-big-bad-wolf-ingy-youssef)
		* OAuth Flows, OpenID Connect, tokens, nonces, gateways & all the fun API stuff. Well, there's always a big bad wolf, and APIs have lots of targets. Digital Transformations are rolling out more and more APIs, yesterday is different than today, the security model is changing, but in what ways? We need to secure APIs and be enablers of change and lock out the big bad wolf.
* **Testing**
	* **General**
		* [Security testing guide for JSON / REST APIs #1/3 - Ivan Novikov](https://medium.com/@d0znpp/security-testing-guide-for-json-rest-apis-1-3-38eddba67098)
		* [Simplifying API Pentesting With Swagger Files - David Yesland](https://rhinosecuritylabs.com/application-security/simplifying-api-pentesting-swagger-files/)
		* [Exploring Service APIs Through Test Automation - Amber Race(2020)](https://testautomationu.applitools.com/exploring-service-apis-through-test-automation/)
	* **Postman**
		* [Better API Penetration Testing with Postman – Part 1 - Mic Whitehorn-Gillam(2019)](https://blog.secureideas.com/2019/03/better-api-penetration-testing-with-postman-part-1.html)
			* [Part 2](https://blog.secureideas.com/2019/03/better-api-penetration-testing-with-postman-part-2.html)
			* [Part 3](https://blog.secureideas.com/2019/04/better-api-penetration-testing-with-postman-part-3.html)
			* [Part 4](https://blog.secureideas.com/2019/06/better-api-penetration-testing-with-postman-part-4.html)
	* **Insomnia**
		* [Insomnia - Kong](https://github.com/Kong/insomnia)
			* Insomnia is a cross-platform REST client, built on top of Electron.
		* [Getting Started API Penetration Testing with Insomnia - Mic Whitehorn-Gillam(2020)](https://blog.secureideas.com/2020/04/getting-started-api-penetration-testing-with-insomnia.html)
* **Fuzzing**
	* [Fuzzapi](https://github.com/lalithr95/Fuzzapi/)
		* Fuzzapi is rails application which uses API_Fuzzer and provide UI solution for gem.
	* [Automating API Penetration Testing using fuzzapi - AppSecUSA 2016](https://www.youtube.com/watch?v=43G_nSTdxLk)
* **REST/SOAP**
	* See [REST](#rest) section below.
* **Tools**
	* [Postman - chrome plugin](https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop)
	* [restclient - Firefox addon](https://addons.mozilla.org/de/firefox/addon/restclient/)
	* [Astra](https://github.com/flipkart-incubator/Astra)
		* REST API penetration testing is complex due to continuous changes in existing APIs and newly added APIs. Astra can be used by security engineers or developers as an integral part of their process, so they can detect and patch vulnerabilities early during development cycle. Astra can automatically detect and test login & logout (Authentication API), so it's easy for anyone to integrate this into CICD pipeline. Astra can take API collection as an input so this can also be used for testing apis in standalone mode.
	* [API-fuzzer](https://github.com/Fuzzapi/API-fuzzer)
		* API Fuzzer which allows to fuzz request attributes using common pentesting techniques and lists vulnerabilities
	* [Automatic API Attack Tool - Imperva](https://github.com/imperva/automatic-api-attack-tool)
		* "Imperva's customizable API attack tool takes an API specification as an input, and generates and runs attacks that are based on it as an output. The tool is able to parse an API specification and create fuzzing attack scenarios based on what is defined in the API specification. Each endpoint is injected with cleverly generated values within the boundaries defined by the specification, and outside of it, the appropriate requests are sent and their success or failure are reported in a detailed manner. You may also extend it to run various security attack vectors, such as illegal resource access, XSS, SQLi and RFI, that are targeted at the existing endpoints, or even at non-existing ones. No human intervention is needed. Simply run the tool and get the results."

----------------
### Web Browsers <a name="webbrowser"></a>
* **101**
	* [Demystifying Browsers - Eric Law(2020)](https://textslashplain.com/2020/02/09/demystifying-browsers/)
	* [Critical rendering path - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/Performance/Critical_rendering_path)
	* [Inside look at modern web browser (part 1) -  Mariko Kosaka(Developers.google)](https://developers.google.com/web/updates/2018/09/inside-browser-part1)
* **Articles/Blogposts**
	* [High Performance Browser Networking - Ilya Grigorik](https://hpbn.co/)
* **Browsers**
	* **Google Chrome**
		* **Articles/Blogposts**
			* [Chromium Internals - Lifetime of a navigation - netsekure.org](https://netsekure.org/)
		* **Source Code**
			* [source.chromium.org](https://source.chromium.org/chromium)
		* **Building it**
			* [ Get the Code: Checkout, Build, & Run Chromium - chromium.org](https://www.chromium.org/developers/how-tos/get-the-code)
		* **Bug Tracker**
			* [bugs.chromium](https://bugs.chromium.org/p/chromium/issues/list)	
		* **Tools**
			* [autochrome](https://github.com/nccgroup/autochrome)
				* This tool downloads, installs, and configures a shiny new copy of Chromium.
				* [Article](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/march/autochrome/)
	* **Microsoft Internet Explorer**
		* **Source Code**
			* [thirdpartysource.ms](https://thirdpartysource.microsoft.com/)
		* Stuff
			* [IEInternals - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/ieinternals/)
				* A look at Internet Explorer from the inside out.
	* **Mozilla Firefox**
		* **Source Code**
			* [searchfox.org](https://searchfox.org/)
		* **Building It**
			* [Building Firefox On Windows](https://firefox-source-docs.mozilla.org/setup/windows_build.html)
			* [Building Firefox On MacOS](https://firefox-source-docs.mozilla.org/setup/macos_build.html)
			* [Building Firefox On Linux](https://firefox-source-docs.mozilla.org/setup/linux_build.html)
		* **Bug Tracker**
			* [bugzilla.mozilla](https://bugzilla.mozilla.org/home)
	* **Webkit**
		* **Source Code**
			* [trac.webkit.org](https://trac.webkit.org/browser)
			* [Webkit Github Source Mirror](https://github.com/WebKit/webkit)
		* **Building It**
			* [Getting Started - webkit.org](https://webkit.org/getting-started/)
			* [Building and Running WebKit - Marcos Cáceres(2020)](https://marcosc.com/2020/09/building-and-running-webkit/)
		* **Bug Tracker**
			* [bugs.webkit](https://bugs.webkit.org/)
* **Rendering Engines**
	* **Articles/Blogposts**
		* [Martian Headsets - Joel Spolsky(2008)](https://www.joelonsoftware.com/2008/03/17/martian-headsets/)
		* [Today, the Trident Era Ends - Christian Schaefer](https://schepp.dev/posts/today-the-trident-era-ends/)
	* **Blink**
	* **Gecko**
	* **KHTML**
	* **Servo**
	* **Webkit**

----------------
### Browser Security <a name="browsersec"></a>
* **101**
	* [Browser Security White Paper - X41-dsec.de](https://browser-security.x41-dsec.de/X41-Browser-Security-White-Paper.pdf)
	* [Browser Security Whitepaper - Cure53](https://cure53.de/browser-security-whitepaper.pdf/)
* **Articles/Blogposts/Writeups**
* **Papers**
	* [Self-Exfiltration: The Dangers of Browser-Enforced Information Flow Control](http://ericchen.me/self_exfiltration.pdf)
		* Abstract: Since the early days of Netscape, browser vendors and web security researchers have restricted out-going data based on its destination. The security argument accompanying these mechanisms is that they prevent sensitive user data from being sent to the attacker’s domain. However, in this paper, we show that regulating web information flow based on its destination server is an inherently flawed security practice. It is vulnerable to self-exfiltration attacks, where an adversary stashes stolen information in the database of a whitelisted site, then later independently connects to the whitelisted site to retrieve the information. We describe eight existing browser security mechanisms that are vulnerable to these “self-exfiltration” attacks. Furthermore, we discovered at least one exfiltration channel for each of the Alexa top 100 websites. None of the existing information flow control mechanisms we surveyed are sufficient to protect data from being leaked to the attacker. Our goal is to prevent browser vendors and researchers from falling into this trap by designing more systems that are vulnerable to self-exfiltration.
	* [How do we Stop Spilling the Beans Across Origins? - A primer on web attacks via cross-origin information leaks and speculative execution - aaj@google.com, mkwst@google.com](https://www.arturjanc.com/cross-origin-infoleaks.pdf)
* **Presentations/Talks/Videos**
	* [Browser as Botnet - Brannon Dorsey - Radical Networks 2017](https://www.youtube.com/watch?v=GcXfu-EAECo)
		* When surfing the web, browsers download and execute arbitrary JavaScript code they receive from websites they visit. What if high-traffic websites served obfuscated code that secretly borrowed clock cycles from their client’s web browser as a means of distributed computing? In this talk I present research on the topic of using web browsers as zero-configuration, trojan-less botnets. The presentation includes a brief history of botnets, followed by an overview of techniques to build and deploy command-and-control botnet clients that run in-browser.
* **Tools**
	* [White Lightning Attack Platform](https://github.com/TweekFawkes/White_Lightning)
* **Chrome Specific**
	* [Chromium Sandbox](https://chromium.googlesource.com/chromium/src/+/master/docs/design/sandbox.md)
		* Sandbox leverages the OS-provided security to allow code execution that cannot make persistent changes to the computer or access information that is confidential. The architecture and exact assurances that the sandbox provides are dependent on the operating system. This document covers the Windows implementation as well as the general design.
	* [Chromium Cross-Origin Read Blocking (CORB)](https://chromium.googlesource.com/chromium/src/+/master/services/network/cross_origin_read_blocking_explainer.md)
	* [Chromium Sidechannel Threat Model: Post-Spectre Threat Model Re-Think(2018)](https://chromium.googlesource.com/chromium/src/+/master/docs/security/side-channel-threat-model.md)
	* [Security analysis of `<portal>` element - Michal Bentkowski](https://research.securitum.com/security-analysis-of-portal-element/)
		* [Code](https://github.com/securitum/research/tree/master/r2019_security-analysis-of-portal-element)
* **Firefox Specific**
* **Safari Specific**
	* [The Good, The Bad and The Ugly of Safari in Client-Side Attacks - bo0om, Wallarm Research](https://lab.wallarm.com/the-good-the-bad-and-the-ugly-of-safari-in-client-side-attacks-56d0cb61275a)
* **Browser Extensions**
	* **Articles/Blogposts/Writeups**
		* [Attacking Browser Extensions](https://github.com/qll/attacking-browser-extensions)
		* [Botnet in the Browser: Understanding Threats Caused by Malicious Browser Extensions](https://arxiv.org/pdf/1709.09577.pdf)
		* [An in-depth look into Malicious Browser Extensions(2014)](http://blog.trendmicro.com/trendlabs-security-intelligence/an-in-depth-look-into-malicious-browser-extensions/)
		* [Game of Chromes: Owning the Web with Zombie Chrome Extensions - DEF CON 25 - Tomer Cohen](https://www.youtube.com/watch?v=pR4HwDOFacY)
		* [Chrome-botnet](https://github.com/i-tsvetkov/chrome-botnet)
		* [Malware in the browser: how you might get hacked by a Chrome extension(2016) - Maxime Kjaer](https://kjaer.io/extension-malware/)
		* [I Sold a Chrome Extension but it was a bad decision - Amit Agarwal](https://www.labnol.org/internet/sold-chrome-extension/28377/)
		* [Detecting Installed Extensions (Edge)(2017) - brokenbrowser.com](https://www.brokenbrowser.com/microsoft-edge-detecting-installed-extensions/)
		* [Finding Browser Extensions To Hunt Evil!(2016) - Brad Antoniewicz](https://umbrella.cisco.com/blog/2016/06/16/finding-browser-extensions-find-evil/)
		* [Sparse Bruteforce Addon Detection(2011) - James Kettle](https://www.skeletonscribe.net/2011/07/sparse-bruteforce-addon-scanner.html)
		* [Intro to Chrome addons hacking: fingerprinting(2012) - kotowicz](http://blog.kotowicz.net/2012/02/intro-to-chrome-addons-hacking.html)
		* [No Place Like Chrome - xorrior](https://www.xorrior.com/No-Place-Like-Chrome/)
		* [Democratizing Chrome Extension Security - Duo Security(2018)](https://duo.com/blog/crxcavator)
		* [Kicking the Rims – A Guide for Securely Writing and Auditing Chrome Extensions - Matthew Bryant(2018)](https://thehackerblog.com/kicking-the-rims-a-guide-for-securely-writing-and-auditing-chrome-extensions/index.html)	
	* **Talks & Presentations**
		* [Offensive Browser Extension Development - Michael Weber(Derbycon7](https://www.youtube.com/watch?v=mKesEr1g4j0)
			* For the past few years, malware authors have abused the extension development functionality of Chrome and Firefox. More often than not, these extensions are abused for standard crimeware activities, such as ad click fraud, cryptocurrency mining, or stealing banking credentials. But this is only scratching the surface of what is possible if the appropriate browser APIs are abused. Extensions can act as a foothold into a target's internal network, provided a single user can be convinced to click two buttons. As a post-exploitation mechanism, extensions can be side-loaded with the ability to read and write files to disk. These actions will all be performed from the browser process(es) and likely go undetected by conventional endpoint protection solutions. This talk will discuss the creation, deployment, and usage of malicious browser extensions so that other red teamers can add this attack vector to their toolkit.
	* **Chrome Specific**
		* [Cross-Origin XMLHttpRequest - dev.chrome](https://developer.chrome.com/extensions/xhr#security-considerations)
		* [Chrome CSP: Interacting with - dev.chrome](https://developer.chrome.com/extensions/contentSecurityPolicy#interactions)
	* **Firefox Specific**
	* **Papers**
		* [Malicious Browser Extensions at Scale: Bridging the Observability Gap between Web Site and Browser - Louis F. DeKoven, Stefan Savage, Geoffrey M. Voelker, Nektarios Leontiadis](https://www.usenix.org/node/205856)
			* We present a methodology whereby users exhibiting suspicious online behaviors are scanned (with permission) to identify the set of extensions in their browser, and those extensions are in turn labelled based on the threat indicators they contain. We have employed this methodology at Facebook for six weeks, identifying more than 1700 lexically distinct malicious extensions. We use this labelling to drive user device clean-up efforts as well to report to antimalware and browser vendors.
			* [Paper](https://www.usenix.org/system/files/conference/cset17/cset17-paper-dekoven.pdf)
	* **Tools**
		* [extension_finder](https://github.com/brad-anton/extension_finder)
			* Python and PowerShell utilities for finding installed browser extensions, plug-ins and add-ons
		* [CSS Keylogger](https://github.com/maxchehab/CSS-Keylogging)
			* Chrome extension and Express server that exploits keylogging abilities of CSS.
		* [tarnish](https://github.com/mandatoryprogrammer/tarnish/)
			* tarnish is a static-analysis tool to aid researchers in security reviews of Chrome extensions.
		* [CRXcavator](https://crxcavator.io/docs#/README)
			* CRXcavator automatically scans the entire Chrome Web Store every 3 hours and produces a quantified risk score for each Chrome Extension based on several factors. These factors include permissions, inclusion of vulnerable third party javascript libraries, weak content security policies, missing details from the Chrome Web Store description, and more. Organizations can use this tool to assess the Chrome Extensions they have installed and to move towards implementing explicit allow (whitelisting) for their organization.
* **Exploiting**
	* [Smashing The Browser: From Vulnerability Discovery To Exploit](https://github.com/demi6od/Smashing_The_Browser)
		* Goes from introducing a fuzzer to producing an IE11 0day
	* [The Birth of a Complete IE11 Exploit Under the New Exploit Mitigations](https://www.syscan.org/index.php/download/get/aef11ba81927bf9aa02530bab85e303a/SyScan15%20Yuki%20Chen%20-%20The%20Birth%20of%20a%20Complete%20IE11%20Exploit%20Under%20the%20New%20Exploit%20Mitigations.pdf)
	* [BeEF Browser Exploitation Framework](http://beefproject.com/)
	* [BeEF](https://github.com/beefproject/beef)
		* Amid growing concerns about web-borne attacks against clients, including mobile clients, BeEF allows the professional penetration tester to assess the actual security posture of a target environment by using client-side attack vectors. Unlike other security frameworks, BeEF looks past the hardened network perimeter and client system, and examines exploitability within the context of the one open door: the web browser. BeEF will hook one or more web browsers and use them as beachheads for launching directed command modules and further attacks against the system from within the browser context.
	* [Browsers Gone Wild - Angelo Prado & Xiaoran Wang - BHAsia2015](https://www.youtube.com/watch?v=nsjCQlEsgW8)
		* In this talk, we will demonstrate and unveil the latest developments on browser specific weaknesses including creative new mechanisms to compromise confidentiality, successfully perform login and history detection, serve mixed content, deliver malicious ghost binaries without a C&C server, exploit cache/timing side channels to extract secrets from third-party domains, and leverage new HTML5 features to carry out more stealthy attacks. This is a practical presentation with live demos that will challenge your knowledge of the Same Origin Policy and push the limits of what is possible with today's web clients.

-----------
### HTTPS Certificates & Certificate Transparency <a name="ct"></a>
* **101**
* **Certificate Revocation**
	* **Articles/Blogposts**
		* [On CRLs, OCSP, and a Short Review of Why Revocation Checking Doesn't Work (for Browsers) - bt3gl](https://github.com/bt3gl/Pentesting_Toolkit/blob/master/Web_Hacking/guide_to_certs_and_cas.md)
		* [Everything You Need to Know About OCSP, OCSP Stapling & OCSP Must-Staple](https://securityboulevard.com/2020/07/everything-you-need-to-know-about-ocsp-ocsp-stapling-ocsp-must-staple/)
* **Certificate Pinning**
	* **101**
		* [Understanding Certificate Pinning - Scott Contini(2020)](https://littlemaninmyhead.wordpress.com/2020/06/08/understanding-certificate-pinning/)
		* [Certificate and Public Key Pinning - OWASP](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
* **Certificate Transparency**
	* **101**
		* [Certificate Transparency: a bird's-eye view - Emily M. Stark(2020)](https://emilymstark.com/2020/07/20/certificate-transparency-a-birds-eye-view.html)
	* **Talks/Presentations/Videos**
		* [Abusing Certificate Transparency Or How To Hack Web Applications BEfore Installation - Hanno Bock](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Hanno-Boeck-Abusing-Certificate-Transparency-Logs.pdf)
* **HTTP Strict Transport Security**
	* [RFC 6797: HTTP Strict Transport Security (HSTS) - IETF](https://tools.ietf.org/html/rfc6797)
	* [HTTP Strict Transport Security - Wikipedia](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)
* **Tools**
	* [CTFR](https://github.com/UnaPibaGeek/ctfr)
		* Do you miss AXFR technique? This tool allows to get the subdomains from a HTTPS website in a few seconds. How it works? CTFR does not use neither dictionary attack nor brute-force, it just abuses of Certificate Transparency logs.
	* [Certificate Transparency Subdomains](https://github.com/internetwache/CT_subdomains)
		* An hourly updated list of subdomains gathered from certificate transparency logs.
	* [CertSpotter](https://github.com/SSLMate/certspotter)
		* Cert Spotter is a Certificate Transparency log monitor from SSLMate that alerts you when a SSL/TLS certificate is issued for one of your domains. Cert Spotter is easier than other open source CT monitors, since it does not require a database.  It's also more robust, since it uses a special certificate parser that ensures it won't miss certificates.
	* [CRTScan](https://github.com/AnikHasibul/crtscan)
	 	* Scan subdomains from certificate transparency logs
	 * [ctexposer](https://github.com/chris408/ct-exposer)
	 	* An OSINT tool that discovers sub-domains by searching Certificate Transparency logs

----------------
### Content Management Systems <a name="cms"></a>
* **Agnostic**
	* [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
		* WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1500 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.
	* [w3af](https://github.com/andresriancho/w3af)
		* w3af: web application attack and audit framework, the open source web vulnerability scanner.
* **Drupal**
	* **101**
		* [Drupal](https://www.drupal.org/)
		* [Official Documentation](https://www.drupal.org/documentation)
		* [Drupal - Wikipedia](https://en.wikipedia.org/wiki/Drupal)
	* **Articles/Blogposts/Writeups**
		* [Drupal Security Checklist](https://github.com/gfoss/attacking-drupal/blob/master/presentation/drupal-security-checklist.pdf)
		* [Uncovering Drupalgeddon 2 - Checkpoint](https://research.checkpoint.com/uncovering-drupalgeddon-2/)
	* **Papers**
		* [Drupal SA-CORE-2019-003 远程命令执行分析](https://paper.seebug.org/821/)
	* **Tools**
		* [Drupal Attack Scripts](https://github.com/gfoss/attacking-drupal)
			* Set of brute force scripts and Checklist	
		* [Droopescan](https://github.com/droope/droopescan)
			* A plugin-based scanner that aids security researchers in identifying issues with several CMSs, mainly Drupal & Silverstripe.
* **Joomla**
	* [Highly Effective Joomla Backdoor with Small Profile](http://blog.sucuri.net/2014/02/highly-effective-joomla-backdoor-with-small-profile.html)
	* [JoomScan](https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project)
		* Joomla! is probably the most widely-used CMS out there due to its flexibility, user-friendlinesss, extensibility to name a few.So, watching its vulnerabilities and adding such vulnerabilities as KB to Joomla scanner takes ongoing activity.It will help web developers and web masters to help identify possible security weaknesses on their deployed Joomla! sites. No web security scanner is dedicated only one CMS.
	* [JScanner](https://github.com/tampe125/jscanner/blob/master/README.md)
		* Analyze target Joomla! installation using several different techniques.
	* [JoomlaVS](https://github.com/rastating/joomlavs)
		* JoomlaVS is a Ruby application that can help automate assessing how vulnerable a Joomla installation is to exploitation. It supports basic finger printing and can scan for vulnerabilities in components, modules and templates as well as vulnerabilities that exist within Joomla itself.
* **Sharepoint**
	* [Sparty - Sharepoint/Frontpage Auditing Tool](https://github.com/alias1/sparty)
		* Sparty is an open source tool written in python to audit web applications using sharepoint and frontpage architecture. The motivation behind this tool is to provide an easy and robust way to scrutinize the security configurations of sharepoint and frontpage based web applications. Due to the complex nature of these web administration software, it is required to have a simple and efficient tool that gathers information, check access permissions, dump critical information from default files and perform automated exploitation if security risks are identified. A number of automated scanners fall short of this and Sparty is a solution to that.
* **Wordpress**
	* [WPScan](https://github.com/wpscanteam/wpscan)
		* WPScan is a black box WordPress vulnerability scanner.
	* [WPSeku](https://github.com/m4ll0k/WPSeku)
		* Wordpress Security Scanner

--------------
### Continous Integration/Delivery/Build Systems <a name="cii"></a>
* [Hacking Jenkins Servers With No Password](https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password)
* [Hacking Jenkins - Ideas - Zeroknock](http://zeroknock.blogspot.com/search/label/Hacking%20Jenkins)
* [pwn_jenkins](https://github.com/gquere/pwn_jenkins)
	* Notes about attacking Jenkins servers
* [Hacking Jenkins Part 1 - Play with Dynamic Routing - Orange](http://blog.orange.tw/2019/01/hacking-jenkins-part-1-play-with-dynamic-routing.html)

--------------
### ColdFusion <a name="coldfusion"></a>
* [Attacking Adobe ColdFusion](http://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html)
* [ColdFusion Security Resources](https://www.owasp.org/index.php/ColdFusion_Security_Resources)
* [ColdFusion for Penetration Testers](http://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers)

----------------
### Electron <a name="electron"></a>
* **101**
	* [Electron.js](https://www.electronjs.org/)
	* [Electron (software framework) - Wikipedia](https://en.wikipedia.org/wiki/Electron_(software_framework))
	* [Electron(code)](https://github.com/electron/electron)
* **Articles/Blogposts/Writeups**
	* [From Markdown to RCE in Atom](https://statuscode.ch/2017/11/from-markdown-to-rce-in-atom/)
	* [As It Stands - Electron Security - 2016](http://blog.scottlogic.com/2016/03/09/As-It-Stands-Electron-Security.html)
	* [As It Stands - Update on Electorn Security - 2016](http://blog.scottlogic.com/2016/06/01/An-update-on-Electron-Security.html)
	* [Modern Alchemy: Turning XSS into RCE](https://blog.doyensec.com/2017/08/03/electron-framework-security.html)
	* [Build cross platform desktop XSS, it’s easier than you think by Yosuke Hasegawa - CodeBlue16](https://www.slideshare.net/codeblue_jp/cb16-hasegawa-en)
	* [Modern Alchemy: Turning XSS into RCE - doyensec](https://blog.doyensec.com/2017/08/03/electron-framework-security.html)
	* [From Markdown to RCE in Atom - statuscode.ch](https://statuscode.ch/2017/11/from-markdown-to-rce-in-atom/)
	* [Instrumenting Electron Apps for Security Testing - Paolo Stagno](https://blog.doyensec.com/2018/07/19/instrumenting-electron-app.html)
	* [Signature Validation Bypass Leading to RCE In Electron-Updater - Lorenzo Stella(2020)](https://blog.doyensec.com/2020/02/24/electron-updater-update-signature-bypass.html)
	* [The App Sandbox - Charlie Hess(Slack2020)](https://slack.engineering/the-app-sandbox/)
	* [Discord Desktop app RCE - Masato Kinugawa(2020)](https://mksben.l0.cm/2020/10/discord-desktop-rce.html)
* **Documentation**
	* [Electron Documentation](https://electronjs.org/docs)
	* [Security, Native Capabilities, and Your Responsibility - Electron Documentation](https://electron.atom.io/docs/tutorial/security/)
* **Papers**
* **Talks & Presentations**
	* [MarkDoom: How I Hacked Every Major IDE in 2 Weeks - Matt Austin, LevelUp 2017](https://www.youtube.com/watch?v=nnEnwJbiO-A)
	* [Electron - Build cross platform desktop XSS, it’s easier than you think by Yosuke Hasegawa - [CB16] ](https://www.youtube.com/watch?v=-j1DPPf9Z4U)
	* [Electronegativity - A Study of Electron Security - Carettoni](https://www.blackhat.com/docs/us-17/thursday/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security.pdf)
	* [Electron Security Checklist - A guide for developers and auditors - Luca Carettoni](https://www.blackhat.com/docs/us-17/thursday/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security-wp.pdf)
* **Published Exploits**
	* [ CVE-2018-15685 - Electron WebPreferences Remote Code Execution Finding](https://www.contrastsecurity.com/security-influencers/cve-2018-15685)
* **Tools**
	* [electron-run-shell-example](https://github.com/martinjackson/electron-run-shell-example?files=1)
		* An HTML5 stand alone app using GitHub Electron (Chrome engine + Node.js) -- this is a GUI wrapper example that runs and process output of a bash shell command.
	* [Electronegativity](https://github.com/doyensec/electronegativity)
		* Electronegativity is a tool to identify misconfigurations and security anti-patterns in Electron-based applications.

----------------
### Flash/SWF <a name="swf"></a>
* **Articles/Blogposts/Writeups**
	* [Testing for Cross-Site-Flashing - OWASP](https://www.owasp.org/index.php/Testing_for_Cross_site_flashing_(OTG-CLIENT-008)\)
	* [Security Domains, Application Domains, and More in ActionScript 3.0](http://www.senocular.com/flash/tutorials/contentdomains/)
	* [The old is new, again. CVE-2011-2461 is back!](https://www.slideshare.net/ikkisoft/the-old-is-new-again-cve20112461-is-back)
		* As a part of an ongoing investigation on Adobe Flash SOP bypass techniques, we identified a vulnerability affecting old releases of the Adobe Flex SDK compiler. Further investigation traced the issue back to a well known vulnerability (CVE20112461), already patched by Adobe. Old vulnerability, let's move on? Not this time. CVE20112461 is a very interesting bug. As long as the SWF file was compiled with a vulnerable Flex SDK, attackers can still use this vulnerability against the latest web browsers and Flash plugin. Even with the most recent updates, vulnerable Flex applications hosted on your domain can be exploited. In this presentation, we will disclose the details of this vulnerability (Adobe has never released all technicalities) and we will discuss how we conducted a large scale analysis on popular websites, resulting in the identification of numerous Alexa Top 50 sites vulnerable to this bug. Finally, we will also release a custom tool and a Burp plugin capable of detecting vulnerable SWF applications.
	* Advanced Flash Vulnerabilities in Youtube Writeups Series
		* [Advanced Flash Vulnerabilities in Youtube – Part 1](https://opnsec.com/2017/08/advanced-flash-vulnerabilities-in-youtube-part-1/)
		* [Advanced Flash Vulnerabilities in Youtube – Part 2](https://opnsec.com/2017/08/advanced-flash-vulnerabilities-in-youtube-part-2/)
		* [Advanced Flash Vulnerabilities in Youtube – Part 3](https://opnsec.com/2017/08/advanced-flash-vulnerabilities-in-youtube-part-3/)
	* [Decode Adobe Flex AMF protocol](http://blog.dornea.nu/2015/06/22/decode-adobe-flex-amf-protocol/)	
	* [Finding XSS vulnerabilities in flash files.](https://olivierbeg.com/finding-xss-vulnerabilities-in-flash-files/)
	* [XSS and CSRF via SWF Applets (SWFUpload, Plupload)](https://nealpoole.com/blog/2012/05/xss-and-csrf-via-swf-applets-swfupload-plupload/)
	* [WordPress Flash XSS in flashmediaelement.swf - cure53](https://gist.github.com/cure53/df34ea68c26441f3ae98f821ba1feb9c)
	* [WordPress Flash XSS in flashmediaelement.swf - cure53](https://gist.github.com/cure53/df34ea68c26441f3ae98f821ba1feb9c)
	* [Security Domains, Application Domains, and More in ActionScript 3.0 - senocular](http://www.senocular.com/flash/tutorials/contentdomains/)
	* [Testing for Cross site flashing (OTG-CLIENT-008) - OWASP](https://www.owasp.org/index.php/Testing_for_Cross_site_flashing_(OTG-CLIENT-008))
	* [XSS and CSRF via SWF Applets (SWFUpload, Plupload) - Neal Poole](https://nealpoole.com/blog/2012/05/xss-and-csrf-via-swf-applets-swfupload-plupload/)
	* [Getting started with AMF Flash Application Penetration Testing ! - nerdint](https://nerdint.blogspot.com/2019/10/getting-started-with-amf-flash.html)
* **Securing**
	* [HardenFlash](https://github.com/HaifeiLi/HardenFlash)
		* Patching Flash binary to stop Flash exploits and zero-days
* **Tools**
	* [ParrotNG](https://github.com/ikkisoft/ParrotNG/releases)
		* ParrotNG is a Java-based tool for automatically identifying vulnerable SWF files, built on top of swfdump. One JAR, two flavors: command line tool and Burp Pro Passive Scanner Plugin.
	[deblaze](http://blog.dornea.nu/2015/06/22/decode-adobe-flex-amf-protocol/)
		* Performs method enumeration and interrogation against flash remoting end points.

----------------
### GhostScript <a name="ghosts"></a>


----------------
### GraphQL <a name="graphql"></a>
* **101**
	* [GraphQL.org](https://graphql.org/)
	* [HowToGraphQL.com](https://www.howtographql.com/)
	* [Security Points to Consider Before Implementing GraphQL - Kristopher Sandoval(2017)](https://nordicapis.com/security-points-to-consider-before-implementing-graphql/)
	* [Why and how to disable introspection query for GraphQL APIs - wallarm(2019)](https://lab.wallarm.com/why-and-how-to-disable-introspection-query-for-graphql-apis/)
* **Articles/Blogposts/Writeups**
	* [ GraphQL Batching Attack  - ](https://lab.wallarm.com/graphql-batching-attack/)
	* [The 5 Most Common GraphQL Security Vulnerabilities - Aidan Noll(2020)](https://carvesystems.com/news/the-5-most-common-graphql-security-vulnerabilities/)
	* [Practical GraphQL attack vectors - jondow.eu](https://jondow.eu/practical-graphql-attack-vectors/)
	* [GraphQL path enumeration for better permission testing - deesee.xyz(2020)](https://blog.deesee.xyz/graphql/security/2020/04/13/graphql-permission-testing.html)
	* [A Hacker’s Guide to the Shopify GraphQL API 🚀](https://github.com/Shopify/bugbounty-resources/blob/master/graphql/main_guide.md)
	* [Introducing the Apollo GraphQL data stack - ApolloGraphQL](https://www.apollographql.com/blog/introducing-the-apollo-graphql-data-stack-5d005312cbd0)
	* [The GraphQL stack: How everything fits together - Sashko Stubailo](https://www.apollographql.com/blog/the-graphql-stack-how-everything-fits-together-35f8bf34f841)
	* [ Securing GraphQL. Part 1 - wallarm](https://lab.wallarm.com/securing-and-attacking-graphql-part-1-overview/)
	* [GraphQL vs REST API model, common security test cases for GraphQL endpoints - just_a_noob(2019)](https://medium.com/@apkash8/graphql-vs-rest-api-model-common-security-test-cases-for-graphql-endpoints-5b723b1468b4)
	* [A Facebook GraphQL crash course - PHWD](https://www.facebook.com/notes/phwd/a-facebook-graphql-crash-course/1189337427822946)
* **Talks/Presentations/Videos**
	* [An Attackers View of Serverless and GraphQL Apps - Abhay Bhargav(AppSecCali2019)](https://www.youtube.com/watch?v=xr2YX5JbDbM)
		* This talk presents a red-team perspective of the various ways in which testers can discover and exploit serverless and/or GraphQL driven applications to compromise sensitive information, and gain a deeper foothold into database services, IAM services and other other cloud components. The talk will have some demos that will demonstrate practical attacks and attack possibilities against Serverless and GraphQL applications.
	* [REST in Peace: Abusing GraphQL to Attack Underlying Infrastructure - Matthew Szymanski(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/2-09-rest-in-peace-abusing-graphql-to-attack-underlying-infrastructure-matthew-szymanski)
		* [BugCrowd LevelUp0x5 Version of the talk](https://www.bugcrowd.com/resources/webinars/rest-in-peace-abusing-graphql-to-attack-underlying-infrastructure/)
		* GraphQL is a query language for APIs set to replace RESTful architecture. The use of this technology has achieved rapid adoption and is now leveraged by companies such as GitHub, Credit Karma, and PayPal. Companies such as Hacker One and New Relic have suffered from critical vulnerabilities hidden within GraphQL endpoints. In this talk we will learn enough about GraphQL to be dangerous. Demonstrate how to use the technology?s intricacies against itself while taking advantage of implementation errors and misconfigurations. Examine GraphQL specific attacks as well as tried and true techniques adapted to fit into the GraphQL context. Then walk through how to carry out these attacks efficiently and effectively, introducing a tool to help automate and streamline the process.
* **Tools**
	* [graphql-api-monitor](https://gitlab.com/dee-see/graphql-api-monitor)
	* [InQL Scanner](https://github.com/doyensec/inql)
		* A security testing tool to facilitate GraphQL technology security auditing efforts. InQL can be used as a stand-alone script or as a Burp Suite extension.
	* [GraphQL - Demo Vulnerable API](https://github.com/CarveSystems/vulnerable-graphql-api)
		* A simple GraphQL API demonstrating several common vulnerabilities.

----------------
### Imagemagick <a name="magick"></a>


----------------
### JavaScript <a name="javascript"></a>
* **Training**
	* [Javascript for Pentesters - PentesterAcademy](https://www.pentesteracademy.com/course?id=11)
* **101**
	* [Javascript Introduction - MozillaDevNetwork](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Introduction)
	* [JavaScript: Crash Course - bt3gl](https://coderwall.com/p/skucrq/javascript-crash-course)
	* [JavaScript for Pentesters. - BitsPlease](https://www.youtube.com/watch?v=HptfL5WRYF8)
* **Articles/Blogposts/Writeups**
	* [Static Analysis of Client-Side JavaScript for pen testers and bug bounty hunters - Bharath](https://blog.appsecco.com/static-analysis-of-client-side-javascript-for-pen-testers-and-bug-bounty-hunters-f1cb1a5d5288)
	* [Javascript for bug bounty hunters(part 1) — Ahmed Ezzat (BitTheByte)](https://medium.com/@bitthebyte/javascript-for-bug-bounty-hunters-part-1-dd08ed34b5a8)
		* [Part 2](https://medium.com/@bitthebyte/javascript-for-bug-bounty-hunters-part-2-f82164917e7)
		* [Part 3](https://medium.com/@bitthebyte/javascript-for-bug-bounty-hunters-part-3-3b987f24ab27)
	* [DOM Clobbering Attack](http://www.thespanner.co.uk/2013/05/16/dom-clobbering/)
* **Talks/Presentations/Videos**
	* [An Infosec Timeline: Noteworthy Events From 1970 To 2050 - Mario Heiderich(OWASP AppSec AMS)](https://www.youtube.com/watch?v=u3x_0955_TU&feature=youtu.be)
	* [Free Tools! How to Use Developer Tools and Javascript in Webapp Pentests - BHIS(2020)](https://www.youtube.com/watch?v=3W65ji1gc8c)
		* I like webapps, don't you? Webapps have got to be the best way to learn about security. Why? Because they're self-contained and so very transparent. You don't need a big ol' lab before you can play with them. You can run them in a single tiny VM or even tiny-er Docker image on your laptop. And so long as you're attacking your own stuff, it's easy to stay out of trouble. You're up and running in the time it takes for a single download.  And the transparent part? Ever since "view source" in the earliest web browsers, it's been easy to see exactly what's going on in a webapp and in the browser. Every webapp you ever use has no choice but to give you the (client-side) source code! It's almost like there's no such thing as a "black box" webapp pentest, if you think about it... Anyhow - the Developer Tools in Firefox (and Chrome) are what happens when you take "view source" and add 25 years or so of creativity and power.  We'll look at the Developer Tools in the latest Firefox with a pentester's eye. Inspect and change the DOM (Document Object Model), take screenshots, find and extract key bits of data, use the console to run Javascript in the site's origin context and even pause script execution in the debugger if things go too fast... Maybe we'll convince you that you can realistically do a big chunk of a webapp pentest without ever leaving the browser.
* **JS Polyglots**
	* [This Image Is Also a Valid Javascript File  - Sebastion Stamm](https://dev.to/sebastianstamm/this-image-is-also-a-valid-javascript-file-5fol)
* **Source Maps**
	* [Introduction to JavaScript Source Maps - Ryan Seddon(2012)](https://www.html5rocks.com/en/tutorials/developertools/sourcemaps/)
* **Reverse-Engineering**
	* [Advanced JS Deobfuscation Via AST and Partial Evaluation (Google Talk WrapUp) - Stefano Di Paola(2015)](https://blog.mindedsecurity.com/2015/10/advanced-js-deobfuscation-via-ast-and.html)
	* [JavaScript AntiDebugging Tricks - x-c3ll(2020)](https://x-c3ll.github.io/posts/javascript-antidebugging/)
	* [Reverse engineering obfuscated JavaScript - PopUnder Chrome 59 - LiveOverflow](https://www.youtube.com/watch?v=8UqHCrGdxOM)
	* [Reverse engineering PopUnder trick for Chrome 60 - LiveOverflow](https://www.youtube.com/watch?v=PPzRcZLNCPY)
	* [Custom Chromium Build to Reverse Engineer Pop-Under Trick - LiveOverflow](https://www.youtube.com/watch?v=y6Uzinz3DRU)
	* [[Live] Reverse Engineering new PopUnder for Chrome 63 on Windows - LiveOverflow](https://www.youtube.com/watch?v=VcFQeimLH1c)
	* [Javascript Anti Debugging — Some Next Level Sh`*`t (Part 1 — Abusing SourceMappingURL) - Gal Weizman(2019)](https://medium.com/@weizmangal/javascript-anti-debugging-some-next-level-sh-t-part-1-abusing-sourcemappingurl-da91ff948e66)
	* [JavaScript tampering – detection and stealth - adtechmadness(2019)](https://adtechmadness.wordpress.com/2019/03/23/javascript-tampering-detection-and-stealth/)
* **Tools**
	* [JSFuck](http://www.jsfuck.com/)
		* JSFuck is an esoteric and educational programming style based on the atomic parts of JavaScript. It uses only six different characters to write and execute code.
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
### Java Server Faces (JSF) <a name="jsf"></a>
* **101**
	* [Java Server Faces - Wikipedia](https://en.wikipedia.org/wiki/JavaServer_Faces)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities - alphabot](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)

----------------
### Java Server Pages (JSP) <a name="jsp"></a>
* **101**
	* [Java Server Pages - Wikipedia](https://en.wikipedia.org/wiki/JavaServer_Pages)
	* [JSP Tutorial - javapoint](https://www.javatpoint.com/jsp-tutorial)
	* [JSP Tutorial - some Examples of Java Servlet Pages - imperial.ac.uk](http://www.imperial.ac.uk/computing/csg/guides/java/jsp-tutorial---some-examples-of-java-servlet-pages/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Hacking with JSP Shells - NetSPI](https://blog.netspi.com/hacking-with-jsp-shells/)
	* [A Smaller, Better JSP Web Shell - securityriskadvisors](https://securityriskadvisors.com/blog/post/a-smaller-better-jsp-web-shell/)
		* [Code](https://github.com/SecurityRiskAdvisors/cmd.jsp)

----------------
### JSON Web Tokens <a name="jwt"></a>
* **101**
	* [JSON Web Token - Wikipedia](https://en.wikipedia.org/wiki/JSON_Web_Token)
	* [RFC 7159: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
	* [RFC 8725: JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)\
		* JSON Web Tokens, also known as JWTs, are URL-safe JSON-based security tokens that contain a set of claims that can be signed and/or encrypted. JWTs are being widely used and deployed as a simple security token format in numerous protocols and applications, both in the area of digital identity and in other application areas. This Best Current Practices document updates RFC 7519 to provide actionable guidance leading to secure implementation and deployment of JWTs.
	* [The Anatomy of a JSON Web Token](https://scotch.io/tutorials/the-anatomy-of-a-json-web-token)
	* [Introduction to JSON Web Tokens](https://jwt.io/introduction/)
	* [JSON Web Token Flowchart](http://cryto.net/%7Ejoepie91/blog/attachments/jwt-flowchart.png)
	* [JSON Web Token Security Cheat Sheet](https://assets.pentesterlab.com/jwt_security_cheatsheet/jwt_security_cheatsheet.pdf)
	* [Learn JSON Web Token(JWT) in 10 Minutes - tutorialdocs.com](https://www.tutorialdocs.com/article/jwt-learn.html)
* **Informational**
	* **Articles/Blogposts/Writeups**
		* [JWT Handbook - Auth0](https://auth0.com/resources/ebooks/jwt-handbook)
		* [Reference Tokens and Introspection - leastprivilege.com(2015)](https://leastprivilege.com/2015/11/25/reference-tokens-and-introspection/)
		* [Stop using JWT for sessions - joepie91(2016)](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/)
		* [Stop using JWT for sessions, part 2: Why your solution doesn't work - joepie91(2016)](http://cryto.net/%7Ejoepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/)
		* [JSON Web Token Best Current Practices - draft-ietf-oauth-jwt-bcp-07](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-07)
		* [JWTs: Which Signing Algorithm Should I Use? - Scott Brady(2020)](https://www.scottbrady91.com/JOSE/JWTs-Which-Signing-Algorithm-Should-I-Use)
		* [The Hard Parts of JWT Security Nobody Talks About - Philippe De Ryck(2019)](https://www.pingidentity.com/en/company/blog/posts/2019/jwt-security-nobody-talks-about.html)
		* [Building a Secure Signed JWT - Dan Noore(2020)](https://fusionauth.io/learn/expert-advice/tokens/building-a-secure-jwt)
	* **Presentations/Talks/Videos**
		* [Jwt==insecurity? - Ruxcon2018](https://www.slideshare.net/snyff/jwt-insecurity)
		* [JSON Web Tokens Suck - Randall Degges (DevNet Create 2018)](https://www.youtube.com/watch?v=JdGOb7AxUo0)
			* JSON Web Tokens (JWTs) are all the rage in the security world. They're becoming more and more ubiquitous in web authentication libraries, and are commonly used to store a user's identity information. In this talk, you'll learn why JWTs suck, and why you should never use them.
		* [Attacking and Securing JWT - @airman604(OWAPS Vancouver)](https://owasp.org/www-chapter-vancouver/assets/presentations/2020-01_Attacking_and_Securing_JWT.pdf)
		* [JWTs in a Flash! - Evan Johnson(Defcon24)](https://www.slideshare.net/EvanJJohnson/jwts-and-jose-in-a-flash)
			* The new(ish) JOSE standard is growing rapidly in popularity. Many people are excited to adopt the new standard and use it to build interesting and new things with JWT! Let's get everyone up to speed on JWT's, talk about the do's and don't regarding JWTs, review some JWT uses, and use JWT's effectively.
		* [Are You Properly Using JWTs? - Dmitry Sotnikov(AppSec California2020)](https://www.youtube.com/watch?v=M3jA0bGDCso)
			* JSON Web tokens (JWTs) are used massively in API-based applications as access tokens or to transport information across services. Unfortunately, JWT are often mis-used and incorrectly handled. Massive data breaches have occurred in the last 18 months due to token leakage and lack of proper of validation. This session focuses on best practices and real world examples of JWT usage, where we cover: Typical scenarios where using JWT is a good idea; Typical scenarios where using JWT is a bad idea!; Principles of Zero trust architecture and why you should always validate; Best practices to thoroughly validate JWTs and potential vulnerabilities if you don’t.; Use cases when encryption may be required for JWT
		* [JWT Parkour - Louis Nyffenegger(AppSec California2020)](https://www.youtube.com/watch?v=zWVRHK3ykfo)
			* Nowadays, JSON Web Tokens are everywhere. They are used as session tokens or just to pass data between applications or µservices. By design, JWT contains a high number of security and cryptography pitfalls. In this talk, we are going to learn how to exploit (with demos) some of those issues. After covering the basics (None and Algorithm confusion), we are going to move to kid injection, embedded JWK (CVE-2018-0114). Finally, we will look at jku and x5u attributes and how they can be abused by chaining vulnerabilities.
		* [JWT: jku x5u - Louis Nyffenegger(2020)](https://www.slideshare.net/snyff/jwt-jku-x5u)
			* Talk on JWT jku and x5u and how to attack them
* **Attacking**
	* **101**
		* [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki)
			* This wiki is a project to document the known attacks and potential security vulnerabilities and misconfigurations you may come across when testing JSON Web Tokens, and to provide a repeatable methodology for attacking them.
		* [JWT Hacking 101 - trustfoundry.net](https://trustfoundry.net/jwt-hacking-101/)
	* **Articles/Blogposts/Writeups**
		* [JWT Tool Attack Methods - ticarpi](https://www.ticarpi.com/jwt-tool-attack-methods/)
		* [JWT Vulnerabilities (Json Web Tokens) - HackTricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
		* [JWT Attack Walk-Through - Jerome Smith(2019)](https://www.nccgroup.com/uk/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/)
		* [Hacking JWT Tokens: The None Algorithm - Shivam Bathla](https://blog.pentesteracademy.com/hacking-jwt-tokens-the-none-algorithm-67c14bb15771)
		* [How to Hack a Weak JWT Implementation with a Timing Attack - Tamas Polgar(2017)](https://hackernoon.com/can-timing-attack-be-a-practical-security-threat-on-jwt-signature-ba3c8340dea9)
		* [Practicing JWT Attacks Against Juice-Shop - scomurr(2020)](https://sc.scomurr.com/jwt-and-juice-shop/)
		* [Hardcoded secrets, unverified tokens, and other common JWT mistakes - Vasilii Ermilov(2020)](https://r2c.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/)
	* **Talks/Presentations**
		* [Friday the 13th: JSON Attacks - Defcon25](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Alvaro-Munoz-JSON-attacks.pdf)
		* [Critical vulnerabilities in JSON Web Token libraries - 2015](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
		* [Cracking JWT tokens: a tale of magic, Node.JS and parallel computing - Luciano Mammino(Codemotion Milan2017)](https://www.youtube.com/watch?v=_wXQW-dIyL8)
			* Learn how you can use some JavaScript/Node.js black magic to crack JWT tokens and impersonate other users or escalate privileges. Just add a pinch of ZeroMQ, a dose of parallel computing, a 4 leaf clover, mix everything applying some brute force and you'll get a powerful JWT cracking potion!
		* [The Hacker's Guide to JWT Security by Patrycja Wegrzynowicz(2019)](https://www.youtube.com/watch?v=_wXQW-dIyL8)
			* JSON Web Token (JWT) is an open standard for creating tokens that assert some number of claims like a logged in user and his/her roles. JWT is widely used in modern applications as a stateless authentication mechanism. Therefore, it is important to understand JWT security risks, especially when broken authentication is among the most prominent security vulnerabilities according to the OWASP Top 10 list.  This talk guides you through various security risks of JWT, including confidentiality problems, vulnerabilities in algorithms and libraries, token cracking, token sidejacking, and more. In live demos, you’ll learn how to hijack a user account exploiting common security vulnerabilities on the client-side, on the server-side, and in transport.  You’ll also find out about common mistakes and vulnerabilities along with the best practices related to the implementation of JWT authentication and the usage of available JWT libraries.
		* ["JWAT.... Attacking JSON Web Tokens" - Louis Nyffenegger(BSides Canberra 2019)](https://www.youtube.com/watch?v=sGvF8wS76Dk)
		* [Modern Webapp Pentesting: How to Attack a JWT - BB King(2020)](https://www.youtube.com/watch?v=muYmiEtPL8U)
			* In this Black Hills Information Security webcast - an excerpt from his upcoming 16-hour Modern Webapp Pentesting course - BB King will talk about what JSON Web Tokens are, why they're so controversial, and how to test for their major weaknesses. Then, using OWSAP's Juice Shop as a target, he'll show you a straightforward method for exploiting them that you can use on your own next webapp pentest
* **Testing**
	* [Attacking JWT authentication](https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/)
	* [Fuzzing JSON Web Services - Simple guide how to fuzz JSON web services properly - secapps](https://secapps.com/blog/2018/03/fuzzing-json-web-services)
	* [JWT Attack Walk-Through - Jerome Smith](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/)
* **Tools**
	* [json token decode](http://jwt.calebb.net/)
	* [JWT Inspector - FF plugin](https://www.jwtinspector.io/)
		* JWT Inspector is a browser extension that lets you decode and inspect JSON Web Tokens in requests, cookies, and local storage. Also debug any JWT directly from the console or in the built-in UI.
	* [c-jwt-cracker ](https://github.com/brendan-rius/c-jwt-cracker)
	* [JWT4B](https://github.com/mvetsch/JWT4B)
		* JSON Web Tokens (JWT) support for the Burp Interception Proxy. JWT4B will let you manipulate a JWT on the fly, automate common attacks against JWT and decode it for you in the proxy history. JWT4B automagically detects JWTs in the form of 'Authorization Bearer' headers as well as customizable post body parameters.
	* [jwt_tool](https://github.com/ticarpi/jwt_tool)
		* a toolkit for validating, forging and cracking JWTs (JSON Web Tokens).
		* [Introducing JWT Tool  - ticarpi](https://www.ticarpi.com/introducing-jwt-tool/)
	* [jwt_secrets - BBhacKing](https://github.com/BBhacKing/jwt_secrets)
		* A list of "secrets" from JWT sample code and readme files based on the list of projects at https://jwt.io/
	* [jwt-secrets - wallarm](https://github.com/wallarm/jwt-secrets)
		* The goal for this project was to find as many public-available JWT secrets as possible to help developers and DevOpses identify it by traffic analysis at the Wallarm NGWAF level.
* **Writeups**
	* [How to configure Json.NET to create a vulnerable web API - alphabot](https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html)
	* [Learn how to use JSON Web Token (JWT) to secure your next Web App! (Tutorial/Example with Tests!!)](https://github.com/dwyl/learn-json-web-tokens)
	* [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
	* [Brute Forcing HS256 is Possible: The Importance of Using Strong Keys in Signing JWTs](https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/)
	* [Hacking JSON Web Token (JWT) - Hate_401](https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6)
	* [JWT (JSON Web Token) (in)security - Michal Sadjak(2019)](https://research.securitum.com/jwt-json-web-token-security/)
	* [Practical Approaches for Testing and Breaking JWT Authentication - Mazin Ahmed](https://mazinahmed.net/blog/breaking-jwt/)
	* [JSON Web Token Validation Bypass in Auth0 Authentication API - Ben Knight(2020)](https://insomniasec.com/blog/auth0-jwt-validation-bypass))

-------------
### MIME Sniffing <a name="mime"></a>
* **101**
	* [What is MIME Sniffing? - keycdn.com](https://www.keycdn.com/support/what-is-mime-sniffing/)
	* [Content Sniffing - Wikipedia](https://en.wikipedia.org/wiki/Content_sniffing)
		* Content sniffing, also known as media type sniffing or MIME sniffing, is the practice of inspecting the content of a byte stream to attempt to deduce the file format of the data within it.
* **Articles/Blogposts/Writeups**
	* [Risky sniffing - MIME sniffing in Internet Explorer enables cross-site scripting attacks - h-online.com(2009)](http://www.h-online.com/security/features/Risky-MIME-sniffing-in-Internet-Explorer-746229.html)
	* [What is “X-Content-Type-Options=nosniff”?](https://stackoverflow.com/questions/18337630/what-is-x-content-type-options-nosniff)
	* [Content hosting for the modern web - Google](https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html)
	* [Is it safe to serve any user uploaded file under only white-listed MIME content types? - StackOverflow](https://security.stackexchange.com/questions/11756/is-it-safe-to-serve-any-user-uploaded-file-under-only-white-listed-mime-content)
* **Exploitation of**
	* [MS07-034 - Yosuke Hasegawa](https://web.archive.org/web/20160609171311/http://openmya.hacker.jp/hasegawa/security/ms07-034.txt)

----------------
### NodeJS <a name="nodejs"></a>
* **101**
* **Educational**
	* [A Roadmap for Node.js Security](https://nodesecroadmap.fyi/)	
	* [NodeGoat](https://github.com/OWASP/NodeGoat)
		* Being lightweight, fast, and scalable, Node.js is becoming a widely adopted platform for developing web applications. This project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
* **Articles/Blogposts/Writeups**	
	* [Reverse shell on a Node.js application](https://wiremask.eu/writeups/reverse-shell-on-a-nodejs-application/)
	* [Pen Testing Node.js: Staying N Sync Can Make the Server Go Bye Bye Bye - Tim Medin](https://pen-testing.sans.org/blog/2015/12/20/pen-testing-node-js-staying-n-sync-can-make-the-server-go-bye-bye-bye)
	* [Debugging Node.js with Google Chrome - Jacopo Daeli](https://medium.com/the-node-js-collection/debugging-node-js-with-google-chrome-4965b5f910f4)
	* [Static Analysis of Client-Side JavaScript for pen testers and bug bounty hunters - Bharath(2018)](https://blog.appsecco.com/static-analysis-of-client-side-javascript-for-pen-testers-and-bug-bounty-hunters-f1cb1a5d5288)
* **Presentations/Talks/Videos**
	* [NodeJS: Remote Code Execution as a Service - Peabnuts123 – Kiwicon 2016](https://www.youtube.com/watch?v=Qvtfagwlfwg)
		* [SLIDES](http://archivedchaos.com/post/153372061089/kiwicon-2016-slides-upload)
	* [It's Coming From Inside the House: An Inside-Out Approach to NodeJS Application Security - Yolonda Smith(CircleCityCon2019)](https://www.irongeek.com/i.php?page=videos/circlecitycon2019/track-3-05-its-coming-from-inside-the-house-an-inside-out-approach-to-nodejs-application-security-yolonda-smith)
		* Getting application security right often requires that developers have a deeper than average understanding of the security domain. In what other industry is this the case? We don't have to be M.D.s to get a medical diagnosis; we don't have to be auto mechanics to get our cars fixed, yet we in security wag our fingers at "iD10t errors" and build grand mousetraps to catch "so obvious" developer missteps, when they may not know what they need to add, change or remove from their applications to make it "secure" in the first place. Furthermore, patterns to address these issues don't always fit the requirements of the application short or long term, resulting in solutions that only address part of the problem, or worse, are omitted altogether because they are too cumbersome to implement. My answer to this is _spartan-a node application created for developers of node.js applications, not security people. _spartan allows developers to create security policies which address their node app's (whether it be Desktop, Web, Mobile, IoT or API) specific requirements; it installs & configures the modules to match the policy and; it generates the boilerplate code that developers can import directly into their applications.
* **Tools**
	* [faker.js](https://github.com/Marak/faker.js)
		* generate massive amounts of fake data in Node.js and the browser
* **Hidden Property Abuse**
	* [Discovering Hidden Properties to Attack Node js Ecosystem - Feng Xiao(DEFCON Safemode)](https://www.youtube.com/watch?v=oGeEoaplMWA)
		* [BlackHat Slides](https://i.blackhat.com/USA-20/Wednesday/us-20-Xiao-Discovering-Hidden-Properties-To-Attack-Nodejs-Ecosystem.pdf)
		* Node.js is widely used for developing both server-side and desktop applications. It provides a cross-platform execution environment for JavaScript programs. Due to the increasing popularity, the security of Node.js is critical to web servers and desktop clients. We present a novel attack method against the Node.js platform, called hidden property abusing (HPA). The new attack leverages the widely-used data exchanging feature of JavaScript to tamper critical program states of Node.js programs, like server-side applications. HPA entitles remote attackers to launch serious attacks, such as stealing confidential data, bypassing security checks, and launching denial of service attacks. To help developers detect the HPA issues of their Node.js applications, we develop a tool, named LYNX, that utilizes hybrid program analysis to automatically reveal HPA vulnerabilities and even synthesize exploits. We apply LYNX on a set of widely-used Node.js programs and identify 13 previously unknown vulnerabilities. LYNX successfully generates 10 severe exploits. We have reported all of our findings to the Node.js community. At the time of paper writing, we have received the confirmation of 12 vulnerabilities and got 12 CVEs assigned. Moreover, we collaborated with an authoritative public vulnerability database to help them use a new vulnerability notion and description in related security issues. The talk consists of four parts. First, we will introduce recent offensive research on Node.js. Second, we will introduce HPA by demonstrating an exploit on a widely-used web framework. Third, we will explain how to leverage program analysis techniques to automatically detect and exploit HPA. In the end, we will have a comprehensive evaluation which discusses how we identified 13 HPA 0days with the help of our detection method.

----------------
### Platform Agnostic Security Token (PASETO) <a name="paseto"></a>
* **101**
	* [PASETO.io](https://paseto.io)
	* [A Thorough Introduction to PASETO - Randall Degges](https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto)
* **Articles/Blogposts/Writeups**
	* [Paseto is a Secure Alternative to the JOSE Standards (JWT, etc.) - Scott Arciszewski](https://paragonie.com/blog/2018/03/paseto-platform-agnostic-security-tokens-is-secure-alternative-jose-standards-jwt-etc)

--------------
### PHP <a name="php"></a>
* **101**
	* [PHP - Wikipedia](https://en.wikipedia.org/wiki/PHP)
	* [PHP Language Reference - php.net](https://www.php.net/manual/en/langref.php)
	* [PHP Tutorial - Tutorialspoint](https://www.tutorialspoint.com/php/index.htm)
* **Articles/Blogposts/Writeups**
	* [Pwning PHP mail() function For Fun And RCE | New Exploitation Techniques And Vectors](https://exploitbox.io/paper/Pwning-PHP-Mail-Function-For-Fun-And-RCE.html)
	* [The unexpected dangers of preg_replace](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace)
	* [Imagecreatefromgif-Bypass](https://github.com/JohnHoder/Imagecreatefromgif-Bypass)
		* A simple helper script to find byte sequences present in both of 2 given files. The main purpose of this is to find bytes that remain untouched after being processed with imagecreatefromgif() PHP function from GD-LIB. That is the place where a malicious PHP script can be inserted to achieve some nasty RCE.
	* [Is PHP vulnerable and under what conditions?](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
	* [PHP7 Internals - Become a Wizard](https://github.com/0xbigshaq/php7-internals)
		* Welcome to the PHP Internals Hub - If you ever wondered about how PHP works internally and how you can exploit it: this is where you should start. In this repo, I show basic and advanced exploitation in PHP (some of the bugs reported by me). In every "chapter", you'll learn a little bit more about PHP Internals from an infosec perspective.
	* [Modern PHP Security Part 1: bug classes - Thomas Chauchefoin, Lena David(2020)](https://labs.detectify.com/2020/08/13/modern-php-security-part-1-bug-classes/)
	* [Modern PHP Security Part 2: Breaching and hardening the PHP engine - Thomas Chauchefoin, Lena David(2020)](https://labs.detectify.com/2020/08/20/modern-php-security-part-2-breaching-and-hardening-the-php-engine/)
* **Code Reuse**
	* **101**
		* [The ReflectionClass class](https://secure.php.net/ReflectionClass)
		* [Autoloading Classes](http://www.php.net/language.oop5.autoload)
	* **Articles/Blogposts/Writeups**
		* [PHP Autoload Invalid Classname Injection](https://hakre.wordpress.com/2013/02/10/php-autoload-invalid-classname-injection/)
* **Crypto**
	* **101**
	* **Articles/Blogposts/Writeups**
		* [I Forgot Your Password: Randomness Attacks Against PHP Applications - George Argyros, Aggelos Kiayia](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.360.4033&rep=rep1&type=pdf)
			* We provide a number of practical techniques and algorithms for exploiting randomness vulnerabilities in PHP applications.We focus on the predictability of password reset tokens and demonstrate how an attacker can take over user accounts in a web application via predicting or algorithmically derandomizing the PHP core randomness generators. While our techniques are designed for the PHP language, the principles behind our techniques and our algorithms are independent of PHP and can readily apply to any system that utilizes weak randomness generators or low entropy sources. Our results include: algorithms that reduce the entropy of time variables, identifying and exploiting vulnera- bilities of the PHP system that enable the recovery or reconstruction of PRNG seeds, an experimental analysis of the Hastad-Shamir framework for breaking truncated linear variables, an optimized online Gaussian solver for large sparse linear systems, and an algorithm for recovering the state of the Mersenne twister generator from any level of truncation.  We demonstrate the gravity of our attacks via a number of case studies. Specifically, we show that a number of current widely used web applications can be broken using our tech- niques including Mediawiki, Joomla, Gallery, osCommerce and others.
* **De/Serialization**
	* **101**
		* [serialize - php](http://us3.php.net/serialize)
		* [unserialize - php](https://secure.php.net/unserialize)
		* [PHP Object Injection](https://www.owasp.org/index.php/PHP_Object_Injection)
		* [Is PHP unserialize() exploitable without any 'interesting' methods? - StackOverflow](https://security.stackexchange.com/questions/77549/is-php-unserialize-exploitable-without-any-interesting-methods)
	* **Articles/Blogposts/Writeups**
		* [Demystifying Insecure Deserialization in PHP - Sourov Gosh(2020)](https://medium.com/bugbountywriteup/demystifying-insecure-deserialization-in-php-684cab9c4d24)
		* [Writing Exploits For Exotic Bug Classes: unserialize()](https://www.alertlogic.com/blog/writing-exploits-for-exotic-bug-classes-unserialize()/)
		* [Remote code execution via PHP [Unserialize] - notsosecure](https://www.notsosecure.com/remote-code-execution-via-php-unserialize/)
		* [PHP Generic Gadget Chains: Exploiting unserialize in unknown environments](https://www.ambionics.io/blog/php-generic-gadget-chains)
		* [PHPGGC: PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
			* PHPGGC is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically. When encountering an unserialize on a website you don't have the code of, or simply when trying to build an exploit, this tool allows you to generate the payload without having to go through the tedious steps of finding gadgets and combining them. Currently, the tool supports: Doctrine, Guzzle, Laravel, Monolog, Slim, SwiftMailer.
		* [File Operation Induced Unserialization via the "phar://" Stream Wrapper - secarma labs](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf)
		* [PHP Object Injection Cheat Sheet - Lucian Nitescu(2018)](https://nitesculucian.github.io/2018/10/05/php-object-injection-cheat-sheet/)
	* **Talks/Presentations/Videos**
		* [Exploiting PHP7 unserialize - Yannay Livneh (33c3)](https://media.ccc.de/v/33c3-7858-exploiting_php7_unserialize)
			* PHP-7 is a new version of the most prevalent server-side language in use today. Like previous version, this version is also vulnerable to memory corruptions. However, the language has gone through extensive changes and none of previous exploitation techniques are relevant. In this talk, we explore the new memory internals of the language from exploiters and vulnerability researchers point of view. We will explain newly found vulnerabilities in the 'unserialize' mechanism of the language and present re-usable primitives for remote exploitation of these vulnerabilities.
	* **Pictures**
		* [Hacking with Pictures - Syscan2015](http://www.slideshare.net/saumilshah/hacking-with-pictures-syscan-2015)
		* [Exploiting PHP-GD imagecreatefromjpeg() function - fakhrizulkifli](https://github.com/fakhrizulkifli/Defeating-PHP-GD-imagecreatefromjpeg)
			* Proof-of-concept to exploit the flaw in the PHP-GD built-in function, imagecreatefromjpeg(). Inspired by one of Reddit's comment on my previous thread regarding exploiting the imagecreatefromgif() PHP-GD function.
	* **Property-Oriented Programming(POP)**
		* [Code Reuse Attacks in PHP: Automated POP Chain Generation](https://www.syssec.rub.de/media/emma/veroeffentlichungen/2014/09/10/POPChainGeneration-CCS14.pdf)
			* In this paper, we study code reuse attacks in the context of PHP-based web applications. We analyze how PHP object injection (POI) vulnerabilities can be exploited via property-oriented programming (POP) and perform a systematic analysis of available gadgets in common PHP applications. Furthermore, we introduce an automated approach to statically detect POI vulnerabilities in object-oriented PHP code. Our approach is also capable of generating POP chains in an automated way. We implemented a prototype of the proposed approach and evaluated it with 10 well-known applications. Overall, we detected 30 new POI vulnerabilities and 28 new gadget chains
		* [Utilizing Code Reuse/ROP in PHP Application Exploits - BH 2010](https://www.owasp.org/images/9/9e/Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits.pdf)
		* [POP-Exploit](https://github.com/enddo/POP-Exploit)
			* Research into Property Oriented Programming about php applications.
* **Function Injection**
	* [Dynamic Function Injection in PHP - Osanda Malith Jayathissa(2015)](https://osandamalith.com/2015/03/27/dynamic-function-injection-in-php/)
* **Bypassing Disabled Functions**
	* [Bypass of Disabled System Functions - Netsparker](https://www.netsparker.com/blog/web-security/bypass-disabled-system-functions/)
	* [A deep dive into disable_functions bypasses and PHP exploitation - Juan Manuel Fernandez(2020)](https://www.blackarrow.net/disable-functions-bypasses-and-php-exploitation/)
* **Polyglots**
	* [Six files that are also a valid PHP - Caio Luders(2017)](https://medium.com/caio-noobs-around/six-files-that-are-also-a-valid-php-540343ad35c8)
* **String Parsing**
	* [Abusing PHP query string parser to bypass IDS, IPS, and WAF - theMiddle(2019)](https://www.secjuice.com/abusing-php-query-string-parser-bypass-ids-ips-waf/)
		* In this post, we'll see how the PHP query string parser could lead to many IDS/IPS and Application Firewall rules bypass.
* **Type Juggling**
	* **101**
		* [PHP Magic Tricks: Type Juggling](https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf)
		* [PHP’s “Magic Hash” Vulnerability (Or Beware Of Type Juggling)](https://web.archive.org/web/20150530075600/http://blog.astrumfutura.com/2015/05/phps-magic-hash-vulnerability-or-beware-of-type-juggling)
	* **Articles/Blogposts/Writeups**
		* [(Super) Magic Hashes - myst404](https://offsec.almond.consulting/super-magic-hash.html)
			* "TL;DR: Magic hashes are well known specific hashes used to exploit Type Juggling attacks in PHP. Combined with bcrypt limitations, we propose the concept of Super Magic Hashes. These hashes can detect 3 different vulnerabilities: type juggling, weak password storage and incorrect Bcrypt usage. A Go PoC found some MD5, SHA1 and SHA224 super magic hashes."
		* [Writing Exploits For Exotic Bug Classes: PHP Type Juggling](https://turbochaos.blogspot.com.au/2013/08/exploiting-exotic-bugs-php-type-juggling.html)
		* [From hacked client to 0day discovery - infoteam](https://security.infoteam.ch/en/blog/posts/from-hacked-client-to-0day-discovery.html)
			* PHP equivalency check failure writeup
* **Writeups**
	* [Php Codz Hacking](https://github.com/80vul/phpcodz)
		* Writeups of specific PHP vulns
	* [Privilege Escalation in 2.3M WooCommerce Shops - Karim El Ouerghemmi, Slavco Mihajloski](https://blog.ripstech.com/2018/woocommerce-php-object-injection/)
		* During our research we discovered a PHP Object Injection vulnerability in WooCommerce (CVE-2017-18356) that allows to escalate privileges with a unique and interesting injection technique.

----------------
### REST/SOAP/Web Services (WSDL) <a name="rest"></a>
* **Learning/Reference**
	* **101**
		* [Representational State Transfer - Wikipedia](https://en.wikipedia.org/wiki/Representational_state_transfer)
		* [Microservices](https://en.wikipedia.org/wiki/Microservices)
		* [Service-Oriented-Architecture](https://en.wikipedia.org/wiki/Service-oriented_architecture)
		* [The S stands for Simple](http://harmful.cat-v.org/software/xml/soap/simple)
			* Satire(Only it's not) of a conversation about SOAP
	* [RESTful Services, The Web Security Blind Spot](https://www.youtube.com/watch?feature=player_embedded&v=pWq4qGLAZHI#!)
		* [Blogpost](https://xiom.com/2016/10/31/restful-services-web-security-blind-spot/)
		* [Presentation Slides -pdf](https://xiomcom.files.wordpress.com/2016/10/security-testing-for-rest-applications-v6-april-2013.pdf)
	* [Learn REST: A Tutorial](http://rest.elkstein.org/)
	* [REST and Stateless Session IDs](https://appsandsecurity.blogspot.com/2011/04/rest-and-stateless-session-ids.html)	
	* [Beginner’s Guide to API(REST) security](https://introvertmac.wordpress.com/2015/09/09/beginners-guide-to-apirest-security/)
	* [Introduction to RESTful APIs with Chris Wahl](https://www.youtube.com/watch?v=k00sfolsmp0&index=1&list=PL2rC-8e38bUU7Xa5kBaw0Cceo2NoI4mK-)
* **Talks & Presentations**
	* [Cracking and fixing REST services - Bill Sempf - Converge 2015](https://www.irongeek.com/i.php?page=videos/converge2015/track109-cracking-and-fixing-rest-services-bill-sempf)
		* REST, or Representational State Transfer, just refers to the protocol with which the whole Web works. No big. We are used to using REST with a browser, but there is more to it - we can write programs with REST. The problem is that writing properties and functions using the web's transfer protocol open them up to all of the security weaknesses of the web, and we know there are a few of those. Finding those bugs is just half of the battle - fixing them is a whole other story. You'll need the details, and you'll get them here.
	* [Deconstructing REST Security by David Blevins(DevoxxUSA2017)](https://www.youtube.com/watch?v=9CJ_BAeOmW0)
		* With an aggressive distaste for fancy terminology, this session delves into OAuth 2.0 as it pertains to REST and shows how it falls into two camps: stateful and stateless. The presentation also details a competing Amazon-style approach called HTTP Signatures and digs into the architectural differences of all three, with a heavy focus on the wire, showing actual HTTP messages and enough detail to have you thinking, “I could write this myself.”
* **Attacking**
	* [Exploiting CVE-2017-8759: SOAP WSDL Parser Code Injection](https://www.mdsec.co.uk/2017/09/exploiting-cve-2017-8759-soap-wsdl-parser-code-injection/)
	* [Cracking and Fixing REST APIs - Bill Sempf](http://www.sempf.net/post/Cracking-and-Fixing-REST-APIs)
	* [Cracking and fixing REST services - Bill Sempf](http://www.irongeek.com/i.php?page=videos/converge2015/track109-cracking-and-fixing-rest-services-bill-sempf)
* **Tools**
	* [WS-Attacker](https://github.com/RUB-NDS/WS-Attacker)
		* WS-Attacker is a modular framework for web services penetration testing. It is developed by the Chair of Network and Data Security, Ruhr University Bochum (http://nds.rub.de/ ) and the Hackmanit GmbH (http://hackmanit.de/).
	* [Damn Vulnerable Web Services dvws](https://github.com/snoopysecurity/dvws)
		* Damn Vulnerable Web Services is an insecure web application with multiple vulnerable web service components that can be used to learn real world web service vulnerabilities.
	* [WS-Attacks.org](http://www.ws-attacks.org/Welcome_to_WS-Attacks)
		* WS-Attacks.org is not a new web service standard by the OASIS Group or W3C; instead it presents the flaws of today's web service standards and implementations in regard to web service security! WS-Attacks.org aims at delivering the most comprehensive enumeration of all known web service attacks.
	* [Astra](https://github.com/flipkart-incubator/Astra)
		* REST API penetration testing is complex due to continuous changes in existing APIs and newly added APIs. Astra can be used by security engineers or developers as an integral part of their process, so they can detect and patch vulnerabilities early during development cycle. Astra can automatically detect and test login & logout (Authentication API), so it's easy for anyone to integrate this into CICD pipeline. Astra can take API collection as an input so this can also be used for testing apis in standalone mode.
		* [Susanoo](https://github.com/ant4g0nist/Susanoo)
			* Susanoo is a REST API security testing framework.
* **Reference**
	* [Web Services Security Testing Cheat Sheet Introduction - OWASP](https://www.owasp.org/index.php/Web_Service_Security_Testing_Cheat_Sheet)
	* [REST_Assessment_Cheat_Sheet.md - OWASP](https://github.com/OWASP/CheatSheetSeries/blob/3a8134d792528a775142471b1cb14433b4fda3fb/cheatsheets/REST_Assessment_Cheat_Sheet.md)
	* [RESTful API Best Practices and Common Pitfalls - Spencer Schneidenbach](https://medium.com/@schneidenbach/restful-api-best-practices-and-common-pitfalls-7a83ba3763b5)
	* [REST API Testing Strategy: What Exactly Should You Test? - Roy Mor(2019)](https://www.sisense.com/blog/rest-api-testing-strategy-what-exactly-should-you-test/)
	* [RESTful web services penetation testing - ]()
	* [Penetration Testing RESTful Web Services - Prakash Dhatti(2017)](http://blog.isecurion.com/2017/10/10/penetration-testing-restful-web-services/)

----------------
### Ruby/Ruby on Rails <a name="ruby"></a>
* **101**
	* [Ruby on Rails Cheatsheet - OWASP](https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet)
	* [Ruby on Rails Security Guide](http://guides.rubyonrails.org/security.html)
* **Articles/Blogposts/Writeups**
	* [Executing commands in ruby](http://blog.bigbinary.com/2012/10/18/backtick-system-exec-in-ruby.html)
	* [Attacking Ruby on Rails Applications - phrack](http://phrack.org/issues/69/12.html#article)
	* [Going AUTH the Rails on a Crazy Train: A Dive into Rails Authentication and Authorization](https://www.blackhat.com/docs/eu-15/materials/eu-15-Jarmoc-Going-AUTH-The-Rails-On-A-Crazy-Train-wp.pdf)
	* [Property Oriented Programming - Applied to Ruby](https://slides.com/benmurphy/property-oriented-programming/fullscreen#/)
	* [Pentesting Django and Rails](https://es.slideshare.net/levigross/pentesting-django-and-rails)
	* [Executing commands in ruby](http://blog.bigbinary.com/2012/10/18/backtick-system-exec-in-ruby.html)
	* [Execution of shell code in Ruby scripts](https://makandracards.com/makandra/1243-execution-of-shell-code-in-ruby-scripts)
* **Tools**
	* [Brakeman](https://github.com/presidentbeef/brakeman)
		* Brakeman is an open source static analysis tool which checks Ruby on Rails applications for security vulnerabilities.

----------------
### Web Assembly <a name="webasm"></a>
* **101**
	* [Web Assembly](http://webassembly.org/)
	* [WebAssembly Specification](https://webassembly.github.io/spec/core/)
	* [A cartoon intro to WebAssembly Articles](https://hacks.mozilla.org/category/code-cartoons/a-cartoon-intro-to-webassembly/)
	* [Lin Clark: A Cartoon Intro to WebAssembly | JSConf EU 2017](https://www.youtube.com/watch?v=HktWin_LPf4&app=desktop)
	* [WebAssembly Design Documents](https://github.com/WebAssembly/design)
		* This repository contains documents describing the design and high-level overview of WebAssembly.
	* [WebAssembly - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/WebAssembly)
* **Articles/Papers/Talks/Writeups**
	* [WebAssembly security: potentials and pitfalls - John Bergbom](https://www.forcepoint.com/blog/x-labs/webassembly-potentials-and-pitfalls)
	* [WebAssembly cut Figma's load time by 3x - Evan Wallace](https://www.figma.com/blog/webassembly-cut-figmas-load-time-by-3x/)
	* [Coding a WebAssembly CTF Challenge - Jacob Baines](https://medium.com/tenable-techblog/coding-a-webassembly-ctf-challenge-5560576e9cb7)
* **Papers**
	* [Security Chasms of WASM - Brian McFadden, Tyler Lukasiewicz, Jeff Dileo, Justin Engler(2018)](https://i.blackhat.com/us-18/Thu-August-9/us-18-Lukasiewicz-WebAssembly-A-New-World-of-Native_Exploits-On-The-Web-wp.pdf)
		* WebAssembly is a new technology that allows web developers to run native C/C++on a webpage with near-native performance. This paper provides a basic introduc-tiontoWebAssemblyandexaminesthesecurityrisksthatadevelopermaytakeonbyusing it. We cover several examples exploring the theoretical security implications ofWebAssembly. We also cover Emscripten, which is currently the most popular Web-Assembly compiler toolchain. Our assessment of Emscripten includes its implemen-tation of compiler-and-linker-level exploit mitigations as well as the internal harden-ing of itslibcimplementation, and how its augmentation of WASM introduces newattack vectors and methods of exploitation. We also provide examples of memorycorruption exploits in the Wasm environment. Under certain circumstances, theseexploits could lead to to hijacking control flow or even executing arbitrary JavaScriptwithin the context of the web page. Finally, we provide a basic outline of best prac-tices and security considerations for developers wishing to integrate WebAssemblyinto their product.
	* [Everything Old is New Again:Binary Security of WebAssembly - Daniel Lehmann, Johannes Kinder, Michael Pradel(2020)](https://www.usenix.org/system/files/sec20-lehmann.pdf)
		* WebAssembly is an increasingly popular compilation targetdesigned to run code in browsers and on other platforms safelyand securely, by strictly separating code and data, enforcingtypes, and limiting indirect control flow. Still, vulnerabilitiesin memory-unsafe source languages can translate to vulnera-bilities in WebAssembly binaries. In this paper, we analyze towhat extent vulnerabilities are exploitable in WebAssemblybinaries, and how this compares to native code. We find thatmany classic vulnerabilities which, due to common mitiga-tions, are no longer exploitable in native binaries, are com-pletely exposed in WebAssembly. Moreover, WebAssemblyenables unique attacks, such as overwriting supposedly con-stant data or manipulating the heap using a stack overflow. Wepresent a set of attack primitives that enable an attacker (i) towrite arbitrary memory, (ii) to overwrite sensitive data, and(iii) to trigger unexpected behavior by diverting control flowor manipulating the host environment. We provide a set ofvulnerable proof-of-concept applications along with completeend-to-end exploits, which cover three WebAssembly plat-forms. An empirical risk assessment on real-world binariesand SPEC CPU programs compiled to WebAssembly showsthat our attack primitives are likely to be feasible in practice.Overall, our findings show a perhaps surprising lack of binarysecurity in WebAssembly. We discuss potential protectionmechanisms to mitigate the resulting risks.
* **Tools**
	* [WebAssembly for .NET](https://github.com/RyanLamansky/dotnet-webassembly)
		* A library able to create, read, modify, write and execute WebAssembly (WASM) files from .NET-based applications. Execution does not use an interpreter. WASM instructions are mapped to their .NET equivalents and converted to native machine language by the .NET JIT compiler.
	* [octopus](https://github.com/pventuzelo/octopus)
		* Security Analysis tool for WebAssembly module (wasm) and Blockchain Smart Contracts (BTC/ETH/NEO/EOS)
* **Reversing**
	* [Web-(Dis)Assembly - Christophe Alladoum - Shakacon X](https://github.com/sophos/WebAssembly/blob/master/Misc/Web-(Dis)Assembly.pdf)
	* [Analyzing WebAssembly binaries: initial feel and behavioral analysis - John Bergbom](https://www.forcepoint.com/blog/x-labs/analyzing-webassembly-binaries-initial-feel-and-behavioral-analysis)
	* [Analyzing WebAssembly binaries - Wasm Reverse Engineering - John Bergbom](https://www.forcepoint.com/blog/x-labs/analyzing-webassembly-binaries)
	* [Manual reverse engineering of WebAssembly: static code analysis - John Bergbom](https://www.forcepoint.com/blog/security-labs/manual-reverse-engineering-webassembly-static-code-analysis)

----------------
### Secure Sockets Layer / Transport Layer Security <a name="ssltls"></a>
* **101**
* **Articles/Blogposts/Writeups**
	* [Downgrade Attack on TLS 1.3 and Vulnerabilities in Major TLS Libraries - David Wong](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/february/downgrade-attack-on-tls-1.3-and-vulnerabilities-in-major-tls-libraries/)

----------------
### Single Sign-On (SSO) <a name="sso"></a>
* **101**
* **Articles/Blogposts/Writeups**
* **Talks & Presentations**
	* [SSO Wars: The Token Menace - Alvaro Munoz, Oleksandr Mirosh]()
		* [Slides](https://i.blackhat.com/USA-19/Wednesday/us-19-Munoz-SSO-Wars-The-Token-Menace.pdf)
* **Dupe Key Confusion**
	* attack to bypass XML signature verification by sending multiple key identifiers in the KeyInfo section. Vulnerable systems will use the first one to verify the XML signature and the second one to verify the trust on the signing party. This plugin applies this technique to SAML tokens by allowing to modify and then resign the SAML assertion with an arbitrary attacker-controlled key which is then send as the first element of the KeyInfo section, while the original key identifier is sent as the second key identifier.
	* **Tools**
		* [DupeKeyInjector](https://github.com/pwntester/DupeKeyInjector)
			* Dupe Key Injetctor is a Burp Suite extension implementing Dupe Key Confusion, a new XML signature bypass technique presented at BSides/BlackHat/DEFCON 2019 "SSO Wars: The Token Menace" presentation.
			* [Slides](https://github.com/pwntester/DupeKeyInjector/blob/master/resources/slides.pdf)
			* [Paper](https://github.com/pwntester/DupeKeyInjector/blob/master/resources/whitepaper.pdf)

----------------
### Web Application Firewalls (WAFs) <a name="waf"></a>
* **101**
	* [Awesome WAF](https://github.com/0xInfection/Awesome-WAF)
		* 🔥 Everything awesome about web-application firewalls (WAF).
* **Web Application Firewalls**
	* [ModSecurity](https://github.com/SpiderLabs/ModSecurity)
		* ModSecurity is an open source, cross platform web application firewall (WAF) engine for Apache, IIS and Nginx that is developed by Trustwave's SpiderLabs. It has a robust event-based programming language which provides protection from a range of attacks against web applications and allows for HTTP traffic monitoring, logging and real-time analys
	* [Shadow Daemon](https://shadowd.zecure.org/overview/introduction/)
		* Shadow Daemon is a collection of tools to detect, protocol and prevent attacks on web applications. Technically speaking, Shadow Daemon is a web application firewall that intercepts requests and filters out malicious parameters. It is a modular system that separates web application, analysis and interface to increase security, flexibility and expandability. Shadow Daemon is free software. It is released under the license GPLv2, so its source code can be examined, modified and distributed by everyone.
* **Articles/Blogposts/Writeups**
	* [Bypassing WAFs](http://www.nethemba.com/bypassing-waf.pdf)
	* [WAF Bypass Cheatsheet/gitbook](https://chybeta.gitbooks.io/waf-bypass/content/)
	* [Web Application Firewall (WAF) Evasion Techniques - theMiddle](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8)
	* [Web Application Firewall (WAF) Evasion Techniques #2 - theMiddle](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)
	* [Web Application Firewall (WAF) Evasion Techniques - secjuice](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8)
	* [Bypassing Web-Application Firewalls by abusing SSL/TLS - 0x09AL](https://0x09al.github.io/waf/bypass/ssl/2018/07/02/web-application-firewall-bypass.html)
	* [Request encoding to bypass web application firewalls - NCCGroup](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/august/request-encoding-to-bypass-web-application-firewalls/)
	* [Bypassing Web-Application Firewalls by abusing SSL/TLS - 0x09AL](https://0x09al.github.io/waf/bypass/ssl/2018/07/02/web-application-firewall-bypass.html)
	* [WAF bypass techniques - Pentestit(2019)](https://medium.com/@Pentestit_ru/bypassing-waf-4cfa1aad16bf)
	* [A Pentesters Guide - Part 5 (Unmasking WAFs and Finding the Source) - pyr0cc](https://delta.navisec.io/a-pentesters-guide-part-5-unmasking-wafs-and-finding-the-source/)
	* [WAF Bypassing with Unicode Compatibility - Jorge Lajara(2020)](https://jlajara.gitlab.io/web/2020/02/19/Bypass_WAF_Unicode.html)
* **Talks & Presentations**
	* [HTTP Invisibility Cloak by Soroush Dalili - SteelCon2017](https://www.youtube.com/watch?reload=9&v=sHEv_EoQJwc)
		* This talk illustrates a number of techniques to smuggle and reshape HTTP requests using features such as HTTP Pipelining that are not normally used by testers. The strange behaviour of web servers with different technologies will be reviewed using HTTP versions 1.1, 1.0, and 0.9 before HTTP v2 becomes too popular! Some of these techniques might come in handy when dealing with a dumb WAF or load balancer that blocks your attacks.
	* [Web Application Firewall Profiling and Evasion - Michael Ritter](https://owasp.org/www-pdf-archive/OWASP_Stammtisch_Frankfurt_WAF_Profiling_and_Evasion.pdf)
	* [Let's Talk About WAF (Bypass) Baby - Brett Gravois(NolaCon2019)](https://www.irongeek.com/i.php?page=videos/nolacon2019/nolacon-2019-c-10-lets-talk-about-waf-bypass-baby-brett-gravois)
		* All modern Web Application Firewalls are able to intercept (and even block) most common attacks from the web. However, what happens when an attacker uses HTTP2 to send attack traffic to a web application or service? In this talk we will cover basic attacks against web applications using HTTP2 to bypass WAFs and Proxies. Attendees will gain knowledge of how to bypass WAF and Proxies using the HTTP2 Protocol, and steps they can take to protect themselves against these kinds of attacks.
* **Tools**
	* [WhatWaf](https://github.com/Ekultek/WhatWaf)
		* WhatWaf is an advanced firewall detection tool who's goal is to give you the idea of "There's a WAF?". WhatWaf works by detecting a firewall on a web application, and attempting to detect a bypass (or two) for said firewall, on the specified target.
	* [WAFPASS](https://github.com/wafpassproject/wafpass)
		* Analysing parameters with all payloads' bypass methods, aiming at benchmarking security solutions like WAF.
	* [WAF_buster](https://github.com/viperbluff/WAF_buster/blob/master/README.md)
	* [LightBulb](https://github.com/PortSwigger/lightbulb-framework)
		* LightBulb is an open source python framework for auditing web application firewalls and filters.
	* [WAFNinja](https://github.com/khalilbijjou/WAFNinja)
		* WAFNinja is a tool which contains two functions to attack Web Application Firewalls.
	* [Web Application Firewall Profiling and Evasion - Michael Ritter - OWASP](https://www.owasp.org/images/b/bf/OWASP_Stammtisch_Frankfurt_WAF_Profiling_and_Evasion.pdf)
	* [Guide To Identifying And Bypassing WAFs](https://www.sunnyhoi.com/guide-identifying-bypassing-wafs/)
	* [ftw](https://github.com/fastly/ftw)
		* Framework for Testing WAFs (FTW!)
	* [wafw00f](https://github.com/EnableSecurity/wafw00f)
		*  WAFW00F allows one to identify and fingerprint Web Application Firewall (WAF) products protecting a website.

----------------
### JS Frameworks <a name="webframeworks"></a>
* **101**
* **Articles/Blogposts/Writeups**
	* [JSMVCOMFG - To sternly look at JavaScript MVC and Templating Frameworks - Mario Heiderich](https://www.youtube.com/watch?v=SLH_IgaQWjs)
		* [Slides](https://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks)
	* [JavaScript Template Attacks](https://github.com/IAIK/jstemplate)
* **Specific Frameworks**
	* **Angular**
		* [AngularJS Security Documentation](https://docs.angularjs.org/guide/security)
		* [Adapting AngularJS payloads to exploit real world applications - Gareth Heyes](https://portswigger.net/research/adapting-angularjs-payloads-to-exploit-real-world-applications)
		* [Angular and AngularJS for Pentesters - Part 1 - Alex Useche(2019)](https://blog.nvisium.com/angular-for-pentesters-part-1)
			* [Part 2](https://blog.nvisium.com/angular-for-pentesters-part-2)
	* **Apache Struts**
		* [Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution](https://www.exploit-db.com/exploits/41570/)
	* **ASP.NET**
		* [Getting Shell with XAMLX Files - Soroush Dalili](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/august/getting-shell-with-xamlx-files/)
		* [ASP.NET resource files (.RESX) and deserialisation issues - Soroush Dalili](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/)
		* [Uploading web.config for Fun and Profit 2 - Soroush Dalili](https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/)
		* [Technical Advisory: Bypassing Microsoft XOML Workflows Protection Mechanisms using Deserialisation of Untrusted Data - Soroush Dalili](https://www.nccgroup.trust/uk/our-research/technical-advisory-bypassing-microsoft-xoml-workflows-protection-mechanisms-using-deserialisation-of-untrusted-data/)
		* [XAML overview in WPF - docs.ms](https://docs.microsoft.com/en-us/dotnet/desktop-wpf/fundamentals/xaml)
		* [Rare ASP.NET request validation bypass using request encoding - nccgroup](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/september/rare-aspnet-request-validation-bypass-using-request-encoding/)
		* [Understanding ASP.NET View State - docs.ms](https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/ms972976(v=msdn.10))
		* [viewstate](https://github.com/yuvadm/viewstate)
			* A small Python 3.5+ library for decoding ASP.NET viewstate.
		* [viewgen](https://github.com/0xACB/viewgen)
			* viewgen is a ViewState tool capable of generating both signed and encrypted payloads with leaked validation keys
		* [RCEvil.NET](https://github.com/Illuminopi/RCEvil.NET)
			* RCEvil.NET is a tool for signing malicious ViewStates with a known validationKey. Any (even empty) ASPX page is a valid target. See http://illuminopi.com/ for full details on the attack vector.
	* **Backbone.js**
	* **Ember.js**
	* **Flask**
		* See [SSI/Template Injection](#ssti)
		* [Injecting Flask - Ryan Reid](https://nvisium.com/blog/2015/12/07/injecting-flask/)
			* In this adventure we will discuss some of the security features available and potential issues within the [Flask micro-framework](http://flask.pocoo.org/docs/0.10/) with respect to Server-Side Template Injection, Cross-Site Scripting, and HTML attribute injection attacks, a subset of XSS. If you’ve never had the pleasure of working with Flask, you’re in for a treat. Flask is a lightweight python framework that provides a simple yet powerful and extensible structure (it is [Python](https://xkcd.com/353/) after all).
	* **MeteorJS**
		* [Hacking Meteor Applications - Remi Testa(2017)](https://medium.com/@funkyremi/hacking-meteor-applications-1c4b326e6cdc)
		* [Pentesting Meteor Applications with Burp Suite - sean(2019)](https://www.gremwell.com/blog/pentesting-meteor-applications-with-burp-suite)
		* [Wekan Authentication Bypass – Exploiting Common Pitfalls of MeteorJS - Dejan Zelic(2020)](https://www.offensive-security.com/offsec/wekan-authentication-bypass/)
	* **mustache.js**
		* [mustache-security(2013)](https://code.google.com/archive/p/mustache-security/)
			* This place will host a collection of security tips and tricks for JavaScript MVC frameworks and templating libraries.
			* [Wikis](https://code.google.com/archive/p/mustache-security/wikis)
	* **ReactJS**
		* [Exploiting Script Injection Flaws in ReactJS Apps](https://medium.com/dailyjs/exploiting-script-injection-flaws-in-reactjs-883fb1fe36c1)
		* [Javascript for bug bounty hunters(part 1) — Ahmed Ezzat (BitTheByte)](https://medium.com/@bitthebyte/javascript-for-bug-bounty-hunters-part-1-dd08ed34b5a8)
			* [Part 2](https://medium.com/@bitthebyte/javascript-for-bug-bounty-hunters-part-2-f82164917e7)
	* **Spring**
		* [How Spring Web MVC Really Works - Stackify.com](https://stackify.com/spring-mvc/)
	* **Vue.js**

----------------
### Web Proxies <a name="webproxy"></a>
* **101**
* **Articles/Blogposts/Writeups**
	* [Utilizing Reverse Proxies to Inject Malicious Code & Extract Sensitive Information - James Sibley](https://versprite.com/blog/application-security/reverse-proxy-attack/)
* **Tools**
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
	* [ratproxy](https://github.com/wallin/ratproxy)
		* Ratproxy is a semi-automated, largely passive web application security audit  tool. It is meant to complement active crawlers and manual proxies more  commonly used for this task, and is optimized specifically for an accurate and  sensitive detection, and automatic annotation, of potential problems and  security-relevant design patterns based on the observation of existing,  user-initiated traffic in complex web 2.0 environments.

----------------
### Web Servers <a name="webservers"></a>
* **Apache**
* **IIS**
* **Jetty**
	* [Making Jetty Bleed - Stephen Haywood](https://www.appsecconsulting.com/blog/making-jetty-bleed)
	* [JetLeak Vulnerability: Remote Leakage Of Shared Buffers In Jetty Web Server [CVE-2015-2080] - Stephen Komal](https://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html)
* **NGINX**

----------------
### Web Storage <a name="webstorage"></a>
* **101**
	* [Web storage - Wikipedia](https://en.wikipedia.org/wiki/Web_storage)
	* [Web Storage API - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API)
	* [HTML5 - Web Storage - TutorialsPoint](https://www.tutorialspoint.com/html5/html5_web_storage.htm)
* **Articles/Blogposts/Writeups**
	* [Please Stop Using Local Storage - Randall Degges(2018)](https://www.rdegges.com/2018/please-stop-using-local-storage/)

----------------
## Tactics & Techniques <a name="tt"></a>
* **Attacking** <a name="ttatk"></a>
	* [OWASP Web Application Security Testing Cheat Sheet](https://cheatsheetseries.owasp.org/)
	* [Web Application testing approach and cheating to win Jim McMurry Lee Neely Chelle Clements - Derbycon7](https://www.youtube.com/watch?v=Z8ZAv_EN-9M)
	* [Attacking Modern SaaS Companies](https://github.com/cxxr/talks/blob/master/2017/nolacon/Attacking%20Modern%20SaaS%20Companies%20%E2%80%93%20NolaCon.pdf)
		* [Presentation](https://www.youtube.com/watch?v=J0otoKRh1Vk&app=desktop)
* **Securing** <a name="ttsec"></a>
	* See [Defense](Defense.md)
* **Guides & Methodologies** <a name="ttgm"></a>
	* [OWASP Testing Checklist](https://www.owasp.org/index.php/Testing_Checklist)
	* [WebAppSec Testing Checklist](http://tuppad.com/blog/wp-content/uploads/2012/03/WebApp_Sec_Testing_Checklist.pdf)
	* [OWASP Testing Checklist(OTGv4)](https://github.com/tanprathan/OWASP-Testing-Checklist)
		* OWASP based Web Application Security Testing Checklist is an Excel based checklist which helps you to track the status of completed and pending test cases. This checklist is completely based on OWASP Testing Guide v 4. The OWASP Testing Guide includes a “best practice” penetration testing framework which users can implement in their own organizations and a “low level” penetration testing guide that describes techniques for testing most common web application security issues. Moreover, the checklist also contains OWASP Risk Assessment Calculator and Summary Findings template.
	* [LTR101: Web App Testing - Methods to The Madness - Andy Gill](https://blog.zsec.uk/ltr101-method-to-madness/)
	* [LTR101: Web Application Testing Methodologies - Andy Gill](https://blog.zsec.uk/ltr101-methodologies/)
	* [The Bug Hunter’s Methodology - Jason Haddix @jhaddix(Defcon Safemode RedTeamVillage 2020)](https://www.youtube.com/watch?v=gIz_yn0Uvb8)
		* The Bug Hunter’s Methodology is an ongoing yearly installment on the newest tools and techniques for bug hunters and red teamers. This version explores both common and lesser-known techniques to find assets for a target. The topics discussed will look at finding a targets main seed domains, subdomains, IP space, and discuss cutting edge tools and automation for each topic. By the end of this session a bug hunter or red team we will be able to discover and multiply their attack surface. We also discuss several vulnerabilities and misconfigurations related to the recon phase of assessment.
* **Testing Writeups** <a name="ttw"></a>
	* [Video Testing stateful web application workflows - András Veres-Szentkirályi](https://www.youtube.com/watch?v=xiTFKigyncg)
	* [Paper Testing stateful web application workflows - SANS - András Veres-Szentkirályi](https://www.sans.org/reading-room/whitepapers/testing/testing-stateful-web-application-workflows-36637)
		* Most web applications used for complex business operations and/or employing advanced GUI frameworks have stateful functionality. Certain workflows, for example, might require completing certain steps before a transaction is committed, or a request sent by a client-side UI element might need several preceding requests that all contribute to the session state. Most automated tools focus on a request and maybe a redirection, thus completely missing the point in these cases, where resending a request gets ignored by the target application. As a result, while these tools are getting better day by day, using them for testing such execution paths are usually out of the question. Since thorough assessment is cumbersome without such tools, there's progress, but we are far from plug-and-play products. This paper focuses on the capabilities of currently available solutions, demonstrating their pros and cons, along with opportunities for improvement.
* **Payloads** <a name="ttpay"></a>
	* [Seclists](https://github.com/danielmiessler/SecLists)
	* [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
	* [weapons4pentester](https://github.com/merttasci/weapons4pentester)
* **Tactics** <a name="ttt"></a>
	* [Using HTTP Pipelining to hide requests - digi.ninja](https://digi.ninja/blog/pipelining.php)
	* [Advanced web security topics - george georgovassilis(2020)](https://blog.georgovassilis.com/2016/04/16/advanced-web-security-topics/)
	* [Backslash Powered Scanning: Hunting Unknown Vulnerability Classes](http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html)
		* Existing web scanners search for server-side injection vulnerabilities by throwing a canned list of technology-specific payloads at a target and looking for signatures - almost like an anti-virus. In this document, I'll share the conception and development of an alternative approach, capable of finding and confirming both known and unknown classes of injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering.
	* **Out-of-Band Attacks**
		* [Out of Band Exploitation (OOB) CheatSheet - Ajay, Ashwin(2018)](https://notsosecure.com/oob-exploitation-cheatsheet/)
		* [Out-of-Band (OOB) SQL Injection - Lee Chun How(2019)](https://medium.com/bugbountywriteup/out-of-band-oob-sql-injection-87b7c666548b)
		* [Out-of-band Attacks [EN] - omercitak.com(2019)](https://omercitak.com/out-of-band-attacks-en/)
* **General Reconnaissance Techniques** <a name="ttgrt"></a>
	* **General Articles/Methodology Writeups** <a name="gamw"></a>
		* [Just another Recon Guide for Pentesters and Bug Bounty Hunters - @slashcrypto(2020)](https://www.offensity.com/de/blog/just-another-recon-guide-pentesters-and-bug-bounty-hunters/)
		* [Turbo Intruder: Embracing the billion-request attack - James Kettle(2020)](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
		* [Bug Bounty Methodology... Just Have a Look.! - Naveenroy(2020)](https://medium.com/@naveenroy008/bug-bounty-methodology-just-have-a-look-b3e7c4b6922)
		* [ReconNotes - bminossi](https://github.com/bminossi/ReconNotes)
	* **Tools that didn't fit elsewhere** <a name="ttdfe"></a>
		* [webgrep](https://github.com/dhondta/webgrep)
			* This self-contained tool relies on the well-known grep tool for grepping Web pages. It binds nearly every option of the original tool and also provides additional features like deobfuscating Javascript or appyling OCR on images before grepping downloaded resources.
	* **(Almost)Fully Automating Recon** <a name="ttafar"></a>
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
			* [Mechanizing the Methodology : Automating Discovery, Testing, and Alerting using Recon/Testing Tools and Amazon SES - Daniel Miessler(Defcon Safemode RTV2020)](https://www.youtube.com/watch?v=URBnM6gGODo)
				* There are a million techniques out there for finding new attack surface and finding potential vulnerabilities; the problem is finding the time to run your entire methodology against all your targets. This talk will take you through finding new attack surface, performing multiple types of test against those targets, and sending real-time alerts---all on a continuous basis using automation from a cloud-based Linux host.
				* [Writeup/Review by Clint Gibler(recommend reading)](https://tldrsec.com/blog/mechanizing-the-methodology/)
		* **Tools**
			* [chomp-scan](https://github.com/SolomonSklash/chomp-scan)
				* A scripted pipeline of tools to simplify the bug bounty/penetration test reconnaissance phase, so you can focus on chomping bugs.
	* **Attack Surface Reconaissance** <a name="ttasr"></a>
		* **Articles/Blogposts/Writeups**
			* [Asset Enumeration: Expanding a Target's Attack Surface - Capt. Meelo](https://captmeelo.com/bugbounty/2019/09/02/asset-enumeration.html)
			* [ What's in a Domain Name? - Collin Meadows(SecureWV/Hack3rcon2018)](https://www.irongeek.com/i.php?page=videos/securewv-hack3rcon2018/speaker-16-whats-in-a-domain-name-collin-meadows)
				* The domain name is one of the most prominent assets an organization can have. While customers can discover an organization from many sources - social media, review aggregators, advertisements, etc - the webpage is often the first direct experience a person has with a business and brand. This vital role makes the domain a target for fraud, data leakage, and cyber attack. Implementing domain monitoring and performing risk assessments is important, but only half the battle. In this talk, we will consider amount of intelligence one can gather starting from only a domain name and investigate how this sets an attacker up with an ideal blueprint for malicious action.
		* **Tools**
			* [AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper)
				* Attack Surface Mapper is a reconnaissance tool that uses a mixture of open source intellgence and active techniques to expand the attack surface of your target. You feed in a mixture of one or more domains, subdomains and IP addresses and it uses numerous techniques to find more targets. It enumerates subdomains with bruteforcing and passive lookups, Other IPs of the same network block owner, IPs that have multiple domain names pointing to them and so on. Once the target list is fully expanded it performs passive reconnaissance on them, taking screenshots of websites, generating visual maps, looking up credentials in public breaches, passive port scanning with Shodan and scraping employees from LinkedIn.
			* [intrigue-core](https://github.com/intrigueio/intrigue-core)
				* Intrigue-core is a framework for external attack surface discovery and automated OSINT.
			* [Domain Analyzer](https://github.com/eldraco/domain_analyzer)
				* Domain analyzer is a security analysis tool which automatically discovers and reports information about the given domain. Its main purpose is to analyze domains in an unattended way.
			* [domain-profiler](https://github.com/jpf/domain-profiler)
				* domain-profiler is a tool that uses information from various sources (Whois, DNS, SSL, ASN) to determine what decisions have been made regarding a domain or list of domains.
			* [The Hamburglar](https://github.com/needmorecowbell/Hamburglar)
				* Hamburglar -- collect useful information from urls, directories, and files
			* [AutoRecon](https://github.com/JoshuaMart/AutoRecon)
				* Simple shell script for automated domain recognition with some tools
				* [AutoRecon for Automated Reconnaissance - Ahmed Elsobky](https://github.com/0xsobky/HackVault/wiki/AutoRecon-for-Automated-Reconnaissance)
			* [Websy](https://github.com/0xrishabh/websy)
				* Keep an eye on your targets with Websy to get quickly notified for any change they push on their Web Server
			* [BlueEye](https://github.com/BullsEye0/blue_eye)
				* Blue Eye is a python Recon Toolkit script. It shows subdomain resolves to the IP addresses, company email addresses and much more ..!
	* **Browser Automation** <a name="ttbo"></a>
		* [playwright](https://github.com/microsoft/playwright)
			* Node.js library to automate Chromium, Firefox and WebKit with a single API
	* **DNS** <a name="ttdns"></a>
		* See [Network_Attacks.md](#./)
	* **Enpdoint Discovery** <a name="tted"></a>
		* **Articles/Blogposts/Writeups**
			* [Scanning JS Files for Endpoints and Secrets - securityjunky.com](https://securityjunky.com/scanning-js-files-for-endpoint-and-secrets/)
		* **Tools**
			* [JSParser](https://github.com/nahamsec/JSParser)
				* A python 2.7 script using Tornado and JSBeautifier to parse relative URLs from JavaScript files. Useful for easily discovering AJAX requests when performing security research or bug bounty hunting.
			* [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
				* LinkFinder is a python script written to discover endpoints and their parameters in JavaScript files. This way penetration testers and bug hunters are able to gather new, hidden endpoints on the websites they are testing. Resulting in new testing ground, possibility containing new vulnerabilities. It does so by using [jsbeautifier](https://github.com/beautify-web/js-beautify) for python in combination with a fairly large regular expression.
			* [relative-url-extractor](https://github.com/jobertabma/relative-url-extractor)
				* During reconnaissance (recon) it is often helpful to get a quick overview of all the relative endpoints in a file. These days web applications have frontend pipelines that make it harder for humans to understand minified code. This tool contains a nifty regular expression to find and extract the relative URLs in such files. This can help surface new targets for security researchers to look at. It can also be used to periodically compare the results of the same file, to see which new endpoints have been deployed. History has shown that this is a goldmine for bug bounty hunters.
			* [hakrawler](https://github.com/hakluke/hakrawler)
				* Simple, fast web crawler designed for easy, quick discovery of endpoints and assets within a web application
				* [Introducing Hakrawler: A Fast Web Crawler for Hackers - Luke Stephens(2020)](https://medium.com/@hakluke/introducing-hakrawler-a-fast-web-crawler-for-hackers-ff799955f134)
			* [endpointdiff](https://github.com/ameenmaali/endpointdiff)
				* endpointdiff is a simple wrapper script around LinkFinder (https://github.com/GerbenJavado/LinkFinder) to quickly identify whether endpoints have changed based on diffs of JS files.
	* **Forced Browsing** <a name="ttfb"></a>
		* **Articles/Blogposts/Writeups**
			* [Turbo Intruder: Embracing the billion-request attack - James Kettle](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
		* **Tools**
			* [Dirbuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
				* DirBuster is a multi threaded java application designed to brute force directories and files names on web/application servers. Often is the case now of what looks like a web server in a state of default installation is actually not, and has pages and applications hidden within. DirBuster attempts to find these.
			* [Go Buster](https://github.com/OJ/gobuster)
				* Directory/file busting tool written in Go; Recursive, CLI-based, no java runtime
			* [WFuzz](https://code.google.com/p/wfuzz/)
				* Wfuzz is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked (directories, servlets, scripts, etc), bruteforce GET and POST parameters for checking different kind of injections (SQL, XSS, LDAP,etc), bruteforce Forms parameters (User/Password), Fuzzing,etc
			* [dirsearch](https://github.com/maurosoria/dirsearch)
				* dirsearch is a simple command line tool designed to brute force directories and files in websites.
			* [ffuf](https://github.com/ffuf/ffuf)
				* Fast web fuzzer written in Go
				* [Everything you need to know about FFUF - codingo(2020)](https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html)
				* [ffuf on Steroids - securityjunky.com](https://securityjunky.com/ffuf-on-steroids/)
			* [Tachyon](https://github.com/delvelabs/tachyon)
				* Tachyon is a Fast Multi-Threaded Web Discovery Tool
			* [Syntribos](https://github.com/openstack/syntribos)
				* Given a simple configuration file and an example HTTP request, syntribos can replace any API URL, URL parameter, HTTP header and request body field with a given set of strings. Syntribos iterates through each position in the request automatically. Syntribos aims to automatically detect common security defects such as SQL injection, LDAP injection, buffer overflow, etc. In addition, syntribos can be used to help identify new security defects by automated fuzzing.
			* [OpenDoor](https://github.com/stanislav-web/OpenDoor)
				* OpenDoor OWASP is console multifunctional web sites scanner. This application find all possible ways to login, index of/ directories, web shells, restricted access points, subdomains, hidden data and large backups. The scanning is performed by the built-in dictionary and external dictionaries as well. Anonymity and speed are provided by means of using proxy servers.
			* [rustbuster](https://github.com/phra/rustbuster)
				* A Comprehensive Web Fuzzer and Content Discovery Tool
			* [feroxbuster](https://github.com/epi052/feroxbuster)
				*  A fast, simple, recursive content discovery tool written in Rust.
			* [SharpBuster](https://github.com/passthehashbrowns/SharpBuster)
				*  SharpBuster is a C# implementation of a directory brute forcing tool. It's designed to be used via Cobalt Strike's execute-assembly and similar tools, when running a similar tool over a SOCKS proxy is not feasible.
			* [FES - Fast Endpoint Scanner](https://github.com/JohnWoodman/FES)
				* A web application endpoint scanner written in Rust, designed to put less load on the domains it scans with parsing features to help grab the important stuff (inspired by tomnomnom's meg).
			* [WAES](https://github.com/Shiva108/WAES)
				* CPH:SEC WAES: Web Auto Enum & Scanner - Auto enums website(s) and dumps files as result
			* [crithit](https://github.com/codingo/crithit)
				* Website Directory and file brute forcing at extreme scale.
			* [snallygaster](https://github.com/hannob/snallygaster)
				* Finds file leaks and other security problems on HTTP servers.
	* **HTTP Enumeration** <a name="tthe"></a>
		* **Articles/Blogposts/Writeups**
			* [Insecure HTTP Header Removal](https://www.aspectsecurity.com/blog/insecure-http-header-removal)
		* **Tools**
			* [Arjun](https://github.com/s0md3v/Arjun)
				* HTTP parameter discovery suite.
			* [Psi-Probe](https://github.com/psi-probe/psi-probe)
				* Advanced manager and monitor for Apache Tomcat, forked from Lambda Probe
			* [HTTPLeaks](https://github.com/cure53/HTTPLeaks)
				* HTTPLeaks - All possible ways, a website can leak HTTP requests
			* [HTTPie - curl for humans](https://gith*ub.com/jakubroztocil/httpie)
				* HTTPie (pronounced aych-tee-tee-pie) is a command line HTTP client. Its goal is to make CLI interaction with web services as human-friendly as possible. It provides a simple http command that allows for sending arbitrary HTTP requests using a simple and natural syntax, and displays colorized output. HTTPie can be used for testing, debugging, and generally interacting with HTTP servers.
			* [gethead](https://github.com/httphacker/gethead)
				* HTTP Header Analysis Vulnerability Tool
	* **HTTP Fingerprinting** <a name="tthf"></a>
		* **Articles/Blogposts/Writeups**
			* [An Introduction to HTTP fingerprinting - Saumil Shah](http://www.net-square.com/httprint_paper.html)
			* [Web Application Finger Printing - Anant Shrivastava](http://anantshri.info/articles/web_app_finger_printing.html)
		* **Tools**
			* [GoFingerprint](https://github.com/Static-Flow/gofingerprint)
				* GoFingerprint is a Go tool for taking a list of target web servers and matching their HTTP responses against a user defined list of fingerprints.
	* **JS-based scanning** <a name="ttjs"></a>
		* **Articles/Blogposts/Writeups**
			* [Exposing Intranets with reliable Browser-based Port scanning - Gareth Heyes](https://portswigger.net/blog/exposing-intranets-with-reliable-browser-based-port-scanning)
				* In this blog post I describe how I created a port scanner using JavaScript.
		* **Tools**
			* [lan-js](https://github.com/jvennix-r7/lan-js)
				* Probe LAN devices from a web browser.
			* [sonar.js](https://thehackerblog.com/sonar-a-framework-for-scanning-and-exploiting-internal-hosts-with-a-webpage/)
				* A Framework for Scanning and Exploiting Internal Hosts With a Webpage
	* **(Sub)Domain Reconnaissance** <a name="sdr"></a>
		* **Articles/Blogposts/Writeups**
			* [A penetration tester’s guide to subdomain enumeration - Bharath](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)
			* [Subdomain Enumeration: 2019 Workflow - Patrik Hudak](https://0xpatrik.com/subdomain-enumeration-2019/)
		* **Domain Discovery**
			* [DRROBOT](https://github.com/sandialabs/dr_robot)
				* Dr.ROBOT is a tool for Domain Reconnaissance and Enumeration. By utilizing containers to reduce the overhead of dealing with dependencies, inconsistencies across operating systems, and different languages, Dr.ROBOT is built to be highly portable and configurable.
			* [assetfinder](https://github.com/tomnomnom/assetfinder)
				* Find domains and subdomains potentially related to a given domain.
		* **Subdomain Discovery Tools**
			* [Sudomy](https://github.com/Screetsec/Sudomy)
				* Sudomy is a subdomain enumeration tool, created using a bash script, to analyze domains and collect subdomains in fast and comprehensive way.
			* [domains-from-csp](https://github.com/0xbharath/domains-from-csp)
				* A Python script to parse domain names from CSP header
			* [pdlist. A passive subdomain finder](https://github.com/gnebbia/pdlist)
				* pdlist is a passive subdomain finder written in python3. This tool can be used effectively to collect information about a domain without ever sending a single packet to any of its hosts. Given a domain like "example.com" it will find all the hosts which have a `hostname <something>.example.com` or URLs strictly related to `example.com`.
			* [Find-Domains](https://github.com/iamj0ker/Find-domains)
				* This repo contain scripts written for finding subdomains using various available tools
			* [sub-differ](https://github.com/smackerdodi/sub-differ)
				* take a list of old subdomain and new subdomain and the output is the deleted subdomain and the new subdomain
			* [OneForAll](https://github.com/shmilylty/OneForAll/)
				* [OneForAll, A Powerful Chinese Subdomain Enumeration Tool - Daehee Park](https://www.daehee.com/oneforall/)
	* **Technology Identification** <a name="tttid"></a>
		* **Articles/Blogposts/Writeups**
		* **Tools**
			* **General**
				* [wappy](https://github.com/blackarrowsec/wappy)
					* A tool to discover technologies in web applications from your terminal. It uses the wap library, that is a python implementation of the great Wappalyzer browser extension. In fact, it uses the rules defined in the file technologies.json of the Wappalyzer repository.
			* **CMS**
				* [CMSExplorer](https://code.google.com/p/cms-explorer/)
					* CMS Explorer is designed to reveal the the specific modules, plugins, components and themes that various CMS driven web sites are running. Additionally, CMS Explorer can be used to aid in security testing. While it performs no direct security checks, the "explore" option can be used to reveal hidden/library files which are not typically accessed by web clients but are nonetheless accessible. This is done by retrieving the module's current source tree and then requesting those file names from the target system. These requests can be sent through a distinct proxy to help "bootstrap" security testing tools like Burp, Paros, Webinspect, etc.
				* [BlindElephant Web Application Fingerprinter](http://blindelephant.sourceforge.net/)
					* The BlindElephant Web Application Fingerprinter attempts to discover the version of a (known) web application by comparing static files at known locations against precomputed hashes for versions of those files in all all available releases. The technique is fast, low-bandwidth, non-invasive, generic, and highly automatable.
				* [Fingerprinter](https://github.com/erwanlr/Fingerprinter)
					*  CMS/LMS/Library etc Versions Fingerprinter. This script's goal is to try to find the version of the remote application/third party script etc by using a fingerprinting approach.
				* [WPScan](https://github.com/wpscanteam/wpscan)
					* WPScan is a free, for non-commercial use, black box WordPress security scanner written for security professionals and blog maintainers to test the security of their WordPress websites.
			* **Proxies**
				* [Web Filter External Enumeration Tool (WebFEET)](https://github.com/nccgroup/WebFEET)
					* WebFEET is a web application for the drive-by enumeration of web security proxies and policies. See associated [white paper](https://www.nccgroup.com/media/481438/whitepaper-ben-web-filt.pdf) (Drive-by enumeration of web filtering solutions)
			* **Web Servers**
				* [httprecon - Advanced Web Server Fingerprinting](https://github.com/scipag/httprecon-win32)
					* The httprecon project is doing some research in the field of web server fingerprinting, also known as http fingerprinting. The goal is the highly accurate identification of given httpd implementations. This is very important within professional vulnerability analysis. Besides the discussion of different approaches and the documentation of gathered results also an implementation for automated analysis is provided. This software shall improve the easyness and efficiency of this kind of enumeration. Traditional approaches as like banner-grabbing, status code enumeration and header ordering analysis are used. However, many other analysis techniques were introduced to increase the possibilities of accurate web server fingerprinting. Some of them were already discussed in the book Die Kunst des Penetration Testing (Chapter 9.3, HTTP-Fingerprinting, pp. 530-550).
				* [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
					* WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1500 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.
	* **Web Scraping** <a name="ttscraping"></a>
		* **101**
			* [Web scraping - Wikipedia](https://en.wikipedia.org/wiki/Web_scraping)
		* **Articles/Papers/Talks/Writeups**
		* **General**
		* **Tools**
			* [Puppeteer](https://github.com/GoogleChrome/puppeteer)
				* Puppeteer is a Node library which provides a high-level API to control Chrome or Chromium over the DevTools Protocol. Puppeteer runs headless by default, but can be configured to run full (non-headless) Chrome or Chromium.
			* [dvcs-ripper](https://github.com/kost/dvcs-ripper)
				* Rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr, ... It can rip repositories even when directory browsing is turned off.
			* [Scrapy](https://scrapy.org/)
				* An open source and collaborative framework for extracting the data you need from websites.
		* **Beautiful Soup**
			* [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/)
			* [Beautiful Soup (HTML parser) - Wikipedia](https://en.wikipedia.org/wiki/Beautiful_Soup_(HTML_parser))
			* [Beautiful Soup Documentation - crummy.com](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)
			* [Intro to Beautiful Soup - Jeri Wieringa](https://programminghistorian.org/en/lessons/intro-to-beautiful-soup)
		* **Miscellaneous**
			* [WeasyPrint](http://weasyprint.org/)
				* WeasyPrint is a visual rendering engine for HTML and CSS that can export to PDF. It aims to support web standards for printing. WeasyPrint is free software made available under a BSD license.
	* **User Enumeration** <a name="ttue"></a>
		* **Articles/Blogposts/Writeups**
			* [Six Methods to Determine Valid User Accounts in Web Applications - Dave](https://whiteoaksecurity.com/blog/2019/2/11/six-methods-to-determine-valid-user-accounts-in-web-applications)
		* **Tools**
			* [WhatsMyName](https://github.com/WebBreacher/WhatsMyName)
				*  This repository has the unified data required to perform user enumeration on various websites. Content is in a JSON file and can easily be used in other projects.
			* [hackability](https://github.com/PortSwigger/hackability)
				* Rendering Engine Hackability Probe performs a variety of tests to discover what the unknown rendering engine supports. To use it simply extract it to your web server and visit the url in the rendering engine you want to test. The more successful probes you get the more likely the target engine is vulnerable to attack.
	* **Virtual Hosts** <a name="ttrvhost"></a>
		* **101**
			* [Virtual Hosting - Wikipedia](https://en.wikipedia.org/wiki/Virtual_hosting)
		* **Tools**
			* [virtual-host-discovery](https://github.com/jobertabma/virtual-host-discovery)
				* This is a basic HTTP scanner that'll enumerate virtual hosts on a given IP address. During recon, this might help expand the target by detecting old or deprecated code. It may also reveal hidden hosts that are statically mapped in the developer's /etc/hosts file.
			* [blacksheepwall](https://github.com/tomsteele/blacksheepwall)
				* blacksheepwall is a hostname reconnaissance tool
			* [VHostScan](https://github.com/codingo/VHostScan)
				* A virtual host scanner that performs reverse lookups, can be used with pivot tools, detect catch-all scenarios, work around wildcards, aliases and dynamic default pages.
	* **Visual Reconnaissance** <a name="ttvr"></a>
		* **Articles/Blogposts/Writeups**
			* [Web Server Screenshots with a Single Command - Carrie Roberts](https://www.blackhillsinfosec.com/web-server-screenshots-single-command/)
			* [Application Enumeration Tips using Aquatone and Burp Suite - Ryan Wendel](https://www.ryanwendel.com/2019/09/27/application-enumeration-tips-using-aquatone-and-burp-suite/)
		* **Tools**
			* [PowerWebShot](https://github.com/dafthack/PowerWebShot)
				* A PowerShell tool for taking screenshots of multiple web servers quickly.
			* [HTTrack - Website Copier](https://www.httrack.com/)
				* It allows you to download a World Wide Web site from the Internet to a local directory, building recursively all directories, getting HTML, images, and other files from the server to your computer. HTTrack arranges the original site's relative link-structure. Simply open a page of the "mirrored" website in your browser, and you can browse the site from link to link, as if you were viewing it online. HTTrack can also update an existing mirrored site, and resume interrupted downloads. HTTrack is fully configurable, and has an integrated help system.
			* [Kraken](https://github.com/Sw4mpf0x/Kraken)
				* Kraken is a tool to help make your web interface testing workflow more efficient. This is done by using Django, Apache, and a MySql database to store and organize web interface screenshots and data. This allows you and your team to take notes and track which hosts have been tested simultaniously. Once you are finished, you can view these notes you took and generate reports in the Reports section.
			* [Eyeballer](https://github.com/bishopfox/eyeballer)
				* Eyeballer is meant for large-scope network penetration tests where you need to find "interesting" targets from a huge set of web-based hosts. Go ahead and use your favorite screenshotting tool like normal (EyeWitness or GoWitness) and then run them through Eyeballer to tell you what's likely to contain vulnerabilities, and what isn't.
			* [gowitness](https://github.com/sensepost/gowitness)
				* gowitness is a website screenshot utility written in Golang, that uses Chrome Headless to generate screenshots of web interfaces using the command line. Both Linux and macOS is supported, with Windows support 'partially working'.
			* [webscreenshot](https://github.com/maaaaz/webscreenshot)
				* A simple script to screenshot a list of websites, based on the url-to-image PhantomJS script.
			* [LazyShot](https://github.com/mdhama/lazyshot)
				* The simplest way to take an automated screenshot of given URLs. Easy installation!
			* [RAWR - Rapid Assessment of Web Resources](https://bitbucket.org/al14s/rawr/wiki/Home)
		* **3rd Party Hosted Tools**
			* [VisualSiteMapper](http://www.visualsitemapper.com)
				* Visual Site Mapper is a free service that can quickly show a map of your site.
		* **Web Page**
			* [HTCAP](https://htcap.org)
				* htcap is a web application scanner able to crawl single page application (SPA) recursively by intercepting ajax calls and DOM changes.
	* **Wordlists** <a name="ttwl"></a>
		* [jhaddix all.txt](https://gist.github.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a)
			*  all wordlists from every dns enumeration tool... ever. Please excuse the lewd entries =/
		* [jhaddix content_discovery_all.txt](https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10)
			* a masterlist of content discovery URLs and files (used most commonly with gobuster)
		* [SecLists](https://github.com/danielmiessler/SecLists)
			* SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.
		* [IntruderPayloads](https://github.com/1N3/IntruderPayloads)
			* A collection of Burpsuite Intruder payloads, BurpBounty payloads (https://github.com/wagiro/BurpBounty), fuzz lists and pentesting methodologies.
		* [CommonSpeak2](https://github.com/assetnote/commonspeak2)
		* [CWFF - Custom wordlists for fuzzing](https://github.com/D4Vinci/CWFF)
			* CWFF is a tool that creates a special High quality fuzzing/content discovery wordlist for you at the highest speed possible using concurrency and it's heavily inspired by @tomnomnom's Who, What, Where, When, Wordlist
		* [1ndiList v 1.0](https://github.com/1ndianl33t/1ndiList)
			* Recon Custom WordList Ganerator
		* [Who, What, Where, When, Wordlist - TomNomNom](https://tomnomnom.com/talks/wwwww.pdf)
* **Vulnerability Scanner** <a name="ttvs"></a>
	* [Nikto](https://cirt.net/Nikto2)
	* [Spaghetti - Web Application Security Scanner](https://github.com/m4ll0k/Spaghetti)
		* Spaghetti is an Open Source web application scanner, it is designed to find various default and insecure files, configurations, and misconfigurations. Spaghetti is built on python2.7 and can run on any platform which has a Python environment.
	* [skipfish](https://code.google.com/p/skipfish/)
		* Skipfish is an active web application security reconnaissance tool. It prepares an interactive sitemap for the targeted site by carrying out a recursive crawl and dictionary-based probes. The resulting map is then annotated with the output from a number of active (but hopefully non-disruptive) security checks. The final report generated by the tool is meant to serve as a foundation for professional web application security assessments.
	* [wikto](https://github.com/sensepost/wikto)
		* Wikto is Nikto for Windows - but with a couple of fancy extra features including Fuzzy logic error code checking, a back-end miner, Google assisted directory mining and real time HTTP request/response monitoring. Wikto is coded in C# and requires the .NET framework.
	* [WATOBO](https://github.com/siberas/watobo)
		* WATABO is a security tool for testing web applications. It is intended to enable security professionals to perform efficient (semi-automated) web application security audits.
	* [YASUO](https://github.com/0xsauby/yasuo)
		* Yasuo is a ruby script that scans for vulnerable 3rd-party web applications.
	* [ParrotNG](https://github.com/ikkisoft/ParrotNG)
		* ParrotNG is a tool capable of identifying Adobe Flex applications (SWF) vulnerable to CVE-2011-2461
	* [Arachni Web Scanner](http://www.arachni-scanner.com/)
		* Arachni is an Open Source, feature-full, modular, high-performance Ruby framework aimed towards helping penetration testers and administrators evaluate the security of web applications.  It is smart, it trains itself by monitoring and learning from the web application's behavior during the scan process and is able to perform meta-analysis using a number of factors in order to correctly assess the trustworthiness of results and intelligently identify (or avoid) false-positives.
	* [Pyfiscan](https://github.com/fgeek/pyfiscan)
		* Pyfiscan is free web-application vulnerability and version scanner and can be used to locate out-dated versions of common web-applications in Linux-servers. Example use case is hosting-providers keeping eye on their users installations to keep up with security-updates. Fingerprints are easy to create and modify as user can write those in YAML-syntax. Pyfiscan also contains tool to create email alerts using templates.
	* [jaeles](https://github.com/jaeles-project/jaeles)
		* "powerful, flexible and easily extensible framework written in Go for building your own Web Application Scanner."
		* [Showcase examples of usage](https://jaeles-project.github.io/showcases/)
	* [0d1n](https://github.com/CoolerVoid/0d1n)
		* 0d1n is a tool for automating customized attacks against web applications.
	* [reNgine](https://github.com/yogeshojha/rengine)
		* reNgine is an automated reconnaissance framework meant for gathering information during penetration testing of web applications. reNgine has customizable scan engines, which can be used to scan the websites, endpoints, and gather information.
	* [Osmodeus](https://github.com/j3ssie/Osmedeus)
		* Fully automated offensive security framework for reconnaissance and vulnerability scanning


----------------
## Attacks <a name="attacks"></a>

### Abuse of Functionality <a name="abuse"></a>
* [jsgifkeylogger](https://github.com/wopot/jsgifkeylogger)
	* a javascript keylogger included in a gif file This is a PoC

----------------
### Brute Force/Fuzzing <a name="brute"></a>
* **101**
	* [Turbo Intruder: Embracing the billion-request attack - James Kettle(2019)](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
* **Tools**
	* [Dirbuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
		* DirBuster is a multi threaded java application designed to brute force directories and files names on web/application servers. Often is the case now of what looks like a web server in a state of default installation is actually not, and has pages and applications hidden within. DirBuster attempts to find these.
	* [Go Buster](https://github.com/OJ/gobuster)
		* Directory/file busting tool written in Go; Recursive, CLI-based, no java runtime
	* [WFuzz](https://code.google.com/p/wfuzz/)
		* Wfuzz is a tool designed for bruteforcing Web Applications, it can be used for finding resources not linked (directories, servlets, scripts, etc), bruteforce GET and POST parameters for checking different kind of injections (SQL, XSS, LDAP,etc), bruteforce Forms parameters (User/Password), Fuzzing,etc
	* [dirsearch](https://github.com/maurosoria/dirsearch)
		* dirsearch is a simple command line tool designed to brute force directories and files in websites.
	* [ffuf](https://github.com/ffuf/ffuf)
		* Fast web fuzzer written in Go
	* [Tachyon](https://github.com/delvelabs/tachyon)
		* Tachyon is a Fast Multi-Threaded Web Discovery Tool
	* [Syntribos](https://github.com/openstack/syntribos)
		* Given a simple configuration file and an example HTTP request, syntribos can replace any API URL, URL parameter, HTTP header and request body field with a given set of strings. Syntribos iterates through each position in the request automatically. Syntribos aims to automatically detect common security defects such as SQL injection, LDAP injection, buffer overflow, etc. In addition, syntribos can be used to help identify new security defects by automated fuzzing.
	* [Patator](https://github.com/lanjelot/patator)
		* multi-purpose brute-forcer

----------------
### Attacking Continous Integration Systems <a name="ci"></a>
* **101**
* **Articles/Blogposts/Writeups**
* **Talks/Presentations/Videos**
	* [Exploiting Continuous Integration (CI) and Automated Build Systems - spaceb0x](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-spaceB0x-Exploiting-Continuous-Integration.pdf)
* **Agnostic**
	* [cider - Continuous Integration and Deployment Exploiter](https://github.com/spaceB0x/cider)
		* CIDER is a framework written in node js that aims to harness the functions necessary for exploiting Continuous Integration (CI) systems and their related infrastructure and build chain (eg. Travis-CI, Drone, Circle-CI). Most of the exploits in CIDER exploit CI build systems through open GitHub repositories via malicious Pull Requests. It is built modularly to encourage contributions, so more exploits, attack surfaces, and build chain services will be integrated in the future.
	* [Rotten Apple](https://github.com/claudijd/rotten_apple)
		* A tool for testing continuous integration (CI) or continuous delivery (CD) system security
* **Bamboo**
* **CircleCI**
* **Jenkins**
	* [Hacking Jenkins Part 1 - Play with Dynamic Routing - Orange Tsai](http://blog.orange.tw/2019/01/hacking-jenkins-part-1-play-with-dynamic-routing.html)
	* [Hacking Jenkins Part 2 - Abusing Meta Programming for Unauthenticated RCE! - Orange Tsai](https://blog.orange.tw/2019/02/abusing-meta-programming-for-unauthenticated-rce.html)

----------------
### CSV Injection <a name="csv"></a>
* **101**
* **Articles/Blogposts/Writeups**
	* [Everything about the CSV Excel Macro Injection - Ishaq Mohammed](http://blog.securelayer7.net/how-to-perform-csv-excel-macro-injection/)
	* [From CSV to CMD to qwerty - exploresecurity](http://www.exploresecurity.com/from-csv-to-cmd-to-qwerty/)
	* [Everything about the CSV Excel Macro Injection - Ishaq Mohammed](http://blog.securelayer7.net/how-to-perform-csv-excel-macro-injection/)
	* [Tricks to improve web app excel export attacks(Slides) - Jerome Smith - CamSec2016]()
		* [Video](https://www.youtube.com/watch?v=3wNvxRCJLQQ)
		* This presentation is an embellished version of the second half of a talk originally presented at BSides MCR 2016. It covers more general web app export issues as well as revisions on the DDE content following feedback from BSides. This talk also had more demos.
	* [CSV Injection Revisited - Making Things More Dangerous(and fun) - Andy Gill](https://blog.zsec.uk/csv-dangers-mitigations/)
	* [From CSV to Meterpreter - XPNSec](https://xpnsec.tumblr.com/post/133298850231/from-csv-to-meterpreter)
	* [CSV Injection- There's devil in the detail - Sunil Joshi](https://www.we45.com/blog/2017/02/14/csv-injection-theres-devil-in-the-detail)
	* [CSV injection: Basic to Exploit!!!! - Akansha Kesharwani](https://payatu.com/csv-injection-basic-to-exploit/)
	* [[Cell Injection] Attacking the end user through the application - David Stubley](http://blog.7elements.co.uk/2013/01/cell-injection.html)
	* [The Absurdly Underestimated Dangers of CSV Injection - George Mauer](http://georgemauer.net/2017/10/07/csv-injection.html)
	* [Data Extraction to Command Execution CSV Injection - Jamie Rougvie](https://www.veracode.com/blog/secure-development/data-extraction-command-execution-csv-injection)
	* [Comma Separated Vulnerabilities](https://www.contextis.com/blog/comma-separated-vulnerabilities)
		* This post introduces Formula Injection, a technique for exploiting ‘Export to Spreadsheet’ functionality in web applications to attack users and steal spreadsheet contents. It also details a command injection exploit for Apache OpenOffice and LibreOffice that can be delivered using this technique.
	* [[Cell Injection] Attacking the end user through the application - 7elements.co.uk](http://blog.7elements.co.uk/2013/01/cell-injection.html)
	* [Microsoft Excel CSV code execution/injection method - xor %eax,%eax](https://xorl.wordpress.com/2017/12/11/microsoft-excel-csv-code-execution-injection-method/)
* **Talks & Presentations**
* **Tools**

----------------
### Clickjacking <a name="click"></a>
* **101**
	* [Clickjacking - Wikipedia](https://en.wikipedia.org/wiki/Clickjacking)
		*  Clickjacking (classified as a User Interface redress attack, UI redress attack, UI redressing) is a malicious technique of tricking a user into clicking on something different from what the user perceives, thus potentially revealing confidential information or allowing others to take control of their computer while clicking on seemingly innocuous objects, including web pages.
	* [Clickjacking Defense Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
		* This cheat sheet is intended to provide guidance for developers on how to defend against Clickjacking, also known as UI redress attacks.
	* [X-Frame-Options - MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
	* [Clickjacking (UI redressing) - PortSwigger](https://portswigger.net/web-security/clickjacking)
* **Articles/Blogposts/Writeups**
	* [Clickjacking DOM XSS on Google.org - Thomas Orlita](https://appio.dev/vulns/clickjacking-xss-on-google-org/)
	* [The clickjacking attack - javascript.info(2019)](https://javascript.info/clickjacking)
	* [Clickjacking Protection¶ - Django](https://docs.djangoproject.com/en/3.1/ref/clickjacking/)
* **Presentations/Talks/Videos**
* **Papers**
	* [Busting Frame Busting: A Study of Clickjacking Vulnerabilities on Popular Sites - Gustav Rydstedt, Elie Bursztein, Dan Boneh, Collin Jackson](https://seclab.stanford.edu/websec/framebusting/framebust.pdf)
* **Tools**

----------------
### Cross Protocol Scripting/Request Attack <a name="cpr"></a>
* **101**
* **Articles/Blogposts/Writeups**
	* [How to steal any developer's local database - bouk.co](https://web.archive.org/web/20170119060232/https://bouk.co/blog/hacking-developers/)
* **Papers**
	* [HTML Form Protocol Attack - Jochen Topf(2001)](https://web.archive.org/web/20170810193321/https://www.jochentopf.com/hfpa/hfpa.pdf)
		* This paper describes how some HTML browsers can be tricked through the use of HTML forms into sending more or less arbitrary data to any TCP port. This can be used to send commands to servers using ASCII based protocols like SMTP, NNTP, POP3, IMAP, IRC, and others. By sending HTML email to unsuspecting users or using a trojan HTML page, an attacker might be able to send mail or post Usenet News through servers normally not accessible to him. In special cases an attacker might be able to do other harm, e.g. deleting mail from a POP3 mailbox.
	* [Cross-Protocol Request Forgery - Tanner Prynn(2018)](https://www.nccgroup.com/us/our-research/cross-protocol-request-forgery/)
		* Server-Side Request Forgery (SSRF) and Cross-Site Request Forgery (CSRF) are two attackmethods that enable attackers to cross network boundaries in order to attack applications,but can only target applications that speak HTTP. Custom TCP protocols are everywhere:IoT devices, smartphones, databases, development software, internal web applications, andmore. Often, these applications assume that no security is necessary because they are onlyaccessible over the local network. This paper aims to be a definitive overview of attacksthat allow cross-protocol exploitation of non-HTTP listeners using CSRF and SSRF, and alsoexpands on the state of the art in these types of attacks to target length-specified protocolsthat were not previously thought to be exploitable.
* **Presentations/Talks/Videos**
* **Tools**
	* [Extract data](https://github.com/bouk/extractdata)
		* Extract data is a demo combining a cross-protocol request attack with DNS rebinding

----------------
### Cross Site Content Hijacking <a name="xshm"></a>
* **101**
	* [Cross domain data hijacking - acunetix.com](https://www.acunetix.com/vulnerabilities/web/cross-domain-data-hijacking/)
	* [Cross Domain Hijack – Flash File Upload Vulnerability - Dunn3S3C](https://web.archive.org/web/20150912225356/dunnesec.com/2014/05/26/cross-domain-hijack-flash-file-upload-vulnerability//)
* **Articles/Blogposts/Writeups**
	* [Content-Type Blues - Neil Bergman](https://d3adend.org/blog/posts/content-type-blues/)
	* [Exploiting CVE-2011-2461 on google.com - Mauro Gentile](https://blog.mindedsecurity.com/2015/03/exploiting-cve-2011-2461-on-googlecom.html)
	* [Cross-Site Content (Data) Hijacking (XSCH) PoC Project](https://github.com/nccgroup/CrossSiteContentHijacking/)
	* [Even uploading a JPG file can lead to Cross-Site Content Hijacking (client-side attack)! - Soroush Dalili](https://soroush.secproject.com/blog/2014/05/even-uploading-a-jpg-file-can-lead-to-cross-domain-data-hijacking-client-side-attack/)
	* [Same Origin Policy Weaknesses - Kuza55](https://www.slideshare.net/kuza55/same-origin-policy-weaknesses-1728474)
	* [The lesser known pitfalls of allowing file uploads on your website - Mathias Karlsson, Frans Rosén](https://labs.detectify.com/2014/05/20/the-lesser-known-pitfalls-of-allowing-file-uploads-on-your-website/)
* **Papers**
* **Presentations/Talks/Videos**
* **Tools**

----------------
### Cross Site History Manipulation <a name="xshm"></a>
* **101**
	* [Cross Site History Manipulation (XSHM) - OWASP](https://owasp.org/www-community/attacks/Cross_Site_History_Manipulation_(XSHM))
	* [Cross Site History Manipulation resolution - StackOverflow](https://stackoverflow.com/questions/27782805/cross-site-history-manipulation-resolution)
* **Articles/Blogposts/Writeups**
* **Papers**
	* [Cross-Site History Manipulation: XSHM - Alex Roichman(2010)](https://www.checkmarx.com/wp-content/uploads/2012/07/XSHM-Cross-site-history-manipulation.pdf)
* **Presentations/Talks/Videos**
* **Tools**
	* [XSHM-Payload-Generator](https://github.com/xamfp/XSHM-Payload-Generator)

----------------
### Cross Site Request Forgery (CSRF) <a name="csrf"></a>
* **101**
	* [Cross-site request forgery - Wikipedia](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
	* [Cross Site Request Forgery - OWASP](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29)
	* [CSRF - PortSwigger](https://portswigger.net/web-security/csrf)
	* [The Cross-Site Request Forgery (CSRF/XSRF) FAQ  - Robert Auger(2010)](https://www.cgisecurity.com/csrf-faq.html#)
* **Articles/Blogposts**
	* [ClientSideTrojan - zope.org(2000)](https://web.archive.org/web/20201019030224/http://old.zope.org/Members/jim/ZopeSecurity/ClientSideTrojan/)
	* Cross-Site Request Forgeries - Peter Watkins(Bugtraq 2002)](https://web.archive.org/web/20020204142607/http://www.tux.org/~peterw/csrf.txt)
	* [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)\_Prevention_Cheat_Sheet)
	* [The OWASP Top Ten and ESAPI – Part 5 – Cross Site Request Forgery (CSRF)](http://www.jtmelton.com/2010/05/16/the-owasp-top-ten-and-esapi-part-6-cross-site-request-forgery-csrf/)
	* [Testing for CSRF (OTG-SESS-005) - OWASP](https://www.owasp.org/index.php/Testing_for_CSRF_(OTG-SESS-005)\)
	* [A most Neglected Fact About CSRF - pdf](http://yehg.net/lab/pr0js/view.php/A_Most-Neglected_Fact_About_CSRF.pdf)
	* [Bypassing CSRF Protection - Vickie Li](https://medium.com/swlh/bypassing-csrf-protection-c9b217175ee)
	* [Samesite by Default and What It Means for Bug Bounty Hunters - Filedescriptor, Ron Chan & Edoverflow(2020)](https://blog.reconless.com//samesite-by-default/)
	* [Cross Site Request Forgery: Techniques - OneHackMan(2019)](https://medium.com/@onehackman/cross-site-request-forgery-techniques-19270174ea4)
	* [CSRF is dead - Scott Helme(2017)](https://scotthelme.co.uk/csrf-is-dead/)
	* [CSRF is (really) dead - Scott Helme(2019)](https://scotthelme.co.uk/csrf-is-really-dead/)
* **Writeups**
	* [WordPress 5.1 CSRF to Remote Code Execution - Simon Scannell(2019)](https://blog.ripstech.com/2019/wordpress-csrf-to-rce/)
	* [CSRF to RCE bug chain in Prestashop v1.7.6.4 and below - Sivanesh Ashok(2020)](https://stazot.com/prestashop-csrf-to-rce-article/)
	* [CSRF Protection Bypass in Play Framework - Luca Carrettoni(2020)](https://blog.doyensec.com/2020/08/20/playframework-csrf-bypass.html)
	* [Research: The mass CSRFing of *.google.com/* products. - missoumsai.com](http://www.missoumsai.com/google-csrfs.html)
	* [Zoom Security Exploit – Cracking private meeting passwords - Tom Anthony(2020)](https://www.tomanthony.co.uk/blog/zoom-security-exploit-crack-private-meeting-passwords/)
	* [How I leveraged an interesting CSRF vulnerability to turn self XSS into a persistent attack? - Akash Methani(2020)](https://medium.com/bugbountywriteup/how-i-leveraged-an-interesting-csrf-vulnerability-to-turn-self-xss-into-a-persistent-attack-b780824042d2)
	* [Exploiting WebSocket [Application Wide XSS / CSRF] - Osama Avvan](https://medium.com/@osamaavvan/exploiting-websocket-application-wide-xss-csrf-66e9e2ac8dfa)
	* [CSRF is No Joke: From CSRF to RCE in Cisco Energy Management - Chris Lyne](https://medium.com/tenable-techblog/csrf-is-no-joke-e6f00594b21e)
	* [From Csrf To Rce - fgsec.net(2020)](https://fgsec.net/2020/04/20/From-CSRF-to-RCE.html)
	* [From CSRF to RCE and WordPress-site takeover: CVE-2020-8417 - Jonas Lejon](https://blog.wpsec.com/csrf-to-rce-wordpress/)
	* [WordPress 5.1 CSRF + XSS + RCE – Poc  - Pablo Plaza Martinez](https://ironhackers.es/en/tutoriales/wordpress-5-1-csrf-xss-rce-poc/)
	* [Bolt CMS <= 3.7.0 Multiple Vulnerabilities - CSRF to RCE - Sivanesh Ashok](https://seclists.org/fulldisclosure/2020/Jul/4)
	* [Playing with GZIP: RCE in GLPI (CVE-2020-11060) - @myst404](https://offsec.almond.consulting/playing-with-gzip-rce-in-glpi.html)
* **Papers**
	* [Session Riding: A Widespread Vulnerability in Today's Web Applications - Thomas Schreiber(2004)(https://crypto.stanford.edu/cs155old/cs155-spring08/papers/Session_Riding.pdf)
	* [Robust Defenses for Cross-Site Request Forgery](http://theory.stanford.edu/people/jcm/papers/ccs2008-barth.pdf)
	* [RequestRodeo: Client Side Protection against Session Riding - Martin Johns and Justus Winter - pdf](https://www.owasp.org/images/4/42/RequestRodeo-MartinJohns.pdf)
* **Presentations/Talks/Videos**
* **Tools**
	* [OWASP CSRFGuard](https://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project)
	* [OWASP CSRFTester](https://www.owasp.org/index.php/Category:OWASP_CSRFTester_Project)
	* [](https://code.google.com/archive/p/pinata-csrf-tool/)
* **Onsite-Request-Forgery**
	* [On-Site Request Forgery - PortSwigger](http://blog.portswigger.net/2007/05/on-site-request-forgery.html)
	* [On-site Request Forgery - cm2.pw](https://blog.cm2.pw/on-site-request-forgery/)

----------------
### Cascading-StyleSheets-related Attacks <a name="cssi"></a>
* **101**
	* [CSS - Wikipedia](https://en.wikipedia.org/wiki/CSS)
	* [Securing Cascading Style Sheets Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Securing_Cascading_Style_Sheets_Cheat_Sheet.html)
* **General**
	* **Articles/Blogposts/Writeups**
		* [I know where you've been - Jeremiah Grossman(2006)](https://blog.jeremiahgrossman.com/2006/08/i-know-where-youve-been.html)
		* [CSS based Attack: Abusing unicode-range of @font-face - Masato Kinugawa(2015)](https://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html)
		* [CSS: Cascading Style Scripting - XSS Jigsaw(2015)](https://blog.innerht.ml/cascading-style-scripting/)
		* [History theft with CSS Boolean algebra - lcamtuf](https://lcamtuf.coredump.cx/css_calc/)
		* [CSS mix-blend-mode is bad for your browsing history - lcamtuf(2016)](https://lcamtuf.blogspot.com/2016/08/css-mix-blend-mode-is-bad-for-keeping.html)
		* [Stealing Data With CSS: Attack and Defense - Mike Gualtieri(2018)](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense)
		* [Third party CSS is not safe - Jake Archibald(2018)](https://jakearchibald.com/2018/third-party-css-is-not-safe/)
		* [CSS Security Vulnerabilities - Chris Coyier(2019)](https://css-tricks.com/css-security-vulnerabilities/)
		* [Cross-Origin CSS Attacks Revisited (feat. UTF-16) - @filedescriptor](https://blog.innerht.ml/cross-origin-css-attacks-revisited-feat-utf-16/)
	* **Talks/Presentations/Videos**
		* [The Sexy Assassin: Tactical Exploitation Using CSS - G. Heyes, D. Lindsay, and E.V. Nava(BlueHat 2009)](http://slideplayer.com/slide/3493669/)
		* [XSS. (No, the _other_ "S") - Mike West(CSSconf.eu 2013)](https://youtu.be/eb3suf4REyI?t=582)
		* [Attacking Rich Internet Applications - Stefano Di Paola, kuza55(25c3 2010)](https://www.youtube.com/watch?v=RNt_e0WR1sc)
			* This presentation will examine the largely underresearched topic of rich internet applications (RIAs) security in the hopes of illustrating how the complex interactions with their executing environment, and general bad security practices, can lead to exploitable applications. In recent years rich internet applications (RIAs) have become the mainstay of large internet applications and are becoming increasingly attractive to the industry due to their similarity to desktop applications. Furthermore their user of exsting web technologies such as HTTP, HTML/XML and Javascript/Actionscript make them attractive options to companies with existing web developers. Unfortunately the use of existing technologies brings with it the burden of existing ways to write vulnerable code, but adds yet more ways. This presentation will examine the largely underresearched topic of RIA security in the hopes of illustrating how the complex interactions with their executing environment, and general bad security practices, can lead to exploitable applications.
		* [The Curse of Cross-Origin Stylesheets - LiveOverflow(2018)](https://www.youtube.com/watch?v=bMPAXsgWNAc)
		* [The Sexy Assassin Tactical Exploitation using CSS. - Gerardo Speaks](https://slideplayer.com/slide/3493669/)
	* **Papers**
		* [Scriptless Attacks - Stealing the Pie Without Touching the Sill - Mario Heiderich, Marcus Niemietz, Felix Schuster, Thorsten Holz, Jörg Schwenk(2012)](https://www.nds.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2012/08/16/scriptlessAttacks-ccs2012.pdf)
			* In this paper, we examine the attack surface that remainsafter XSS and similar scripting attacks are supposedly mit-igated by preventing an attacker from executing JavaScriptcode. We address the question of whether an attacker reallyneeds JavaScript or similar functionality to perform attacksaiming for information theft. The surprising result is thatan attacker can also abuse Cascading Style Sheets (CSS) incombination with other Web techniques like plain HTML,inactive SVG images or font files.  Through several casestudies, we introduce the so calledscriptless attacksanddemonstrate that an adversary might not need to executecode to preserve his ability to extract sensitive informationfrom well protected websites. More precisely, we show thatan attacker can use seemingly benign features to build sidechannel attacks that measure and exfiltrate almost arbitrarydata displayed on a given website.We conclude this paper with a discussion of potential mit-igation techniques against this class of attacks. In addition,we have implemented a browser patch that enables a websiteto make a vital determination as to being loaded in a de-tached view or pop-up window. This approach proves usefulfor prevention of certain types of attacks we here discuss.
	* **Tools**
		* http://eaea.sirdarckcat.net/cssar/v2/
		* [CTF insomnihack'18 - Cool Storage Service web challenge](https://gist.github.com/cgvwzq/f7c55222fbde44fc686b17f745d0e1aa)
* **CSS Injection**
	* **101**
		* [CSS injection (stored) - PortSwigger](https://portswigger.net/kb/issues/00501301_css-injection-stored)
		* [CSS injection (reflected) - PortSwigger](https://portswigger.net/kb/issues/00501300_css-injection-reflected)
	* **Articles/Blogposts/Writeups**
		* [Stealing Secrets with CSS : Cross Origin CSS Attacks - Keith Makan(2016)](http://blog.k3170makan.com/2016/02/stealing-secrets-with-css-cross-origin.html)
		* [CSS Injection Primitives - x-c3ll](https://x-c3ll.github.io//posts/CSS-Injection-Primitives/)
		* [CSS data exfiltration in Firefox via a single injection point - Michal Bentkowski(2020)](https://research.securitum.com/css-data-exfiltration-in-firefox-via-single-injection-point/)
	* **Presentations/Talks/Videos**
		* [CSS Injection Attacks or how to leak content with `<style>` - Pepe Vila(2019)](https://vwzq.net/slides/2019-s3_css_injection_attacks.pdf)

----------------
### Cross Site WebSocket Hijacking <a name="cswsh"></a>
* **101**
	* [Cross-Site WebSocket Hijacking (CSWSH) - Christian Schneider(2019)](https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html)
	* [Cross-site WebSocket hijacking - PortSwigger](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)
	* [Testing WebSockets - OWASP WSTG v4.1](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/10-Testing_WebSockets)
* **Articles/Blogposts/Presentations/Talks/Videos**
	* [Security Testing HTML5 WebSockets - ethicalhack3r(2013)](https://web.archive.org/web/20140626111641/http://www.ethicalhack3r.co.uk/security-testing-html5-websockets/)
	* [How Cross-Site WebSocket Hijacking could lead to full Session Compromise - notsosecure.com(2014)](https://www.notsosecure.com/how-cross-site-websocket-hijacking-could-lead-to-full-session-compromise/)
	* [Analysing, Testing and Fuzzing WebSocket Implementations with IronWASP  - ironwasp.org(2014)](http://blog.ironwasp.org/2014/11/analysing-testing-and-fuzzing-websocket.html)
	* [Cross-Site Websocket Hijacking (CSWSH) - Jesse Somerville(2019)](https://www.praetorian.com/blog/cross-site-websocket-hijacking-cswsh?edition=2019)
	* [Hacking WebSocket With Cross-Site WebSocket Hijacking attacks - Vickie Li(2019)](https://medium.com/swlh/hacking-websocket-25d3cba6a4b9)
	* [Cross-site WebSocket hijacking (CSWSH) - HackTricks](https://book.hacktricks.xyz/pentesting-web/cross-site-websocket-hijacking-cswsh)
* **Talks/Presentations/Videos**
* **Papers**
	* [Research and Defense of Cross-Site WebSocket Hijacking Vulnerability - Wenbo Mei, Zhaohua Long(2020)](https://ieeexplore.ieee.org/document/9182458)
* **Tools**
	* [Cross-Site WebSocket Hijacking Tester](https://cow.cat/cswsh.html)

----------------
### Data Structure Attacks <a name="dsa"></a>
* --> See XML section
* --> See 'CSV Injection' Attack
* [Comma Separated Vulnerabilities](https://www.contextis.com/blog/comma-separated-vulnerabilities)

----------------
### Edge Side Include Injection <a name="esii"></a>
* **101**
	* [Edge Side Includes - Wikipedia](https://en.wikipedia.org/wiki/Edge_Side_Includes)
* **Articles/Blogposts/Writeups**
	* [Beyond XSS: Edge Side Include Injection - Louis Dion-Marcil(2018)](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/)
	* [ESI Injection Part 2: Abusing specific implementations - Philippe Arteau(2019)](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)
	* [Edge Side Includes abused to enable RCE - Catherine Chapman(2019)](https://portswigger.net/daily-swig/edge-side-includes-abused-to-enable-rce)
* **Talks/Presentations/Videos**
	* [Cache Me If You Can - Philippe Arteau](https://gosecure.github.io/presentations/2019-02-26-confoo_mtl/Cache_Me_If_You_Can.pdf)
	* [Edge Side Include Injection: Abusing Caching Servers into SSRF and Transparent Session Hijacking - Louis Dion-Marcil(BHUSA2018)](https://www.youtube.com/watch?v=6t50uRAxFT8)
		* [Slides](https://i.blackhat.com/us-18/Wed-August-8/us-18-Dion_Marcil-Edge-Side-Include-Injection-Abusing-Caching-Servers-into-SSRF-and-Transparent-Session-Hijacking.pdf)
		* When caching servers and load balancers became an integral part of the Internet's infrastructure, vendors introduced what is called "Edge Side Includes" (ESI), a technology allowing malleability in caching systems. This legacy technology, still implemented in nearly all popular HTTP surrogates (caching/load balancing services), is dangerous by design and brings a yet unexplored vector for web-based attacks.
* **Tools**

----------------
### Embedded Malicious Code <a name="emc"></a>
* **101**
* **Articles/Blogposts/Writeups**
* **Papers**
* **Presentations/Talks/Videos**
* **Tools**

----------------
### Exploitation of Authentication <a name="eoa"></a>
* **101**
* **Articles/Blogposts/Writeups**
* **Papers**
* **Presentations/Talks/Videos**
* **Tools**

----------------
### IDN Homograph & Homograph Attacks <a name="idn"></a>
* **101**
	* [The Homograph Attack - Evgeniy Gabrilovich, Alex Gontmakher](http://evgeniy.gabrilovich.com/publications/papers/homograph_full.pdf)
	* [IDN homograph attack - Wikipedia](https://en.wikipedia.org/wiki/IDN_homograph_attack)
* **Articles/Blogposts/Writeups**
	* [Homograph Attack - crypto-it.net](http://www.crypto-it.net/eng/attacks/homograph-attack.html)
	* [What is an IDN Homograph Attack and How Do You Protect Yourself? - zvelo(2018)](https://zvelo.com/what-is-idn-homograph-attack-protect-yourself/)
	* [Phishing with Unicode Domains - Xudong Zheng(2017)](https://www.xudongz.com/blog/2017/idn-phishing/)
	* [Watch Your Step: The Prevalence of IDN Homograph Attacks - Asaf Nadler(2017)](https://blogs.akamai.com/sitr/2020/05/watch-your-step-the-prevalence-of-idn-homograph-attacks.html)
	* [Homograph attacks: Don’t believe everything you see -  Cecilia Pastorino(2017)](https://www.welivesecurity.com/2017/07/27/homograph-attacks-see-to-believe/)
	* [A Quick Guide to the IDN Homograph Attack - Ronnie T. Baby](https://resources.infosecinstitute.com/a-quick-guide-to-the-idn-homograph-attack/)
* **Talks/Presentations/Videos**
	* [Weaponizing Unicode Homographs Beyond IDNs - The Tarquin(DEFCON 26)](https://www.youtube.com/watch?v=Ec1OOiG4RMA)
		* Most people are familiar with homograph attacks due to phishing or other attack campaigns using Internationalized Domain Names with look-alike characters. But homograph attacks exist against wide variety of systems that have gotten far less attention. This talk discusses the use of homographs to attack machine learning systems, to submit malicious software patches, and to craft cryptographic canary traps and leak repudiation mechanisms. It then introduces a generalized defense strategy that should work against homograph attacks in any context.
* **Papers**
	* [Cutting through the Confusion: A Measurement Study of Homograph Attacks. - Tobias Holgers, David E. Watson, Steven D. Gribble(2006)](https://www.researchgate.net/publication/220881094_Cutting_through_the_Confusion_A_Measurement_Study_of_Homograph_Attacks)
		* Web homograph attacks have existed for some time, and the recent adoption of International Domain Names (IDNs) support by browsers and DNS registrars has exacerbated the problem [Gabr02]. Many international letters have similar glyphs, such as the Cyrillic letter P (lower case 'er,' Unicode 0x0440) and the Latin letter p. Because of the large potential for misuse of IDNs, browser vendors, policy advocates, and researchers have been exploring techniques for mitigating homograph attacks [=Mozi05, Appl05, Oper05, Mark05]. There has been plenty of attention on the problem recently, but we are not aware of any data that quantifies the degree to which Web homograph attacks are currently taking place. In this paper, we use a combination of passive network tracing and active DNS probing to measure several aspects of Web homographs. Our main findings are four-fold. First, many authoritative Web sites that users visit have several confusable domain names registered. Popular Web sites are much more likely to have such confusable domains registered. Second, registered confusable domain names tend to consist of single character substitutions from their authoritative domains, though we saw instances of five-character substitutions. Most confusables currently use Latin character homographs, but we did find a non-trivial number of IDN homographs. Third, Web sites associated with non-authoritative confusable domains most commonly show users advertisements. Less common functions include redirecting victims to competitor sites and spoofing the content of authoritative site. Fourth, during our nine-day trace, none of the 828 Web clients we observed visited a non-authoritative confusable Web site. Overall, our measurement results suggest that homograph attacks currently are rare and not severe in nature. However, given the recent increases in phishing incidents, homograph attacks seem like an attractive future method for attackers to lure users to spoofed sites.
	* [Іntеrnɑtⅰonɑlⅰzеⅾ Dоmɑⅰn Nɑmе Hоmоɡrɑρh Attɑсκ - Chen Lai, Zhongrong Jian, J. Sidrach](https://github.com/jsidrach/idn-homograph-attack)
	* [ShamFinder: An Automated Frameworkfor Detecting IDN Homographs](https://arxiv.org/pdf/1909.07539.pdf)
* **Tools**
	* [EvilURL v2.0](https://github.com/UndeadSec/EvilURL)
		* Generate unicode evil domains for IDN Homograph Attack and detect them.
	* [homoglyphs.net](https://www.homoglyphs.net)
	* [Punycode converter](https://www.punycoder.com/)
		* or an IDN converter, a tool for Punycode to Text/Unicode and vice-versa conversion

----------------
### Insecure Direct Object Reference <a name="idor"></a>
* **101**
	* [Insecure Direct Object References - tutorialspoint.com](https://www.tutorialspoint.com/security_testing/insecure_direct_object_reference.htm)
	* [What Are Insecure Direct Object References - Tomasz Andrzej Nidecki(2020)](https://www.acunetix.com/blog/web-security-zone/what-are-insecure-direct-object-references/)
* **Articles/Blogposts/Writeups**
	* [Testing for Insecure Direct Object References (OTG-AUTHZ-004) - OWASP](https://wiki.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004))
	* [Insecure Direct Object Reference Prevention Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
	* [Airbnb – Web to App Phone Notification IDOR to view Everyone’s Airbnb Messages - Brett Buerhaus](https://buer.haus/2017/03/31/airbnb-web-to-app-phone-notification-idor-to-view-everyones-airbnb-messages/)
	* [How-To: Find IDOR (Insecure Direct Object Reference) Vulnerabilities for large bounty rewards - BugCrowd](https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/)
	* [A Less Known Attack Vector, Second Order IDOR Attacks - Ozgur Alp(2020)](https://blog.usejournal.com/a-less-known-attack-vector-second-order-idor-attacks-14468009781a?gi=49aab32e1f3d)
* **Talks/Presentations/Videos**
* **Tools**
	* [AuthCov](https://github.com/authcov/authcov)
		* AuthCov crawls your web application using a Chrome headless browser while logged in as a pre-defined user. It intercepts and logs API requests as well as pages loaded during the crawling phase. In the next phase it logs in under a different user account, the "intruder", and attempts to access each of one of the API requests or pages discovered previously. It repeats this step for each intruder user defined. Finally it generates a detailed report listing the resources discovered and whether or not they are accessible to the intruder users.

----------------
### Execution After(/Open) Redirect (EAR) <a name="ear"></a>
* **Execution After Redirect**
	* [Execution After Redirect - OWASP](https://www.owasp.org/index.php/Execution_After_Redirect_(EAR))
	* [Overview of Execution After Redirect Web Application Vulnerabilities](https://adamdoupe.com/blog/2011/04/20/overview-of-execution-after-redirect-web-application-vulnerabilities/)
	* [EARs in the Wild: Large-Scale Analysis of Execution After Redirect Vulnerabilities](https://www.cs.ucsb.edu/~vigna/publications/2013_SAC_EARdetect.pdf)
	* [Fear the EAR: Discovering and Mitigating Execution After Redirect Vulnerabilities](http://cs.ucsb.edu/~bboe/public/pubs/fear-the-ear-ccs2011.pdf)
* **Open Redirect**
	* [Open Redirect Payloads](https://github.com/cujanovic/Open-Redirect-Payloads)
	* [Security and Open Redirects  Impact of 301-ing people in 2013](https://makensi.es/rvl/openredirs/#/)

------------
### File Upload Testing <a name="file"></a>
* **101**
	* [Unrestricted File Upload - OWASP](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
	* [File Upload Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
	* [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
* **Articles/Blogposts/Writeups**
	* [Why File Upload Forms are a Major Security Threat - acunetix](https://www.acunetix.com/websitesecurity/upload-forms-threat/)
	* [Unrestricted File Upload Testing](https://www.aptive.co.uk/blog/unrestricted-file-upload-testing/)
	* [BookFresh Tricky File Upload Bypass to RCE - secgeek.net](https://secgeek.net/bookfresh-vulnerability/)
	* [15 Technique to Exploit File Upload Pages - Ebrahim Hegazy(HackIT17)](https://es.slideshare.net/HackIT-ukraine/15-technique-to-exploit-file-upload-pages-ebrahim-hegazy)
	* [File Upload and PHP on IIS: `>=?` and `<=*` and `"=.` - Soroush Dalili](https://soroush.secproject.com/blog/2014/07/file-upload-and-php-on-iis-wildcards/)
	* [Exploiting File Uploads Pt. 1 – MIME Sniffing to Stored XSS #bugbounty - HackerOnTwoWheels(2019)](https://anotherhackerblog.com/exploiting-file-uploads-pt1/)
	* [Bypassing file upload filter by source code review in Bolt CMS - Sivanesh Ashok](https://stazot.com/boltcms-file-upload-bypass/)
	* [Ability to upload HTML via SRT caption files for Facebook Videos - philippeharewood.com(2015)](https://philippeharewood.com/ability-to-upload-html-via-srt-caption-files-for-facebook-videos/)
* **Papers**
	* [FUSE: Finding File Upload Bugs via Penetration Testing - Taekjin Lee, Seongil Wi, Suyoung Lee, Sooel Son](https://www.ndss-symposium.org/wp-content/uploads/2020/02/23126.pdf)
* **Presentations/Talks/Videos**
	* [FUSE: Finding File Upload Bugs via Penetration Testing - Taekjin Lee, Seongil Wi, Suyoung Lee, Sooel Son(NDSS2020)]()
		* An Unrestricted File Upload (UFU) vulnerability is a critical security threat that enables an adversary to upload her choice of a forged file to a target web server. This bug evolves into an Unrestricted Executable File Upload (UEFU) vulnerability when the adversary is able to conduct remote code execution of the uploaded file via triggering its URL. We design and implement FUSE, the first penetration testing tool designed to discover UFU and UEFU vulnerabilities in server-side PHP web applications. The goal of FUSE is to generate upload requests; each request becomes an exploit payload that triggers a UFU or UEFU vulnerability. However, this approach entails two technical challenges: (1) it should generate an upload request that bypasses all content-filtering checks present in a target web application; and (2) it should preserve the execution semantic of the resulting uploaded file. We address these technical challenges by mutating standard upload requests with carefully designed mutation operations that enable the bypassing of content- filtering checks and do not tamper with the execution of uploaded files. FUSE discovered 30 previously unreported UEFU vulnerabilities, including 15 CVEs from 33 real-world web applications, thereby demonstrating its efficacy in finding code execution bugs via file uploads.
		* [Paper](https://www.ndss-symposium.org/wp-content/uploads/2020/02/23126.pdf)
* **Tools**
	* [Anti Malware Testfile - EICAR](https://www.eicar.org/?page_id=3950)
	* [fuxploider](https://github.com/almandin/fuxploider)
		* File upload vulnerability scanner and exploitation tool.

----------------
### HTML Smuggling <a name="hsmug"></a>
* **101**
	* [HTML Smuggling Explained - Stan Hegt](https://outflank.nl/blog/2018/08/14/html-smuggling-explained/)
* **Articles/Blogposts/Writeups**
	* [File Smuggling with HTML and JavaScript - ired.team](https://ired.team/offensive-security/defense-evasion/file-smuggling-with-html-and-javascript)
	* [Strange Bits: HTML Smuggling and GitHub Hosted Malware - gdatasoftware.com](https://www.gdatasoftware.com/blog/2019/05/31695-strange-bits-smuggling-malware-github)
	* [Smuggling HTA files in Internet Explorer/Edge - Richard Warren](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/august/smuggling-hta-files-in-internet-exploreredge/)
* **Tools**
	* [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
	* [Demiguise](https://github.com/nccgroup/demiguise)

----------------
### HTTP Request Smuggling <a name="httprs"></a>
* **101**
	* [HTTP request smuggling - Wikipedia](https://en.wikipedia.org/wiki/HTTP_request_smuggling)
		* HTTP request smuggling is a security exploit on the HTTP protocol that uses inconsistency between the interpretation of Content-length and/or Transfer-encoding headers between HTTP server implementations in an HTTP proxy server chain. It was first documented in 2005, and was again repopularized by PortSwigger's research.
	* [HTTP request smuggling - Portswigger](https://portswigger.net/web-security/request-smuggling)
	* [HTTP Desync Attacks: Request Smuggling Reborn - James Kettle](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
	* [‘HTTP Request Smuggling’ - Securiteam](https://securiteam.com/securityreviews/5gp0220g0u/)
	* [Help you understand HTTP Smuggling in one article - @ZeddYu_Lu](https://blog.zeddyu.info/2019/12/08/HTTP-Smuggling-en/)
* **Articles/Blogposts/Writeups**
	* [Checking HTTP Smuggling issues in 2015 - Part1 - RBleug(2015)](https://regilero.github.io/security/english/2015/10/04/http_smuggling_in_2015_part_one/)
	* [Hiding in plain sight: HTTP request smuggling - Travis Isaacson(2020)](https://blog.detectify.com/2020/05/28/hiding-in-plain-sight-http-request-smuggling/)
	* [Demystifying HTTP request smuggling - Sam Sanoop](https://snyk.io/blog/demystifying-http-request-smuggling/)
	* [The Powerful HTTP Request Smuggling 💪 - Ricardo Iramar dos Santos](https://medium.com/@ricardoiramar/the-powerful-http-request-smuggling-af208fafa142)
		* "TL;DR: This is how I was able to exploit a HTTP Request Smuggling in some Mobile Device Management (MDM) servers and send any MDM command to any device enrolled on them for a private bug bounty program."
	* [h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext (h2c) - Jake Miller(2020)](https://labs.bishopfox.com/tech-blog/h2c-smuggling-request-smuggling-via-http/2-cleartext-h2c)
	* [HTTP Request Smuggling – 5 Practical Tips - Pieter Hiele(2020)](https://honoki.net/2020/02/18/http-request-smuggling-5-practical-tips/)
	* [XXE-scape through the front door: circumventing the firewall with HTTP request smuggling - Pieter Hiele(2020)](https://honoki.net/2020/03/18/xxe-scape-through-the-front-door-circumventing-the-firewall-with-http-request-smuggling/)
* **Performing**
	* [A Pentester’s Guide to HTTP Request Smuggling - Bursa Demir(2020)](https://blog.cobalt.io/a-pentesters-guide-to-http-request-smuggling-8b7bf0db1f0)
	* [Smuggling HTTP headers through reverse proxies - Robin Verton(2020)](http://github.security.telekom.com/2020/05/smuggling-http-headers-through-reverse-proxies.html)	
	* [HTTP Request Smuggling: Abusing Reverse Proxies - Christopher Elgee(2020)](https://www.sans.org/blog/http-request-smuggling-abusing-reverse-proxies/)
	* [WAF Bypass Techniques - Using HTTP Standard and Web Servers’ Behaviour - Soroush Dalili(2018)](https://www.slideshare.net/SoroushDalili/waf-bypass-techniques-using-http-standard-and-web-servers-behaviour)
* **Papers**
	* [HTTP Request Smuggling - Chaim Linhart, Amit Klein, Ronen Heled, Steve Orrin](https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf)
* **Presentations/Talks/Videos**
	* [HTTP Desync Attacks: Smashing into the Cell Next Door - James Kettle(DEFCON27)](https://www.youtube.com/watch?v=w-eJM2Pc0KI)
		* HTTP requests are traditionally viewed as isolated, standalone entities. In this session, I'll introduce techniques for remote, unauthenticated attackers to smash through this isolation and splice their requests into others, through which I was able to play puppeteer with the web infrastructure of numerous commercial and military systems, rain exploits on their visitors, and harvest over $50k in bug bounties.  Using these targets as case studies, I’ll show you how to delicately amend victim's requests to route them into malicious territory, invoke harmful responses, and lure credentials into your open arms. I’ll also demonstrate using backend reassembly on your own requests to exploit every modicum of trust placed on the frontend, gain maximum privilege access to internal APIs, poison web caches, and compromise my favourite login page.  Although documented over a decade ago, a fearsome reputation for difficulty and collateral damage has left this attack optimistically ignored for years while the web's susceptibility grew. By applying fresh ideas and new techniques, I’ll unveil a vast expanse of vulnerable systems ranging from huge content delivery networks to bespoke backends, and ensure you leave equipped to devise your own desync techniques and tailor attacks to your target of choice.
	* [Hiding Wookiees in HTTP: HTTP smuggling - regilero(Defcon24)](https://www.youtube.com/watch?v=dVU9i5PsMPY)
		* HTTP is everywhere, everybody wants to write an HTTP server. So I wrote mine :-) But mine not fast, and come with an HTTP client which sends very bad HTTP queries. My tool is a stress tester for HTTP servers and proxies, and I wrote it because I found flaws in all HTTP agents that I have checked in the last year i.e. nodejs, golang, Apache httpd, FreeBSD http, Nginx, Varnish and even Haproxy. This presentation will try to explain how flaws in HTTP parsers can be exploited for bad things; we'll play with HTTP to inject unexpected content in the user browser, or perform actions in his name. If you know nothing about HTTP it should be understandable, but you'll have to trust me blindly at the end. If you think you know HTTP, you have no reason to avoid this talk. Then, the short part, I will show you this new Open Source stress tool that I wrote and hope that you will remember it when you'll write your own HTTP parser for you new f** language.
	* [Practical Attacks using HTTP Request Smuggling - @defparam(#NahamCon2020)](https://www.youtube.com/watch?v=3tpnuzFLU8g)
	* [HTTP Request Smuggling in 2020 – New Variants, New Defenses and New Challenges - Amit Klein(BHUSA2020)](https://www.blackhat.com/us-20/briefings/schedule/#http-request-smuggling-in---new-variants-new-defenses-and-new-challenges-20019)
		* [Slides](https://i.blackhat.com/USA-20/Wednesday/us-20-Klein-HTTP-Request-Smuggling-In-2020-New-Variants-New-Defenses-And-New-Challenges.pdf)
		* [Paper](https://i.blackhat.com/USA-20/Wednesday/us-20-Klein-HTTP-Request-Smuggling-In-2020-New-Variants-New-Defenses-And-New-Challenges-wp.pdf)
* **Tools**
	* [Smuggler](https://github.com/defparam/smuggler)
		* An HTTP Request Smuggling / Desync testing tool written in Python 3
	* [HTTPWookie](https://github.com/regilero/HTTPWookiee)
		*  HTTPWookiee is an HTTP server and proxy stress tool (respect of RFC, HTTP Smuggling issues, etc). If you run an HTTP server project contact me for private repository access with more tests.

----------------
### Image-based Exploitation AKA Exploiting Polyglot features of File standards <a name="ibe"></a>
* **101**
	* [Graphics Interchange Format Java Archives (GIFAR) - Wikipedia](https://en.wikipedia.org/wiki/Gifar)
* **Articles/Blogposts/Writeups**
	* [Revisiting XSS payloads in PNG IDAT chunks - Adam Logue](https://www.adamlogue.com/revisiting-xss-payloads-in-png-idat-chunks/)
	* [An XSS on Facebook via PNGs & Wonky Content Types - jack@whitton.io](https://whitton.io/articles/xss-on-facebook-via-png-content-types/)
	* [Encoding Web Shells in PNG IDAT chunks - idontplaydarts](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
	* [Bypassing CSP using polyglot JPEGs - Gareth Heyes](https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs)
	* [Hacking group using Polyglot images to hide malvertising attacks - Josh Summit](https://devcondetect.com/blog/2019/2/24/hacking-group-using-polyglot-images-to-hide-malvertsing-attacks)
	* [BMP/x86 Polyglot - steiner@warroom.securestate](https://warroom.securestate.com/bmp-x86-polyglot/)
	* [Upload a web.config File for Fun & Profit - Soroush Dalili](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/)
	* [Uploading web.config for Fun and Profit 2 - Soroush Dalili](https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/)
	* [Encoding Web Shells in PNG IDAT chunks - phil](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
* **Tools**
	* [xss2png](https://github.com/vavkamil/xss2png)
		* A simple tool to generate PNG images with XSS payloads stored in PNG IDAT chunks
	* [pixload](https://github.com/chinarulezzz/pixload)
		* Set of tools for creating/injecting payload into images.
	* [PNG-IDAT-Payload-Generator](https://github.com/huntergregal/PNG-IDAT-Payload-Generator)
		* Generate a PNG with a payload embedded in the IDAT chunk (Based off of previous concepts and code -- credit in README)
	* [Imagecreatefromgif-Bypass](https://github.com/JohnHoder/Imagecreatefromgif-Bypass)

----------------
### Injection Based Attacks <a name="ija"></a>
* **101**
* **Articles/Blogposts/Writeups**
	* [Exploiting ShellShock getting a reverse shell](http://www.fantaghost.com/exploiting-shellshock-getting-reverse-shell)
	* [Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)
	* [Exploiting Python Code Injection in Web Applications - sethsec](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)
* **Command Injection**
	* **101**
	* **Tools**
	* **Resources**
		* [FuzzDB OS Cmd Injection List](https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/os-cmd-execution)
* **JSON(P) Injection**
	* **101**
		* [What Are JSON Injections - Tomasz Andrzej Nidecki(2019)](https://www.acunetix.com/blog/web-security-zone/what-are-json-injections/)
	* **Articles/Blogposts/Writeups**
		* [Handling Untrusted JSON Safely - Jim Manico(2013)](https://www.whitehatsec.com/blog/handling-untrusted-json-safely/)
		* [DOM-based client-side JSON injection - PortSwigger](https://portswigger.net/web-security/dom-based/client-side-json-injection)
		* [Practical JSONP Injection - Petre Popescu(2018)](https://securitycafe.ro/2017/01/18/practical-jsonp-injection/)
		* [Hacking JWT Tokens: JSON Injection - Shivam Bathla(2020)](https://blog.pentesteracademy.com/hacking-jwt-tokens-json-injection-89ac555c484c?gi=2afc23113d06)
	* **Talks/Presentations/Videos**
		* [Web PenTesting Workshop Part 12 of 12 JSON injection - Jeremy Druin](https://www.youtube.com/watch?v=ZLAaq7Q-5jc)
			* Video from the ISSA Kentuckiana Web Pen-Testing Workshop.
	* **Tools**
	* **Resources**
		* [Lab: JSON Injection](https://github.com/enygma/h2-json-injection)
		* [AJAX Security Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html#Protect_against_JSON_Hijacking_for_Older_Browsers)	
* **Papers**
* **Presentations/Talks/Videos**
	* [Popular Approaches to Preventing Code Injection Attacks are Dangerously Wrong - AppSecUSA 2017](https://www.youtube.com/watch?v=GjK0bB4K2zA&app=desktop)
	* [Remote Code Execution in Firefox beyond memory corruptions(2019) - Frederik Braun](https://frederik-braun.com/firefox-ui-xss-leading-to-rce.html)
		* Browsers are complicated enough to have attack surface beyond memory safety issues. This talk will look into injection flaws in the user interface of Mozilla Firefox, which is implemented in JS, HTML, and an XML-dialect called XUL. With an Cross-Site Scripting (XSS) in the user interface attackers can execute arbitrary code in the context of the main browser application process. This allows for cross-platform exploits of high reliability. The talk discusses past vulnerabilities and will also suggest mitigations that benefit Single Page Applications and other platforms that may suffer from DOM-based XSS, like Electron.
* **Tools**
* See also: JNDI, JSON, SQLi, XSS

----------------
### OS Command Injection <a name="osci"></a>
* **General**
	* [Command Injection - OWASP](https://www.owasp.org/index.php/Command_Injection)
* **Testing**
	* [Testing for Command Injection - OWASP](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013))
	* [How To: Command Injections - Hackerone](https://www.hackerone.com/blog/how-to-command-injections)
	* [Data Exfiltration via Blind OS Command Injection](https://www.contextis.com/blog/data-exfiltration-via-blind-os-command-injection)
* **Tools**
	* [commix](https://github.com/stasinopoulos/commix)
		* Automated All-in-One OS Command Injection and Exploitation Tool
	* [SHELLING](https://github.com/ewilded/shelling)
		* A comprehensive OS command injection payload generator

----------------
### JNDI Attack Class <a name="jndi"></a>
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

----------------
### Path Confusion Attacks <a name="pca"></a>
* **101**
* **Articles/Papers/Writeups**

----------------
### LFI & RFI <a name="lrfi"></a>
* **101**
	* [File inclusion vulnerability - Wikipedia](https://en.wikipedia.org/wiki/File_inclusion_vulnerability)
* **Articles/Papers/Writeups**
	* [LFI with PHPINFO() Assistance - InsomniaSecurity 2011](https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf)
	* [Turning LFI into RFI](https://l.avala.mp/?p=241)
		* When configured in a specific way the web application would load the JAR file and search within the file for a class. Interestingly enough, in Java classes you can define a static block that is executed upon the class being processed
	* [Unrestricted File Upload Security Testing - Aptive](https://www.aptive.co.uk/blog/unrestricted-file-upload-testing/)
	* [LFI2RCE (Local File Inclusion to Remote Code Execution) advanced exploitation: /proc shortcuts](http://www.ush.it/2008/08/18/lfi2rce-local-file-inclusion-to-remote-code-execution-advanced-exploitation-proc-shortcuts/)
		* This paper exposes the ability from the attacker standpoint to use /proc in order to exploit LFI (Local File Inclusion) vulnerabilities.
	* [Turning LFI to RFI ](https://l.avala.mp/?p=241)
	* [Local file inclusion tricks](http://devels-playground.blogspot.fr/2007/08/local-file-inclusion-tricks.html)
	* [Upgrade from LFI to RCE via PHP Sessions](https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)
	* [CVV #1: Local File Inclusion - SI9INT](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
	* [Exploiting Blind File Reads / Path Traversal Vulnerabilities on Microsoft Windows Operating Systems - @evisneffos]
	* [File Inclusion - nets.ec](https://nets.ec/File_Inclusion)
	* [SMTP Log Poisioning through LFI to Remote Code Excecution - Raj Chandel](https://www.hackingarticles.in/smtp-log-poisioning-through-lfi-to-remote-code-exceution/)
* **Cheat Sheets/Reference Lists**
	* [HighOn.coffee LFI Cheat](https://highon.coffee/blog/lfi-cheat-sheet/)
	* [Local File Inclusion (LFI) [Definitive Guide] - aptive.co.uk](https://www.aptive.co.uk/blog/local-file-inclusion-lfi-testing/)
* **Testing**
	* [OWASP LFI](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
	* [LFI Local File Inclusion Techniques (paper)](http://www.ush.it/2008/08/18/lfi2rce-local-file-inclusion-to-remote-code-execution-advanced-exploitation-proc-shortcuts/)
		* This paper exposes the ability from the attacker standpoint to use /proc in order to exploit LFI (Local File Inclusion) vulnerabilities. While using /proc for such aim is well known this one is a specific technique that was not been previously published as far as we know. A tool to automatically exploit LFI using the shown approach is released accordingly.
	* [Local File Inclusion (LFI) of session files to root escalation - ush.it(2008)](http://www_ush_it/2008/07/09/local-file-inclusion-lfi-of-session-files-to-root-escalation/)
	* [Windows Blind Files Collection - 0xsp](https://0xsp.com/offensive/windows-blind-files-collection)
* **Tools**
	* [dotdotpwn](https://github.com/wireghoul/dotdotpwn)
	* [Liffy](https://github.com/rotlogix/liffy)
		* Liffy is a Local File Inclusion Exploitation tool.
	* [lfi-labs](https://github.com/paralax/lfi-labs)
		* small set of PHP scripts to practice exploiting LFI, RFI and CMD injection vulns
	* [psychoPATH - LFI](https://github.com/ewilded/psychoPATH/blob/master/README.md)
		* This tool is a highly configurable payload generator detecting LFI & web root file uploads. Involves advanced path traversal evasive techniques, dynamic web root list generation, output encoding, site map-searching payload generator, LFI mode, nix & windows support plus single byte generator.
	* [Kadimus](https://github.com/P0cL4bs/Kadimus)
		* Kadimus is a tool to check sites to lfi vulnerability , and also exploit it
	* [lfipwn](https://github.com/m101/lfipwn)
	* [LFISuite](https://github.com/D35m0nd142/LFISuite)

----------------
### (No)SQL Injection <a name="sqli"></a>
* **101**
	* [NT Web Technology Vulnerabilities - rain.forest.puppy](http://phrack.org/issues/54/8.html)
	* [NT Web Technology Vulnerabilities - rain.forest.puppy](http://phrack.org/issues/54/8.html)
		* First public writeup of SQLi
	* ["How I hacked PacketStorm" - rain forest puppy](http://www.ouah.org/rfp.txt)
	* [SQL injection - PortSwigger](https://portswigger.net/web-security/sql-injection)
	* [Basic of SQL for SQL Injection - SecurityIdiots](http://www.securityidiots.com/Web-Pentest/SQL-Injection/Part-1-Basic-of-SQL-for-SQLi.html)
* **Reference**
	* [SQL Injection Knowledge Base](http://websec.ca/kb/sql_injection#MySQL_Testing_Injection)
	* [SQL Injection Cheat Sheet](http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/)
	* [SQL Injection Cheat Sheet - NetSparker](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
	* [SQL Injection wiki](http://www.sqlinjectionwiki.com/)
	* [Your Pokemon Guide for Essential SQL Pen Test Commands - Joshua Wright(2017)](https://www.sans.org/blog/your-pokemon-guide-for-essential-sql-pen-test-commands/)
* **General Articles/Blogposts/Writeups**
	* [Finding SQL injections fast with white-box analysis — a recent bug example - Frycos](https://medium.com/@frycos/finding-sql-injections-fast-with-white-box-analysis-a-recent-bug-example-ca449bce6c76)
	* [Blind (time-based) SQLi - Bug Bounty - jspin.re](https://jspin.re/fileupload-blind-sqli/)
	* [SELECT code_execution FROM * USING SQLite; Gaining code execution using a malicious SQLite database - Omer Gull](https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/)
	* [Beyond SQLi: Obfuscate and Bypass - CWH Underground](https://www.exploit-db.com/papers/17934/)
	* [Second Order SQLI: Automating with sqlmap - Jorge Lajara(2019)](https://jlajara.gitlab.io/web/2019/04/29/Second_order_sqli.html)
	* [Advanced boolean-based SQLi filter bypass techniques - theMiddle(2020)](https://www.secjuice.com/advanced-sqli-waf-bypass/)
	* [Hunting for SQL injections (SQLis) and Cross-Site Request Forgeries (CSRFs) in WordPress Plugins - Alex Pena(2020)](https://medium.com/tenable-techblog/hunting-for-sql-injections-sqlis-and-cross-site-request-forgeries-csrfs-in-wordpress-plugins-632dafc9cd2f)
	* [SELECT code_execution FROM * USING SQLite; - Omer Gull(2019)](https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/)
	* [SQL Injection filter bypass to perform blind SQL Injection - mannulinux.org(2020)](http://www.mannulinux.org/2020/09/sql-injection-filter-bypass-to-perform.html)
* **Papers**
	* [SQL Injection In Insert, Update, And Delete - Osanda Malith(2014)](https://packetstormsecurity.com/files/126527/SQL-Injection-In-Insert-Update-And-Delete.html)
* **Talks/Presentations/Videos**
	* [Time-Based Blind SQL Injection using Heavy Queries: A practical approach for MS SQL Server, MS Access, Oracle and MySQL databases and Marathon Tool - Chema Alonso, Daniel Kachakil, Rodolfo Bordón, Antonio Guzmán y Marta Beltrán(Defcon16)](https://www.defcon.org/images/defcon-16/dc16-presentations/alonso-parada/defcon-16-alonso-parada-wp.pdf)
		*
* **Writeups**
	* [Use google bots to perform SQL injections on websites](http://blog.sucuri.net/2013/11/google-bots-doing-sql-injection-attacks.html)
	* [Performing sqlmap POST request injection](https://hackertarget.com/sqlmap-post-request-injection/)
* **Training**
	* [SQLi Lab lessons](https://github.com/Audi-1/sqli-labs)
		* SQLI-LABS is a platform to learn SQLI
* **NoSQL**
	* **Articles/Blogposts/Writeups**
		* [NoSQL Injection in Modern Web Applications - petecorey.com](http://www.petecorey.com/blog/2016/03/21/nosql-injection-in-modern-web-applications/)
		* [N1QL Injection: Kind of SQL Injection in a NoSQL Database - Krzysztof Pranczk(2020)](https://labs.f-secure.com/blog/n1ql-injection-kind-of-sql-injection-in-a-nosql-database/)
	* **MeteorJS**
		* [Meteor Blind NoSQL Injection - Kert Ojasoo(2019)](https://medium.com/rangeforce/meteor-blind-nosql-injection-29211775cd01)
	* **MongoDB**
		* [Making Mongo Cry Attacking NoSQL for Pen Testers Russell Butturini](https://www.youtube.com/watch?v=NgsesuLpyOg)
		* [MongoDB: Typical Security Weaknesses in a NoSQL DB](http://blog.spiderlabs.com/2013/03/mongodb-security-weaknesses-in-a-typical-nosql-database.html)
		* [MongoDB Pentesting for Absolute Beginners](https://github.com/nixawk/pentest-wiki/blob/master/2.Vulnerability-Assessment/Database-Assessment/mongodb/MongoDB%20Pentesting%20for%20Absolute%20Beginners.pdf)
		* [A NoSQL Injection Primer (with Mongo) - Charlie Belmer(2020)](https://nullsweep.com/a-nosql-injection-primer-with-mongo/)
	* **Talks/Presentations/Videos**
		* [ Making Mongo Cry-Attacking NoSQL for Pen Testers - Russell Butturrini(Derbycon2014)](https://www.irongeek.com/i.php?page=videos/derbycon4/t408-making-mongo-cry-attacking-nosql-for-pen-testers-russell-butturini)
			* NoSQL databases continue to grow in popularity due to their scalability, dynamic data structures, ease of development and cloud readiness. As these types of databases become more prevalent, penetration testers need to understand how these databases work, how applications interact with them, and where the inherent weaknesses of NoSQL databases are. This presentation is targeted towards penetration testers and putting the theoretical attacks researchers have discussed into practice during a penetration testing engagement. It will discuss weaknesses with a particular focus on MongoDB and how to quickly and easily exploit them as well as where the high value targets in the system are post exploitation. NoSQLMap, a Python tool written for automatically stealing data from NoSQL database servers and web applications, will also be demoed.
		* [Abusing NoSQL Databases - Ming Chow](https://www.youtube.com/watch?v=lcO1BTNh8r8)
			* [Slides](https://www.defcon.org/images/defcon-21/dc-21-presentations/Chow/DEFCON-21-Chow-Abusing-NoSQL-Databases.pdf)
			* The days of selecting from a few SQL database options for an application are over. There is now a plethora of NoSQL database options to choose from: some are better than others for certain jobs. There are good reasons why developers are choosing them over traditional SQL databases including performance, scalabiltiy, and ease-of-use. Unfortunately like for many hot techologies, security is largely an afterthought in NoSQL databases. This short but concise presentation will illustrate how poor the quality of security in many NoSQL database systems is. This presentation will not be confined to one particular NoSQL database system. Two sets of security issues will be discussed: those that affect all NoSQL database systems such as defaults, authentication, encryption; and those that affect specific NoSQL database systems such as MongoDB and CouchDB. The ideas that we now have a complicated heterogeneous problem and that defense-in-depth is even more necessary will be stressed. There is a common misconception that SQL injection attacks are eliminated by using a NoSQL database system. While specifically SQL injection is largely eliminated, injection attack vectors have increased thanks to JavaScript and the flexibility of NoSQL databases. This presentation will present and demo new classes of injection attacks. Attendees should be familiar with JavaScript and JSON.
	* **Papers**
		* [No SQL, No Injection? - Examining NoSQL Security - Aviv Ron, Alexandra Shulman-Peleg, Emanuel Bronshtein](https://arxiv.org/pdf/1506.04082.pdf)
			* NoSQL data storage systems have become very popular due to their scalability and ease of use. This paper examines the maturity of security measures for NoSQL databases, addressing their new query and access mechanisms. For example the emergence of new query formats makes the old SQL injection techniques irrelevant, but are NoSQL databases immune to injection in general? The answer is NO. Here we present a few techniques for attacking NoSQL databases such as injections and CSRF. We analyze the source of these vulnerabilities and present methodologies to mitigate the attacks. We show that this new vibrant technological area lacks the security measures and awareness which havedeveloped over the years in traditional RDBMSSQL systems.
	* **Tools**	
		* [Nosql-Exploitation-Framework](https://github.com/torque59/Nosql-Exploitation-Framework)
			* A FrameWork For NoSQL Scanning and Exploitation Framework
		* [NoSQL Injector](https://github.com/Charlie-belmer/nosqli)
			* NoSQL scanner and injector.
* **DB2**
	* [DB2 SQL injection cheat sheet](https://securityetalii.es/2012/05/20/db2-sql-injection-cheat-sheet/)
* **MongoDB**
	* **101**
		* [Intro to Hacking Mongo DB - SecuritySynapse](https://securitysynapse.blogspot.com/2015/07/intro-to-hacking-mongo-db.html)
		* [Attacking MongoDB - ZeroNights2012](http://blog.ptsecurity.com/2012/11/attacking-mongodb.html)
		* [MongoDB Injection - How To Hack MongoDB](http://www.technopy.com/mongodb-injection-how-to-hack-mongodb-html/)
		* [Hacking NodeJS and MongoDB - websecurify](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)
	* **Tools**
		* [mongoaudit](https://github.com/stampery/mongoaudit)
			* mongoaudit is a CLI tool for auditing MongoDB servers, detecting poor security settings and performing automated penetration testing.
		* [mongot](https://github.com/dstours/mongot)
			* mongot makes it easy to extract data from open MongoDB's. By specifying an IP/port with the -d/-p parameters, mongot will connect to an open MongoDB, display any identified database names, collections, and a small sample of data in each.
* **MS-SQL**
	* [Pen test and hack microsoft sql server (mssql)](http://travisaltman.com/pen-test-and-hack-microsoft-sql-server-mssql/)
* **MySQL**
	* **101**
		* [](https://dev.mysql.com/doc/refman/8.0/en/select.html)
	* **Articles/Blogposts/Writeups**
		* [MySQL UDF Exploitation](https://osandamalith.com/2018/02/11/mysql-udf-exploitation/)
* **Oracle SQL**
	* **101**
		* [Oracle SQL Injection Guides & Whitepapers](https://haiderm.com/oracle-sql-injection-guides-and-whitepapers/)
	* **Articles/Blogposts/Writeups**
* **PostgreSQL**
	* **101**
		* [PostgreSQL Documentation: Ch4 SQL Syntax: Lexical Structure](https://www.postgresql.org/docs/9.0/sql-syntax-lexical.html)
	* **Articles/Blogposts/Writeups**
		* [PostgreSQL Pass The Hash protocol design weakness](https://hashcat.net/misc/postgres-pth/postgres-pth.pdf)
		* [Ultimate Guide: PostgreSQL Pentesting - Shlok Yadav(2020)](https://medium.com/@lordhorcrux_/ultimate-guide-postgresql-pentesting-989055d5551e)
		* [A Penetration Tester’s Guide to PostgreSQL - David Hayter(2017)](https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9)
		* [Attacking Dell Foglight Server - infosecaddicts.com(2017)](https://infosecaddicts.com/attacking-dell-foglight-server/)
		* [Postgres “unsupported frontend protocol” mystery - Greg Sabino Mullane(2015)](https://www.endpoint.com/blog/2015/05/28/postgres-unsupported-frontend-protocol)
		* [SQL Injection Double Uppercut :: How to Achieve Remote Code Execution Against PostgreSQL - Steven Seeley](https://srcincite.io/blog/2020/06/26/sql-injection-double-uppercut-how-to-achieve-remote-code-execution-against-postgresql.html)
* **Ruby on Rails (ActiveRecord)**
	* [rails-sqli.org](https://rails-sqli.org/)
* **Tools**
	* [sqlmap](https://github.com/sqlmapproject/sqlmap)
	* [jSQL Injection](https://github.com/ron190/jsql-injection)
		* jSQL Injection is a Java application for automatic SQL database injection.
	* [mongoaudit](https://github.com/stampery/mongoaudit)
	* [Laduanum](http://laudanum.sourceforge.net/)
		* “Laudanum is a collection of injectable files, designed to be used in a pentest when SQL injection flaws are found and are in multiple languages for different environments.They provide functionality such as shell, DNS query, LDAP retrieval and others.”
	* [GraFScaN](https://github.com/grafscan/GraFScaN)
	* [Albatar](https://github.com/lanjelot/albatar)
		* Albatar is a SQLi exploitation framework in Python

----------------
### Path Traversal Attacks <a name="pta"></a>
* **101**
	* [Exploiting PHP File Inclusion – Overview](https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/)
* **Articles/Blogposts/Writeups**
	* [Exploiting Blind File Reads / Path Traversal Vulnerabilities on Microsoft Windows Operating Systems - soffensive](https://www.soffensive.com/2018/06/exploiting-blind-file-reads-path.html)
	* [RCE using Path Traversal - inc0gbyt3](https://incogbyte.github.io/pathtraversal/)
	* [Zip Slip Vulnerability - snyk.io](https://snyk.io/research/zip-slip-vulnerability)
	* [Exploiting Blind File Reads / Path Traversal Vulnerabilities on Microsoft Windows Operating Systems - soffensive](http://www.soffensive.com/2018/06/exploiting-blind-file-reads-path.html)
* **Tools**
	* [dotdotpwn](https://github.com/wireghoul/dotdotpwn)
		* It's a very flexible intelligent fuzzer to discover traversal directory vulnerabilities in software such as HTTP/FTP/TFTP servers, Web platforms such as CMSs, ERPs, Blogs, etc.

-------------
### Prototype Pollution Attack <a name="ppa"></a>
* **101**
	* [Maintainable JavaScript: Don’t modify objects you don’t own - Nicholas C. Zakas](https://humanwhocodes.com/blog/2010/03/02/maintainable-javascript-dont-modify-objects-you-down-own/)
	* [What is Prototype Pollution? - Changhui Xu](https://codeburst.io/what-is-prototype-pollution-49482fc4b638)
	* [What is prototype pollution and why is it such a big deal? - Dani Akash](https://medium.com/node-modules/what-is-prototype-pollution-and-why-is-it-such-a-big-deal-2dd8d89a93c)
* **Articles/Blogposts/Writeups**
	* [Prototype Pollution Affecting jquery package, versions <3.4.0 - snyk.io](https://snyk.io/vuln/SNYK-JS-JQUERY-174006)
	* [After three years of silence, a new jQuery prototype pollution vulnerability emerges once again - Liran Tal](https://snyk.io/blog/after-three-years-of-silence-a-new-jquery-prototype-pollution-vulnerability-emerges-once-again/)
	* [Prototype pollution attack (lodash) - holyvier](https://hackerone.com/reports/310443)
	* [Inheritance and the prototype chain - MozillaDevNetwork](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Inheritance_and_the_prototype_chain)
	* [Prototype pollution attack through jQuery $.extend - Asger Feldthaus(HackerOne)](https://hackerone.com/reports/454365)
	* [Analysis and Exploitation of Prototype Pollution attacks on NodeJs - Nullcon HackIM CTF web 500 writeup - Anirudh Anand](https://blog.0daylabs.com/2019/02/15/prototype-pollution-javascript/)
	* [Prototype Pollution - Michal Bentkowski](https://slides.com/securitymb/prototype-pollution-in-kibana/#/)
	* [Exploiting prototype pollution – RCE in Kibana (CVE-2019-7609) - Michal Bentkowski](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)
* **Presentations, Talks, Videos**
	* [Prototype pollution attack - HoLyVieR](https://github.com/HoLyVieR/prototype-pollution-nsec18)
		* "Content released at NorthSec 2018 for my talk on prototype pollution"
		* [Slides](https://github.com/HoLyVieR/prototype-pollution-nsec18/tree/master/slides)
		* [Paper](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)
* **Tools**

-------------
### Reflected File Download <a name="rfd"></a>
* **101**
* **Articles/Blogposts/Writeups**
* **Talks/Presentations/Videos**
	* [Reflected File Download - A New Web Attack Vector - BHEU 2014](https://www.youtube.com/watch?v=dl1BJUNk8V4)
		* Skip to 19:24 for technical content
	* [Paper](https://drive.google.com/file/d/0B0KLoHg_gR_XQnV4RVhlNl96MHM/view)
* **Tools**

----------------
### Relative Path Overwrite <a name="rpo"></a>
* **101**
	* [Relative Path Overwrite Explanation/Writeup](http://www.thespanner.co.uk/2014/03/21/rpo/)
		* RPO (Relative Path Overwrite) is a technique to take advantage of relative URLs by overwriting their target file. To understand the technique we must first look into the differences between relative and absolute URLs. An absolute URL is basically the full URL for a destination address including the protocol and domain name whereas a relative URL doesn’t specify a domain or protocol and uses the existing destination to determine the protocol and domain.
* **Articles/Blogposts/Writeups**
	* [A few RPO exploitation techniques - Takeshi Terada](https://www.mbsd.jp/Whitepaper/rpo.pdf)
	* [Non-Root-Relative Path Overwrite (RPO) in IIS and .Net applications - soroush.techproject](https://soroush.secproject.com/blog/tag/non-root-relative-path-overwrite/)
* **Talks/Presentations/Videos**
* **Papers**
	* [Understanding and Mitigating theSecurity Risks of ContentInclusion in Web Browsers - Sajjad Arshad(2020)](https://arxiv.org/pdf/2001.03643.pdf)
		* In this thesis, I propose novel research into understanding and mitigatingthe security risks of content inclusion in web browsers to protect website pub-lishers as well as their users. First, I introduce an in-browser approach calledExcisionto automatically detect and block malicious third-party content in-clusions as web pages are loaded into the user’s browser or during the execu-tion of browser extensions. Then, I proposeOriginTracer, an in-browserapproach to highlight extension-based content modification of web pages. Fi-1 nally, I present the first in-depth study of style injection vulnerability usingRPO and discuss potential countermeasures
* **Tools**

----------------
### (De-)Serialization Attacks <a name="serialization"></a>
* **General**
	* **Articles/Blogposts/Writeups**
		* [OWASP Wiki](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
* **.NET**
	* **Articles/Blogposts/Writeups**
		* [.NET Serialization: Detecting and defending vulnerable endpoints - Alvaro Munoz](https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints)
		* [ASP.NET resource files (.RESX) and deserialisation issues - Soroush Dalili](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/)
		* [RCEVIL.NET: A Super Serial Story - Jared McLaren(BSides Iowa2019)](https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf)
		* [HITCON 2018: Why so Serials? Write-up - cyku.tw](https://cyku.tw/ctf-hitcon-2018-why-so-serials/)
		* [HITCON CTF 2018 - Why so Serials? Writeup - Orange](https://xz.aliyun.com/t/3019)
	* **Talks/Presentations/Videos**
	* **Papers**
	* **Tools**
		* [YSoSerial.Net](https://github.com/pwntester/ysoserial.net)
			* ysoserial.net is a collection of utilities and property-oriented programming "gadget chains" discovered in common .NET libraries that can, under the right conditions, exploit .NET applications performing unsafe deserialization of objects. The main driver program takes a user-specified command and wraps it in the user-specified gadget chain, then serializes these objects to stdout. When an application with the required gadgets on the classpath unsafely deserializes this data, the chain will automatically be invoked and cause the command to be executed on the application host.
* **Java**
	* **Articles/Blogposts/Writeups**
		* [New Exploit Technique In Java Deserialization Attack (BlackHat EU 2019)](https://i.blackhat.com/eu-19/Thursday/eu-19-Zhang-New-Exploit-Technique-In-Java-Deserialization-Attack.pdf)
		* [Pentesting J2EE - Marc Schönefeld(BlackHat 2006)](https://www.blackhat.com/presentations/bh-federal-06/BH-Fed-06-Schoenefeld-up.pdf)
		* [Java Deserialization Security FAQ](https://christian-schneider.net/JavaDeserializationSecurityFAQ.html)
		* [The Perils of Java Deserialization](http://community.hpe.com/hpeb/attachments/hpeb/off-by-on-software-security-blog/722/1/HPE-SR%20whitepaper%20java%20deserialization%20RSA2016.pdf)
		* [Detecting deserialization bugs with DNS exfiltration](http://gosecure.net/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltration/)
		* [Reliable discovery and Exploitation of Java Deserialization vulns](https://techblog.mediaservice.net/2017/05/reliable-discovery-and-exploitation-of-java-deserialization-vulnerabilities/)
		* [Fastjson: exceptional deserialization vulnerabilities - Peter Stockli(2020)](https://www.alphabot.com/security/blog/2020/java/Fastjson-exceptional-deserialization-vulnerabilities.html)
		* [Liferay Portal JSON Web Service RCE Vulnerabilities - Markus Wulftange(2020)](https://codewhitesec.blogspot.com/2020/03/liferay-portal-json-vulns.html)
	* **General**
		* [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
			* A cheat sheet for pentesters about Java Native Binary Deserialization vulnerabilities
	* **Presentations/Talks/Videos**
		* [Pwning Your Java Messaging With De- serialization Vulnerabilities](https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities-wp.pdf)
		* [Marshalling Pickles - Chris Frohoff, Gabe Lawrence(AppSecCali 2015)](https://frohoff.github.io/appseccali-marshalling-pickles/)
			* [Slides](https://github.com/frohoff/appseccali-marshalling-pickles)
			* Object serialization technologies allow programs to easily convert in-memory objects to and from various binary and textual data formats for storage or transfer – but with great power comes great responsibility, because deserializing objects from untrusted data can ruin your day. We will look at historical and modern vulnerabilities across different languages and serialization technologies, including Python, Ruby, and Java, and show how to exploit these issues to achieve code execution. We will also cover some strategies to protect applications from these types of attacks.
		* [Exploiting Deserialization Vulnerabilities in Java - Matthis Kaiser(2015)](https://www.youtube.com/watch?v=VviY3O-euVQ)
			* Deserialization vulnerabilities in Java are lesser known and exploited (compared to unserialize() in PHP). This talk will give insights how this bug class can be turned into serverside Remote Code Execution. Details and a demo will be given for one of my patched vulnerabilities (CVE-2015-6576, Atlassian Bamboo RCE).
		* [Deserialize My Shorts Or How I Learned to Start Worrying and Hate Java Object Deserialization - Chris Frohoff, Gabe Lawrence](https://frohoff.github.io/owaspsd-deserialize-my-shorts/)
			* [Slides](https://www.slideshare.net/frohoff1/deserialize-my-shorts-or-how-i-learned-to-start-worrying-and-hate-java-object-deserialization)
			* Object deserialization is an established but poorly understood attack vector in applications that is disturbingly prevalent across many languages, platforms, formats, and libraries. In January 2015 at AppSec California, Chris Frohoff and Gabe Lawrence gave a talk on this topic, covering deserialization vulnerabilities across platforms, the many forms they take, and places they can be found. It covered, among other things, somewhat novel techniques using classes in commonly used libraries for attacking Java serialization that were subsequently released in the form of the ysoserial tool. Few people noticed until late 2015, when other researchers used these techniques/tools to exploit well known products such as Bamboo, WebLogic, WebSphere, ApacheMQ, and Jenkins, and then services such as PayPal. Since then, the topic has gotten some long-overdue attention and great work is being done by many to improve our understanding and developer awareness on the subject. This talk will review the details of Java deserialization exploit techniques and mitigations, as well as report on some of the recent (and future) activity in this area.
		* [Automated Discovery of Deserialization Gadget Chains - Ian Haken(Defcon26)](https://www.youtube.com/watch?v=wPbW6zQ52w8)
		* [In-Memory Data Grid Applications: Finding Common Java Deserialization Vulnerabilities with CodeQL - Man Yue Mo(2019)](https://securitylab.github.com/research/in-memory-data-grid-vulnerabilities)
		* [Oracle Java Deserialization Vulnerabilities - Stephen Kost, Phil Reimann(2016)](https://www.youtube.com/watch?v=oZPZLiY2PeA)
			* Java deserialization is a class of security vulnerabilities that can result in server-side remote code execution (RCE). As many Oracle products are based on Java, deserialization bugs are found in many Oracle environments especially those using Oracle WebLogic, Oracle Fusion Middleware, and Oracle E-Business Suite. As an example, in November 2015 Oracle released an out-of-cycle security fix (CVE-2015-4852) in order to fix a deserialization bug in Oracle WebLogic. This education webinar provides an understanding of Java deserialization vulnerabilities, the potential impact for Oracle environments, and strategies to protect an Oracle environment from this class of security vulnerabilities.
		* [Defending against Java Deserialization Vulnerabilities - Luca Carettoni(2016)](https://www.ikkisoft.com/stuff/Defending_against_Java_Deserialization_Vulnerabilities.pdf)
		* [Deserialization: what, how and why [not] - Alexei Kojenov(AppSecUSA2018)](https://www.youtube.com/watch?v=t-zVC-CxYjw)
			* Insecure deserialization was recently added to OWASP's list of the top 10 most critical web application security risks, yet it is by no means a new vulnerability category. For years, data serialization and deserialization have been used in applications, services and frameworks, with many programming languages supporting them natively. Deserialization got more attention recently as a potential vehicle to conduct several types of attacks: data tampering, authentication bypass, privilege escalation, various injections and, ultimately, remote code execution. Two prominent vulnerabilities in Apache Commons and Apache Struts, both allowing remote code execution, also contributed to raising awareness of this risk. We will discuss how data serialization and deserialization are used in software, the dangers of deserializing untrusted input, and how to avoid insecure deserialization vulnerabilities. The presentation will contain several code examples with live demos of bypassing security controls due to incorrect deserialization. The examples and demos will use Java and its native serialization, but the techniques can be extrapolated to other languages and formats.
		* [Java Serialization security issues - Erno Jeges - OWASP Bay Area(2018)](https://www.youtube.com/watch?v=uur5B0rFMkQ)
			* In this short talk, we'll take a look at the various security issues coming from deserializing untrusted data in Java: information disclosure, denial of service, and even code execution. We'll examine these issues through live demonstrations with step-by-step explanations of what can go wrong – and how. Most importantly, we'll discuss several best practices and countermeasures you can use as a developer to protect yourself from these issues – or prevent them from affecting you in the first place.	
		* [Deserialization: what, how and why [not] - Alexei Kojenov(AppSec USA2018)](https://www.youtube.com/watch?v=t-zVC-CxYjw)
			* [Slides](https://drive.google.com/file/d/1o8VPE4nwNLb9cAYfG-3gM4WR4CY7FwoT/view)
			* [Code](https://github.com/kojenov/serial)
			* Insecure deserialization was recently added to OWASP's list of the top 10 most critical web application security risks, yet it is by no means a new vulnerability category. For years, data serialization and deserialization have been used in applications, services and frameworks, with many programming languages supporting them natively. Deserialization got more attention recently as a potential vehicle to conduct several types of attacks: data tampering, authentication bypass, privilege escalation, various injections and, ultimately, remote code execution. Two prominent vulnerabilities in Apache Commons and Apache Struts, both allowing remote code execution, also contributed to raising awareness of this risk. We will discuss how data serialization and deserialization are used in software, the dangers of deserializing untrusted input, and how to avoid insecure deserialization vulnerabilities. The presentation will contain several code examples with live demos of bypassing security controls due to incorrect deserialization. The examples and demos will use Java and its native serialization, but the techniques can be extrapolated to other languages and formats.
		* [Marshalling Pickles - Chris Frohoff & Gabriel Lawrence(OWASPAppSec California2015)](https://www.youtube.com/watch?v=KSA7vUkXGSg)
			* Object serialization technologies allow programs to easily convert in-memory objects to and from various binary and textual data formats for storage or transfer – but with great power comes great responsibility, because deserializing objects from untrusted data can ruin your day. We will look at historical and modern vulnerabilities across different languages and serialization technologies, including Python, Ruby, and Java, and show how to exploit these issues to achieve code execution. We will also cover some strategies to protect applications from these types of attacks.
		* [Automated Discovery of Deserialization Gadget Chains - Ian Haken(Defcon26)](https://www.youtube.com/watch?v=wPbW6zQ52w8)
			* [Slides](https://i.blackhat.com/us-18/Thu-August-9/us-18-Haken-Automated-Discovery-of-Deserialization-Gadget-Chains.pdf)
		* [New Exploit Technique In Java Deserialization Attack - Yang Zhang, Yongtao Wang, Keyi Li, Kunzhe Chai(BHEU2019)](https://www.youtube.com/watch?v=Lv9BC_bYaI8)
			* In our depth research, we analyzed more than 10000+ Java third-party libraries and found many cases which can be exploited in real-world attack scenarios. In this talk, we will bat around the principle and exploit technique of these vulnerabilities. Also, we will present how to pwn target server by our new exploit technique. It can not only improve the effect of java deserialization vulnerability but also enhance other Java security issues impact, and we will discuss profound impacts of the attack vector in the java security field.
	* **Papers**
		* [Java Unmarshaller Security - Turning your data into code execution](https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true)
			* This paper presents an analysis, including exploitation details, of various Java open-source marshalling libraries that allow(ed) for unmarshalling of arbitrary, attacker supplied, types and shows that no matter how this process is performed and what implicit constraints are in place it is prone to similar exploitation techniques.
			* tool from the above paper: [marshalsec](https://github.com/mbechler/marshalsec/)
	* **Tools**
		* [Break Fast Serial](https://github.com/GoSecure/break-fast-serial)
			* A proof of concept that demonstrates asynchronous scanning for Java deserialization bugs
		* [ysoserial](https://github.com/frohoff/ysoserial)
		* [JMET](https://github.com/matthiaskaiser/jmet)
			* JMET was released at Blackhat USA 2016 and is an outcome of Code White's research effort presented in the talk "Pwning Your Java Messaging With Deserialization Vulnerabilities". The goal of JMET is to make the exploitation of the Java Message Service (JMS) easy. In the talk more than 12 JMS client implementations where shown, vulnerable to deserialization attacks. The specific deserialization vulnerabilities were found in ObjectMessage implementations (classes implementing javax.jms.ObjectMessage).
		* [GadgetProbe](https://github.com/BishopFox/GadgetProbe)
			* GadgetProbe takes a wordlist of Java classes, outputs serialized DNS callback objects, and reports what's lurking in the remote classpath.
			* [Blogpost](https://know.bishopfox.com/research/gadgetprobe)
		* [marshalsec](https://github.com/mbechler/marshalsec)
			* This paper presents an analysis, including exploitation details, of various Java open-source marshalling libraries that allow(ed) for unmarshalling of arbitrary, attacker supplied, types and shows that no matter how this process is performed and what implicit constraints are in place it is prone to similar exploitation techniques.
	* **Exploits**
		* [SerialKiller: Bypass Gadget Collection](https://github.com/pwntester/SerialKillerBypassGadgetCollection)
			* Collection of Bypass Gadgets that can be used in JVM Deserialization Gadget chains to bypass "Look-Ahead ObjectInputStreams" desfensive deserialization.
		* [Serianalyzer](https://github.com/mbechler/serianalyzer)
			* A static byte code analyzer for Java deserialization gadget research
		* [Java Deserialization Exploits](https://github.com/CoalfireLabs/java_deserialization_exploits)
			* A collection of Java Deserialization Exploits
		* [Java Deserialization Exploits](https://github.com/Coalfire-Research/java-deserialization-exploits)
			* A collection of curated Java Deserialization Exploits
* **.NET**
	* [.NET Serialization: Detecting and defending vulnerable endpoints - Alvaro Munez(LocoMocoSec2018)](https://www.youtube.com/watch?v=qDoBlLwREYk&list=PLwvifWoWyqwqkmJ3ieTG6uXUSuid95L33&index=9)
		* 2016 was the year of Java deserialization apocalypse. Although Java Deserialization attacks were known for years, the publication of the Apache Commons Collection Remote Code Execution gadget (RCE from now on) finally brought this forgotten vulnerability to the spotlight and motivated the community to start finding and fixing these issues. .NET is next in line; formatters such as BinaryFormatter and NetDataContractSerializer are known to share similar mechanics which make them potentially vulnerable to similar RCE attacks. However, as we saw with Java before, the lack of RCE gadgets led some software vendors to not take this issue seriously. In this talk, we will analyze .NET serializers including third party JSON parsers for potential RCE vectors. We will provide real-world examples of vulnerable code and more importantly, we will review how these vulnerabilities were detected and fixed in each case.
	* [Friday the 13th: Attacking JSON - Alvaro Muñoz & Oleksandr Mirosh(AppSecUSA 2017)](https://www.youtube.com/watch?v=NqHsaVhlxAQ)
			* 2016 was the year of Java deserialization apocalypse. Although Java Deserialization attacks were known for years, the publication of the Apache Commons Collection Remote Code Execution (RCE from now on) gadget finally brought this forgotten vulnerability to the spotlight and motivated the community to start finding and fixing these issues. One of the most suggested solutions for avoiding Java deserialization issues was to move away from Java Deserialization altogether and use safer formats such as JSON. In this talk, we will analyze the most popular JSON parsers in both .NET and Java for potential RCE vectors. We will demonstrate that RCE is also possible in these libraries and present details about the ones that are vulnerable to RCE by default. We will also discuss common configurations that make other libraries vulnerable. In addition to focusing on JSON format, we will generalize the attack techniques to other serialization formats. In particular, we will pay close attention to several serialization formats in .NET. These formats have also been known to be vulnerable since 2012 but the lack of known RCE gadgets led some software vendors to not take this issue seriously. We hope this talk will change this. With the intention of bringing the due attention to this vulnerability class in .NET, we will review the known vulnerable formats, present other formats which we found to be vulnerable as well and conclude presenting several gadgets from system libraries that may be used to achieve RCE in a stable way: no memory corruption -- just simple process invocation. Finally, we will provide recommendations on how to determine if your code is vulnerable, provide remediation advice, and discuss alternative approaches.
* **PHP**
	* See [PHP](#php)
	* **Articles/Blogposts/Writeups**
		* [Diving into unserialize() - Vickie Li](https://medium.com/swlh/diving-into-unserialize-3586c1ec97e)
		* [Diving into unserialize(): POP Chains](https://medium.com/@vickieli/diving-into-unserialize-pop-chains-35bc1141b69a)
		* [Diving into unserialize(): Magic Methods - Vickie Li](https://medium.com/swlh/diving-into-unserialize-magic-methods-386d41c1b16a)
	* **Tools**
		* [Insecure-Deserialization](https://github.com/raadfhaddad/Insecure-Deserialization/tree/master/Challenge)
* **Python**
	* **Articles/Blogposts/Writeups**
		* [Exploiting Python Deserialization Vulnerabilities](https://crowdshield.com/blog.php?name=exploiting-python-deserialization-vulnerabilities)
		* [Exploiting misuse of Python's "pickle"](https://blog.nelhage.com/2011/03/exploiting-pickle/)
		* [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability. - breenmachine](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/)
		* [Python web frameworks and pickles - Nicolas Oberli](https://www.balda.ch/posts/2013/Jun/23/python-web-frameworks-pickle/)
	* **Talks**
			* [Marshalling Pickles - Chris Frohoff & Gabriel Lawrence(OWASPAppSec California2015)](https://www.youtube.com/watch?v=KSA7vUkXGSg)
				* Object serialization technologies allow programs to easily convert in-memory objects to and from various binary and textual data formats for storage or transfer – but with great power comes great responsibility, because deserializing objects from untrusted data can ruin your day. We will look at historical and modern vulnerabilities across different languages and serialization technologies, including Python, Ruby, and Java, and show how to exploit these issues to achieve code execution. We will also cover some strategies to protect applications from these types of attacks.
* **Ruby**
	* See [Ruby](#ruby)
	* **Articles/Blogposts/Writeups**
		* [Ruby 2.x Universal RCE Deserialization Gadget Chain - Luke Jahnke(2018)](https://www.elttam.com/blog/ruby-deserialization/)
	* **Talks**
		* [Marshalling Pickles - Chris Frohoff & Gabriel Lawrence(OWASPAppSec California2015)](https://www.youtube.com/watch?v=KSA7vUkXGSg)
			* Object serialization technologies allow programs to easily convert in-memory objects to and from various binary and textual data formats for storage or transfer – but with great power comes great responsibility, because deserializing objects from untrusted data can ruin your day. We will look at historical and modern vulnerabilities across different languages and serialization technologies, including Python, Ruby, and Java, and show how to exploit these issues to achieve code execution. We will also cover some strategies to protect applications from these types of attacks.

----------------
### Server Side Request Forgery (SSRF) <a name="ssrf"></a>
* **101**
	* [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
	* [What is Server Side Request Forgery (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)
	* [What is the Server Side Request Forgery Vulnerability & How to Prevent It? - netsparker](https://www.netsparker.com/blog/web-security/server-side-request-forgery-vulnerability-ssrf/)
	* [Vulnerable by Design: Understanding Server-Side Request Forgery - BishopFox](https://www.bishopfox.com/blog/2015/04/vulnerable-by-design-understanding-server-side-request-forgery/)
* **General**
	* [AllThingsSSRF](https://github.com/jdonsec/AllThingsSSRF)
		* This is a collection of writeups, cheatsheets, videos, related to SSRF in one single location
* **Articles/Blogposts/Writeups**
	* [SSRF vs Business-Critical Applications Part 1: XXE Tunneling In SAP Net Weaver - erpscan](https://erpscan.com/wp-content/uploads/publications/SSRF-vs-Businness-critical-applications-final-edit.pdf)
	* [A New Era of SSRF  - Exploiting URL Parser in  Trending Programming Languages! - Orange Tsai - BH USA 17](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
	* [curl Based SSRF Exploits Against Redis](https://maxchadwick.xyz/blog/ssrf-exploits-against-redis)
	* [Pivoting from blind SSRF to RCE with HashiCorp Consul](http://www.kernelpicnic.net/2017/05/29/Pivoting-from-blind-SSRF-to-RCE-with-Hashicorp-Consul.html)
	* [ How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)
	* [Airbnb – Chaining Third-Party Open Redirect into Server-Side Request Forgery (SSRF) via LivePerson Chat - Brett Buerhaus](https://buer.haus/2017/03/09/airbnb-chaining-third-party-open-redirect-into-server-side-request-forgery-ssrf-via-liveperson-chat/)
	* [CVE-2020-13379 Unauthenticated Full-Read SSRF in Grafana - rhynorater(2020)](https://rhynorater.github.io/CVE-2020-13379-Write-Up)
	* [Blind SSRF exploitation - wallarm(2020)](https://lab.wallarm.com/blind-ssrf-exploitation/)
* **Papers**
	* [Cracking the Lens: Targeting HTTP's Hidden Attack Surface](https://portswigger.net/knowledgebase/papers/CrackingTheLens-whitepaper.pdf)
	* [LAN-Based Blind SSRF Attack Primitive for Windows Systems (switcheroo) - initblog](https://initblog.com/2019/switcheroo/)
	https://medium.com/a-bugz-life/exploiting-an-ssrf-trials-and-tribulations-14c5d8dbd69a
* **Presentations, Talks, Videos**
	* [Server-Side Browsing Considered Harmful - Nicolas Gregoire(AppSec EU15)](https://www.youtube.com/watch?v=8t5-A4ASTIU)
		* [Slides](http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)
	* [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages - Orange Tsai(BHUSA2017)](https://www.youtube.com/watch?v=R9pJ2YCXoJQ)
		* [Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
	* [Owning The Cloud Through Server-Side Request Forgery - Ben Sadeghipour, Cody Brocious (Daeken)](https://www.youtube.com/watch?v=o-tL9ULF0KI)
		* With how many apps are running in the cloud, hacking these instances becomes easier with a simple vulnerability due to an unsanitized user input. In this talk, we’ll discuss a number of different methods that helped us exfil data from different applications using Server-Side Request Forgery (SSRF). Using these methods, we were able to hack some of the major transportation, hospitality, and social media companies and make $50,000 in rewards in 3 months.
	* [Server Side Request Forgery (SSRF) All-In-One - Busra Demir(2020)](https://www.youtube.com/watch?v=kkX2TZt6y38)
		* In this video, Busra Demir will explore how to exploit Server Side Request Forgery (SSRF) by using different attack scenarios. She will dig into how to exploit an SSRF vulnerability: ; - On a Hack the Box machine called Player (SSRF - FFMPEG Exploit); - On a Hack the Box machine called Kotarak (SSRF Filter Bypass/port scan); - By combining SQL Injection on a VulnHub machine called6Days; - Combined with HTML Injection on a VulnHub machine Gemini Inc 1
* **Testing**
	* [SSRF bible. Cheatsheet](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#heading=h.t4tsk5ixehdd)	
	* [SSRF (Server Side Request Forgery) testing resources](https://github.com/cujanovic/SSRF-Testing/)	
	* [How To: Server-Side Request Forgery (SSRF)](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)
	* [Port scanning with Server Side Request Forgery (SSRF) - acunetix](https://www.acunetix.com/blog/articles/ssrf-vulnerability-used-to-scan-the-web-servers-network/)
	* [SVG SSRF Cheatsheet](https://github.com/allanlw/svg-cheatsheet)
* **Tools**

----------------
### Server Side Include <a name="ssi"></a>
* **General**
	* [Server Side Includes - Wikipedia](https://en.wikipedia.org/wiki/Server_Side_Includes)
	* [Server-Side Includes (SSI) Injection - OWASP](https://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection)
* **Testing**
	* [Testing for SSI Injection (OTG-INPVAL-009) - OWASP](https://www.owasp.org/index.php/Testing_for_SSI_Injection_(OTG-INPVAL-009))

----------------
### Client/Server Side Template Injection <a name="ssti"></a>
* **General**
	* [Server-Side Template Injection: RCE for the modern webapp](http://blog.portswigger.net/2015/08/server-side-template-injection.html)
		* [Paper](https://portswigger.net/knowledgebase/papers/ServerSideTemplateInjection.pdf)
		* [Video](https://www.youtube.com/watch?v=3cT0uE7Y87s)
		* This paper defines a methodology for detecting and exploiting template injection, and shows it being applied to craft RCE zerodays for two widely deployed enterprise web applications. Generic exploits are demonstrated for five of the most popular template engines, including escapes from sandboxes whose entire purpose is to handle user-supplied templates in a safe way.
* **Purposefully Vulnerable Webapps**
	* [Breakable Flask](https://github.com/stephenbradshaw/breakableflask)
		* A simple vulnerable Flask application.
	* [Hackable](https://github.com/JasonHinds13/hackable)
		* A python flask app that is purposfully vulnerable to SQL injection and XSS Attacks
	* [Injecting Flask - Nvisium](https://nvisium.com/blog/2015/12/07/injecting-flask/)
	* [hackable - JasonHinds](https://github.com/JasonHinds13/hackable)
		* A python flask app that is purposfully vulnerable to SQL injection and XSS attacks
* **Writeups**
	* [Exploring SSTI in Flask/Jinja2](https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2/)
	* [Exploring SSTI in Flask/Jinja2, Part II](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
	* [Ruby ERB Template Injection](https://www.trustedsec.com/2017/09/rubyerb-template-injection/)
	* [Remote Code Execution via Server Side Template Injection at OFBiz 13.07.03 (CVE-2016-4462)](https://insinuator.net/2016/07/dilligent-bug/)
	* [Injecting Flask - Nvisium](https://nvisium.com/blog/2015/12/07/injecting-flask/)
	* [Spring Boot RCE](http://www.deadpool.sh/2017/RCE-Springs/)
	* [Fuzzing `{{7*7}} Till {{P1}}` - err0rr](http://verneet.com/fuzzing-77-till-p1/)
* **Talks, Presentations, Videos**
	* [SEC642: Killing snakes for fun, Flask SSTIs and RCEs in Python - Moses Frost(SANS)](https://www.sans.org/webcasts/sec642-killing-snakes-fun-flask-sstis-rces-python-112860)
		* Here is a word: Reflection. How many times have you read the words SSTI or even CSTI and wondered what they actually did, how they worked, or how to execute one? How can you take a file reading vulnerability like SSTI into a Remote Code Execution exploit? In this talk we will give you a glance into the SEC642 topic on Server Side Template Injection in Flask and taking that one concept a few steps further by introducing Python Method Reflection to execute code, and even backdoors. Join Moses Frost as he discusses this and other topics that are found in SEC642: Advanced Web App Penetration Testing, Ethical Hacking, and Exploitation Techniques.
* **Tools**
	* [tplmap](https://github.com/epinna/tplmap)
		* Code and Server-Side Template Injection Detection and Exploitation Tool
	* [Templates Injections - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections)
* [Exploiting Custom Template Engines - Dalton Campbell](https://depthsecurity.com/blog/exploiting-custom-template-engines)

----------------
### Subdomain Hijack/Takeover <a name="subtake"></a>
* **101**
* **Articles/Blogposts/Writeups**
	* [Hostile Subdomain Takeover using Heroku/Github/Desk + more - Detectify](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)
	* [5 Subdomain Takeover #ProTips - Patrik Hudak](https://securitytrails.com/blog/subdomain-takeover-tips)
* **Talks/Presentations**
* **Tools**

----------------
### Website Imaging(Taking Snapshots of WebPages) <a name="simg"></a>
* **101**
* **Tools**
	* [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)
		* EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible.
	* [gowitness](https://github.com/sensepost/gowitness)
		* a golang, web screenshot utility using Chrome Headless
	* [SharpWitness](https://github.com/rasta-mouse/SharpWitness)
		*  C# implementation of EyeWitness
	* [webDisco](https://github.com/joeybelans/webDisco)
		* Web discovery tool to capture screenshots from a list of hosts & vhosts.  Requests are made via IP address and vhosts to determine differences. Additionallty checks for common administrative interfaces and web server  misconfigurations.
	* [PowerWebShot](https://github.com/dafthack/PowerWebShot)
		* A PowerShell tool for taking screenshots of multiple web servers quickly.
	* [Kraken](https://github.com/Sw4mpf0x/Kraken)
		* Kraken is a tool to help make your web interface testing workflow more efficient. This is done by using Django, Apache, and a MySql database to store and organize web interface screenshots and data. This allows you and your team to take notes and track which hosts have been tested simultaniously. Once you are finished, you can view these notes you took and generate reports in the Reports section.

----------------
### (Bit)/Typo-squatting <a name="typosquatting"></a>
* **101**
	* [Typosquatting - ICANNWiki](https://icannwiki.org/Typosquatting)
	* [Typosquatting - Wikipedia](https://en.wikipedia.org/wiki/Typosquatting)
* **Articles/Blogposts/Writeups**
	* [Typosquatting programming language package managers](http://incolumitas.com/2016/06/08/typosquatting-package-managers/)
* **Talks/Presentations/Videos**
	* [Examining the Bitsquatting Attack Surface - Jaeson Schultz(Defcon21)](https://media.defcon.org/DEF%20CON%2021/DEF%20CON%2021%20video%20and%20slides/DEF%20CON%2021%20Hacking%20Conference%20Presentation%20By%20Jaeson%20Schultz%20-%20Examining%20the%20Bitsquatting%20Attack%20Surface%20-%20Video%20and%20Slides.m4v)
		* [Paper](https://www.defcon.org/images/defcon-21/dc-21-presentations/Schultz/DEFCON-21-Schultz-Examining-the-Bitsquatting-Attack-Surface-WP.pdf)
		* Bit errors in computer memory, when they occur in a stored domain name, can cause Internet traffic to be directed to the wrong Internet location potentially compromising security. When a domain name one bit different from a target domain is registered, this is called "bitsquatting". This presentation builds on previous work in this area presented by Artem Dinaburg at Blackhat 2011. Cisco's research into bitsquatting has revealed several previously unknown vectors for bitsquatting. Cisco has also discovered several new mitigations which do not involve installation of error correcting memory, nor the mass registration of bitsquat domains. In fact some of the new mitigations have the potential to render the problem of bitsquatting to the dustbin of history.

----------------
### Web Shells <a name="shells"></a>
* **Articles**
	* [Binary Webshell Through OPcache in PHP 7 - Ian Bouchard](https://gosecure.net/2016/04/27/binary-webshell-through-opcache-in-php-7/)
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
	* [Encoding Web Shells in PNG IDAT chunks - idontplaydarts.com](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
	* [novahot](https://github.com/chrisallenlane/novahot)
		* novahot is a webshell framework for penetration testers. It implements a JSON-based API that can communicate with trojans written in any language. By default, it ships with trojans written in PHP, ruby, and python. Beyond executing system commands, novahot is able to emulate interactive terminals, including mysql, sqlite3, and psql. It additionally implements "virtual commands" that make it possible to upload, download, edit, and view remote files locallly using your preferred applications.

----------------
### XSS <a name="xss"></a>
* **101**
	* [Types of Cross-Site Scripting - OWASP](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting)
	* [Postcards from a Post-XSS World - Michael Zalewski](http://lcamtuf.coredump.cx/postxss/#dangling-markup-injection)
		* This page is a rough collection of notes on some of the fundamental alternatives to direct script injection that would be available to attackers following the universal deployment of CSP or other security mechanisms designed to prevent the execution of unauthorized scripts. I hope to demonstrate that in many cases, the capabilities offered by these alternative methods are highly compatible with the goals of contemporary XSS attacks.
	* [Cross Site Scripting Prevention Cheat Sheet - OWASP](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
	* [CERT Advisory CA-2000-02 Malicious HTML TagsEmbedded in Client Web Requests](http://www.cert.org/advisories/CA-2000-02.html)
	* [HTML Code Injection and Cross-site Scripting - Gunter Ollmann](http://www.technicalinfo.net/papers/CSS.html)
	* [Flirting with MIME Types: A Browser’sPerspective - Blake Frantz](http://www.leviathansecurity.com/pdf/Flirting%20with%20MIME%20Types.pdf)
* **Articles/Blogposts/Writeups**
	* [Actual XSS in 2020 - Samuel Anttila(2020)](https://netsec.expert/2020/02/01/xss-in-2020.html)
	* [Getting Real with XSS - Olive Simonnet(2019)](https://labs.f-secure.com/blog/getting-real-with-xss/)
	* [XSS technique without parentheses - The Spanner](http://www.thespanner.co.uk/2012/05/01/xss-technique-without-parentheses/)
	* [Text/Plain Considered Harmful - Jan](https://jankopecky.net/index.php/2017/04/18/0day-textplain-considered-harmful/)
	* [Setting The ‘REFERER’ Header Using Javascript - Drew Kirkpatrick(2020)](https://www.trustedsec.com/blog/setting-the-referer-header-using-javascript/)
	* [Unleashing an Ultimate XSS Polyglot - Ahmed Elsobky](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot)
	* [Password stealing from HTTPS login page and CSRF protection bypass with reflected XSS - Michael Koczwara(2020)](https://medium.com/@MichaelKoczwara/password-stealing-from-https-login-page-and-csrf-bypass-with-reflected-xss-76f56ebc4516)
	* [What is the use of CDATA inside JavaScript tags and HTML? - sptrac.com(2017)](http://sptrac.com/wordpress/?p=3765)
	* [Detecting valid tags/events on XSS exploitation. - Jorge Lajara(2020)](https://jlajara.gitlab.io/web/2020/01/25/XSS_tag_event_analyzer.html)
* **Presentations, Talks, Videos**
	* [Self XSS: we’re not so different you and I - Mathias Karlsson](https://www.youtube.com/watch?v=l3yThCIF7e4)	
	* [Scriptless Attacks – Stealing the Pie Without Touching the Sill](http://www.syssec.rub.de/media/emma/veroeffentlichungen/2012/08/16/scriptlessAttacks-ccs2012.pdf)
		* Due to their high practical impact, Cross-Site Scripting (XSS) attacks have attracted a lot of attention from the security community members. In the same way, a plethora of more or less effective defense techniques have been proposed, addressing the causes and effects of XSS vulnerabilities. As a result, an adversary often can no longer inject or even execute arbitrary scripting code in several real-life scenarios. In this paper, we examine the attack surface that remains after XSS and similar scripting attacks are supposedly mitigated by preventing an attacker from executing JavaScript code. We address the question of whether an attacker really needs JavaScript or similar functionality to perform attacks aiming for information theft. The surprising result is that an attacker can also abuse Cascading Style Sheets (CSS) in combination with other Web techniques like plain HTML, inactive SVG images or font files. Through several case studies, we introduce the so called scriptless attacks and demonstrate that an adversary might not need to execute code to preserve his ability to extract sensitive informati on from well protected websites. More precisely, we show that an attacker can use seemingly benign features to build side channel attacks that measure and exfiltrate almost arbitrary data displayed on a given website. We conclude this paper with a discussion of potential mitigation techniques against this class of attacks. In addition, we have implemented a browser patch that enables a website to make a vital determination as to being loaded in a detached view or pop-up window. This approach proves useful for prevention of certain types of attacks we here discuss.	
	* ["Gimme a bit!" - Exploring Attacks in the "Post-XSS" World - Takashi Yoneuchi](https://speakerdeck.com/lmt_swallow/gimme-a-bit-exploring-attacks-in-the-post-xss-world)
	* [Tricks For Weaponizing XSS - Drew Kirkpatrick](https://www.trustedsec.com/blog/tricks-for-weaponizing-xss/)
	* [Understanding XSS - Christina Mitchell(Nolacon2019)](https://www.irongeek.com/i.php?page=videos/nolacon2019/nolacon-2019-d-02-understanding-xss-christina-mitchell)
		* Come learn in depth about the web vulnerability XSS. First we discuss how browsers and web apps work to better understand how it's possible. Then we will cover the following: how to spot it in the wild, how to exploit it, remediation steps, and impact. How can I inject into your webpage? Come learn how!
	* [Popping Shells Instead OF Alert Boxes: Weaponizing XSS For Fun and Profit - Drew Kirkpatrick(2019)](https://www.trustedsec.com/events/webinar-popping-shells-instead-of-alert-boxes-weaponizing-xss-for-fun-and-profit/)
* **Bypass Techniques & Writeups**
	* Cheat-Sheets/References
		* [XSS Filter Evasion Cheat Sheet - OWASP](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
	* **Filter Evasion**
		* [XSS cheatsheet Esp: for filter evasion - RSnake](https://n0p.net/penguicon/php_app_sec/mirror/xss.html)
		* [Bypassing XSS Detection Mechanisms - Somdev Sangwan(2018)](https://github.com/s0md3v/MyPapers/tree/master/Bypassing-XSS-detection-mechanisms)
		* [XSS Filter Evasion - Zbigniew Banach(2019)](https://www.netsparker.com/blog/web-security/xss-filter-evasion/)
		* [XSS without parentheses and semi-colons - Gareth Heyes(2019)](https://portswigger.net/research/xss-without-parentheses-and-semi-colons)
		* [Bypass XSS filters using JavaScript global variables - theMiddle](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/)
		* [Executing non-alphanumeric JavaScript without parenthesis - Gareth Heyes](https://portswigger.net/research/executing-non-alphanumeric-javascript-without-parenthesis)
		* [Non-alphanumeric code With JavaScript & PHP - Gareth Heyes](http://www.businessinfo.co.uk/labs/talk/Nonalpha.pdf)
		* [CTF Challenge: INS Hack 2019 / Bypasses Everywhere -corb3nik](https://corb3nik.github.io/blog/ins-hack-2019/bypasses-everywhere)
		* [JavaScript without parentheses using DOMMatrix - Gareth Heyes(2020)](https://portswigger.net/research/javascript-without-parentheses-using-dommatrix)
		* [Arbitrary Parentheses-less XSS(against strict CSP policies) - terjang(2020)](https://medium.com/@terjanq/arbitrary-parentheses-less-xss-e4a1cf37c13d)
		* [XSS: Arithmetic Operators & Optional Chaining To Bypass Filters & Sanitization - theMiddle(2020)](https://www.secjuice.com/xss-arithmetic-operators-chaining-bypass-sanitization/)
	* **Images**
		* [JS via Images - Osanda Malith Jayathissa(2014)](https://osandamalith.com/2014/11/13/js-via-images/)
	* **Length**
		* [Exploiting XSS with 20 characters limitation - Jorge Lajara(2019)](https://jlajara.gitlab.io/web/2019/11/30/XSS_20_characters.html)
	* **Restricted Character Sets**
		* [JSFuck](http://www.jsfuck.com/)
		* [jsf$ck](https://github.com/centime/jsfsck)
			* jsf$ck is a fork from jsfuck.com that doesn't use parenthesis.
		* [jjencode](https://utf-8.jp/public/jjencode.html)
	* **SVG**
		* [XSS fun with animated SVG - Paweł Hałdrzyński(2020)](https://blog.isec.pl/xss-fun-with-animated-svg/)
		* [Redefining Impossible: XSS without arbitrary JavaScript - Luan Herrera(2020)](https://portswigger.net/research/redefining-impossible-xss-without-arbitrary-javascript)
		* [XSS Challenge Solution - SVG use - Alex Infuhr(2020)](https://insert-script.blogspot.com/2020/09/xss-challenge-solution-svg-use.html)
	* **Other**
		* [Bypass XSS Protection with xmp, noscript, noframes.. etc.. - Hahwul](https://www.hahwul.com/2019/04/bypass-xss-protection-with-xmp-noscript-etc....html)
		* [MITM XSS Protection – Still Popping Alerts - doyler.net(2017)](https://www.doyler.net/security-not-included/mitm-xss-protection-still-popping-alerts)
		* [Attacking and defending JavaScript sandboxes - Gareth Heyes(2020)](https://portswigger.net/research/attacking-and-defending-javascript-sandboxes)
		* [Evading defences using VueJS script gadgets - Gareth Heyes(2020)](https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets)
		* [Escaping JavaScript sandboxes with parsing issues - Gareth Heyes(2020)](https://portswigger.net/research/escaping-javascript-sandboxes-with-parsing-issues)
		* [Bypassing modern XSS mitigations with code-reuse attacks - Alexander Andersson(2020)](https://blog.truesec.com/2020/04/03/bypassing-modern-xss-mitigations-with-code-reuse-attacks/)
	* **Lists**
		* [XSS bypass strtoupper & htmlspecialchars](https://security.stackexchange.com/questions/145716/xss-bypass-strtoupper-htmlspecialchars)
		* [Is htmlspecialchars enough to prevent an SQL injection on a variable enclosed in single quotes? - StackOverflow](https://stackoverflow.com/questions/22116934/is-htmlspecialchars-enough-to-prevent-an-sql-injection-on-a-variable-enclosed-in)
		* [XSS Web Filter Bypass list - rvrsh3ll](https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec#file-xxsfilterbypass-lst-L1)
		* [XSS Filter Bypass List](https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec)
* **Cheat-Sheets**
	* [XSS (Cross Site Scripting) - Carlos Polop](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
	* [Cross-site scripting (XSS) cheat sheet - portswigger](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
	* [XSS Filter Evasion Cheat Sheet - OWASP](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
	* [Testing for Reflected Cross Site Scripting - OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.html)
	* [Testing for Stored Cross Site Scripting - OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.html)
	* [Testing for DOM-Based Cross Site Scripting - OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting.html)
* **Types-Of**
	* **DOM-based**
		* **101**
		* **Articles/Blogposts/Writeups**
			* postMessage API
				* [Window.postMessage() - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
				* [Detecting postMessage interfaces - Sjoerd Langkemper(2018)](https://www.sjoerdlangkemper.nl/2018/05/09/attacking-postmessage-interfaces/)
				* [The pitfalls of postMessage -  Mathias Karlsson(2016)](https://labs.detectify.com/2016/12/08/the-pitfalls-of-postmessage/)
				* [The Mystery of postMessage - Ron Chan(2018)](https://ngailong.wordpress.com/2018/02/13/the-mystery-of-postmessage/)
				* [PostMessage Vulnerabilities. Part I - Jorge Lajara(2020)](https://jlajara.gitlab.io/web/2020/06/12/Dom_XSS_PostMessage.html)
					* [Part 2](https://jlajara.gitlab.io/web/2020/07/17/Dom_XSS_PostMessage_2.html)
		* **Talks/Presentations/Videos**
			* [In the DOM - no one will hear you scream - Mario Heiderich(Garage4Hackers Ranchoddas Webcast2014)](https://www.youtube.com/watch?v=5W-zGBKvLxk)
				* This talk is about the DOM and its more twilight areas. Well see the weird parts and talk about where and why this might be security critical and affect your precious online applications, browser extensions or packaged apps. To understand the foundations of what the DOM has become by today, we'll further explore the historical parts - who created the DOM, what was the intention and how fought dirty about it during the browser wars.  Finally, we'll see a DOM based attack called "DOM Clobbering". An attack, that is everything but obvious and affected a very popular and commonly used Rich Text Editor. Be prepared for a lot of tech-talk as well as fear and loathing in the browser window. But don't shed no tears, there's a tool that fixes the security crazy for you and this talk will present it.
			* [Don't Trust The DOM: Bypassing XSS Mitigations Via Script Gadgets - Sebastian Lekies(AppSecEU2017)](https://www.youtube.com/watch?v=p07acPBi-qw)
				* Over the years many techniques have been introduced to prevent or mitigate XSS. Thereby, most of these techniques such as HTML sanitizers or CSP focus on script tags and event handlers. In this talk, we present a novel Web hacking technique that enables an attacker to bypass these mitigations. In order to to so, the attacker abuses so-called script gadgets. A gadget Is a legitimate piece of JS in a page that reads elements via selectors and processes them in a way that results in script execution. To abuse a gadget, the attacker injects benign elements that match the gadget&rsquo;s selector. Subsequently, the gadget selects the elements and executes the attacker's scripts. As the attacker's markup is benign it passes HTML sanitizers and security policies. The XSS only surfaces when the gadget mistakenly elevates the privileges of the element. Based on real-world examples, we will demonstrate that these gadgets are present in almost all modern JavaScript libraries, APIs and applications.
			* [Breaking XSS Mitigations Via Script Gadgets - Sebastian Lekies, Krzysztof Kotowicz & Eduardo Vela(BHUSA2017)](https://www.youtube.com/watch?v=i6Ug8O23DMU)
				* In this talk, we present a novel Web hacking technique that enables an attacker to circumvent most XSS mitigations. In order to do so, the attacker abuses so-called script gadgets. A script gadget Is a legitimate piece of JavaScript in a page that reads elements from the DOM via selectors and processes them in a way that results in script execution
			* [Eval Villain: Simplifying DOM XSS and JS Reversing - Dennis Goodlett(BSidesCLE2019)]()
				* JavaScript cruft is growing faster than my ability to read. Since I can't read every line of code, I need tools to find important lines. Eval Villain is a web extension for Firefox that hooks native JavaScript functions *before* the page loads so that you will be notified every time a function is called. Eval Villain has discovered instances of DOM XSS that only appear in 1 of 100 page loads. It makes the reversing of malicious, second-stage encrypted JavaScript code trivial. I plan on walking through all the features of this tool using examples. To follow along, bring a computer that can run Firefox.https://www.irongeek.com/i.php?page=videos/bsidescleveland2019/bsides-cleveland-c-00-eval-villain-simplifying-dom-xss-and-js-reversing-dennis-goodlett
		* **Papers**
			* [DOM Based Cross Site Scripting or XSS of the Third Kind: A look at an overlooked flavor of XSS - Amit Klein(2005)](http://www.webappsec.org/projects/articles/071105.html)
		* **Tools**
			* [DOM XSS Intro - MechaTechSec](https://mechatechsec.blogspot.com/2018/01/dom-xss-intro.html)
			* [DOM-based XSS – The 3 Sinks - brutelogic.com](https://brutelogic.com.br/blog/dom-based-xss-the-3-sinks/)
			* [DOM Event reference - MDN(Mozilla)](https://developer.mozilla.org/en-US/docs/Web/Events)
		* **Writeups(DOM XSS)**
			* [$20000 Facebook DOM XSS - Vinoth Kumar(2020)](https://vinothkumar.me/20000-facebook-dom-xss/)
			* [INTIGRITI XSS CHALLENGE WRITE-UP - František Uhrecký(2019)](https://citadelo.com/en/blog/intigriti-xss-challenge-write-up/)
			* [The XSS challenge that +100k people saw but only 90 solved - intigrit(2019)](https://blog.intigriti.com/2019/05/06/intigriti-xss-challenge-1/)
			* [How our community hacked our own XSS challenge - Intigriti(2019)](https://blog.intigriti.com/2019/05/27/winner-announced-how-our-community-hacked-our-own-xss-challenge/)
			* [Intigriti Easter XSS Challenge Write-up - Abdullah Hussam(2020)](https://ahussam.me/intigriti-easter-xss-challenge/)
			* [Intigriti XSS Challenge Write-Up - Renaud Martinet(2019)](https://renaudmarti.net/posts/intigriti-xss-challenge/)
			* [Intigriti XSS Challenge #4 - PSPAUL(2019)](https://blog.pspaul.de/posts/intigriti-xss-challenge-4/)
			* [Intigriti Easter XSS Challenge 2020 Write Up - lboynton.com(2020)](https://lboynton.com/2020/04/20/intigriti-easter-xss-challenge-2020-write-up/)
			* [Intigriti XSS Challenge – Fun with DOM XSS - doyler.net(2019)](https://www.doyler.net/security-not-included/intigriti-xss-challenge-dom-xss)
			* [Solving Intigriti Challenge using… Content Injection! - Amal Murali(2020)](https://medium.com/@amalmurali47/solving-intigriti-challenge-using-content-injection-84e212cae00f)
			* [Finally! HOW TO solve the INTIGRITI Easter XSS challenge using only Chrome DEVTOOLS! - ST0K](https://www.youtube.com/watch?v=IhPsBMBDFcg)
		* **Mutation XSS**
			* **101**
				* [What is mutation XSS (mXSS)? - StackOverflow](https://security.stackexchange.com/questions/46836/what-is-mutation-xss-mxss)
			* **Articles/Blogposts/Writeups**
				* [mXSS - TheSpanner(2014)](http://www.thespanner.co.uk/2014/05/06/mxss/)
				* [Write-up of DOMPurify 2.0.0 bypass using mutation XSS - Michał Bentkowski(2019)](https://research.securitum.com/dompurify-bypass-using-mxss/)
				* [Mutation XSS - Infinite8security(2016)](https://infinite8security.blogspot.com/2016/02/mutation-xss.html)
				* [Mutation XSS in Google Search - Tomasz Andrzej Nidecki(2019)](https://www.acunetix.com/blog/web-security-zone/mutation-xss-in-google-search/)
				* [Mutation XSS- A Unique class of XSS - Pankaj Rane(2019)](http://www.insejournal.co.in/mutation-xss.html)
				* [Mutation XSS via namespace confusion – DOMPurify < 2.0.17 bypass - Michal Bentkowski (2020)](https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/)
				* [Bypassing DOMPurify again with mutation XSS - Gareth Heyes(2020)](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss)
			* **Talks/Presentations/Videos**
				* [How mXSS attacks change everything we believed to know so far - Mario Heiderich - OWASP AppSec EU 2013](https://www.youtube.com/watch?v=Haum9UpIQzU)
			* **Papers**
				* [mXSS attacks: Attacking well-secured web-applications by using innerHTML mutations - Mario Heiderich, Jörg Schwenk, Tilman Frosch, Jonas Magazinius(2013)](https://www.researchgate.net/publication/266654651_mXSS_attacks_Attacking_well-secured_web-applications_by_using_innerHTML_mutations)
					* Back in 2007, Hasegawa discovered a novel Cross-Site Scripting (XSS) vector based on the mistreatment of the backtick character in a single browser implementation. This initially looked like an implementation error that could easily be fixed. Instead, as this paper shows, it was the first example of a new class of XSS vectors, the class of mutation-based XSS (mXSS) vectors, which may occur in innerHTML and related properties. mXSS affects all three major browser families: IE, Firefox, and Chrome. We were able to place stored mXSS vectors in high-profile applications like Yahoo! Mail, Rediff Mail, OpenExchange, Zimbra, Roundcube, and several commercial products. mXSS vectors bypassed widely deployed server-side XSS protection techniques (like HTML Purifier, kses, htmlLawed, Blueprint and Google Caja), client-side filters (XSS Auditor, IE XSS Filter), Web Application Firewall (WAF) systems, as well as Intrusion Detection and Intrusion Prevention Systems (IDS/IPS). We describe a scenario in which seemingly immune entities are being rendered prone to an attack based on the behavior of an involved party, in our case the browser. Moreover, it proves very difficult to mitigate these attacks: In browser implementations, mXSS is closely related to performance enhancements applied to the HTML code before rendering; in server side filters, strict filter rules would break many web applications since the mXSS vectors presented in this paper are harmless when sent to the browser. This paper introduces and discusses a set of seven different subclasses of mXSS attacks, among which only one was previously known. The work evaluates the attack surface, showcases examples of vulnerable high-profile applications, and provides a set of practicable and low-overhead solutions to defend against these kinds of attacks.
				* [Automation of Mutated Cross Site Scripting - Anchal Tiwari, J. Jeysree](https://www.ijsr.net/archive/v4i4/SUB152876.pdf)	
					* Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted web sites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it. In browsers Mutation event occur when there is a change in the DOM Structure of the browsers. There are various ways in which DOM structure could be changed among which innerHTML property is discussed specifically. mXSS is a new class of XSS vectors, the class of mutation-based XSS (mXSS) vectors, which may occur in innerHTML andrelated properties. mXSS affects all three major browserfamilies: IE, Firefox, and Chrome.mXSS could be placed in major browser families and effecting major web applications. In this paper we apply the idea of mutation-based testing technique to generate adequate test data sets for testing XSSVs. Our work addresses XSSVs related to web-applications that use PHP and JavaScript code to generate dynamic HTML contents. Finally there would be the development of an automatic tool which would generate mutants automatically, automatically testing the web application and finally giving the output.
	* **Persistent XSS**
		* **101**
		* **Articles/Blogposts/Writeups**
			* **General**
				* [Self-XSS + CSRF to Stored XSS - Renwa(2018)](https://medium.com/@renwa/self-xss-csrf-to-stored-xss-54f9f423a7f1)
				* [AirBnb Bug Bounty: Turning Self-XSS into Good-XSS #2 - Geekboy(2016)](https://www.geekboy.ninja/blog/airbnb-bug-bounty-turning-self-xss-into-good-xss-2/)
			* **Blind**
				* [Blind XSS for beginners - Syntax Error(2018)](https://medium.com/bugbountywriteup/blind-xss-for-beginners-c88e48083071)
			* **File-Based**
				* [XSS SVG - Ghostlulz](http://ghostlulz.com/xss-svg/)
				* [XSS on Facebook via PNGs & Wonky Content Types - whitton.io(2016)](https://whitton.io/articles/xss-on-facebook-via-png-content-types/)
				* [$1,000 USD IN 5 MINUTES, XSS STORED IN OUTLOOK.COM (IOS BROWSERS) - @omespino(2019)](https://omespino.com/write-up-1000-usd-in-5-minutes-xss-stored-in-outlook-com-ios-browsers/)
				* [Persistent XSS at AH.nl - Jonathan Bouman(2018)](https://medium.com/@jonathanbouman/persistent-xss-at-ah-nl-198fe7b4c781)
		* **Talks/Presentations/Videos**
		* **Papers**
	* **Reflected XSS**
		* **101**
		* **Articles/Blogposts/Writeups**
			* [Reflected XSS at Philips.com - Jonathan Bouman](https://medium.com/@jonathanbouman/reflected-xss-at-philips-com-e48bf8f9cd3c)
			* [How I XSS’ed Uber and Bypassed CSP - Efkan(2018)](https://medium.com/@efkan162/how-i-xssed-uber-and-bypassed-csp-9ae52404f4c5)
			* [admin.google.com Reflected Cross-Site Scripting (XSS) - Brett Buerhaus(2015)](https://buer.haus/2015/01/21/admin-google-com-reflected-cross-site-scripting-xss/)
			* [From Reflected XSS to Account Takeover — Showing XSS Impact - A Bug'z Life(2019)](https://medium.com/a-bugz-life/from-reflected-xss-to-account-takeover-showing-xss-impact-9bc6dd35d4e6)
			* [Reflected DOM XSS and CLICKJACKING on https://silvergoldbull.de/bt.html - Daniel Maksimovic(2018)](https://medium.com/bugbountywriteup/reflected-dom-xss-and-clickjacking-on-https-silvergoldbull-de-bt-html-daa36bdf7bf0)
		* **Talks/Presentations/Videos**
		* **Papers**
* **JS Framework-Specific**
    * **Angular**
    	* [XSS without HTML: Client-Side Template Injection with AngularJS - Gareth Hayes(2020)](https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs)
    	* [DOM Based Angular Sandbox Escapes by Gareth Heyes - BSides Manchester2017](https://www.youtube.com/watch?v=jlSI5aVTEIg&index=16&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)
    * **React.js**
    	* [The Most Common XSS Vulnerability in React.js Applications - Emelia Smith(2016)](https://medium.com/node-security/the-most-common-xss-vulnerability-in-react-js-applications-2bdffbcc1fa0)
		* [Exploiting Script Injection Flaws in ReactJS Apps - Bernhard Mueller(2017)](https://medium.com/dailyjs/exploiting-script-injection-flaws-in-reactjs-883fb1fe36c1)
		* [Avoiding XSS in React is Still Hard - Ron Perris(2018)](https://medium.com/javascript-security/avoiding-xss-in-react-is-still-hard-d2b5c7ad9412)
		* [How Much XSS Vulnerability Protection is React Responsible For? #3473 Github Issue](https://github.com/facebook/react/issues/3473)
			* [Response #1](https://github.com/facebook/react/issues/3473#issuecomment-90594748)
			* [Response #2](https://github.com/facebook/react/issues/3473#issuecomment-91349525)
* **JSON Hijacking**
	* **101**
		* [JSON Hijacking Demystified - Rohini Sulatycki(2012)](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/json-hijacking-demystified/)
		* [Reflected XSS via JSON executed with Burp, but how to do it in realistic conditions? - StackOverflow](https://security.stackexchange.com/questions/150009/reflected-xss-via-json-executed-with-burp-but-how-to-do-it-in-realistic-conditi)
		* [XSS : Content-type: application/json - StackOverflow](https://security.stackexchange.com/questions/13821/xss-content-type-application-json)
		* [Is it possible to XSS exploit JSON responses with proper JavaScript string escaping - StackOverflow](https://stackoverflow.com/questions/3146324/is-it-possible-to-xss-exploit-json-responses-with-proper-javascript-string-escap)
	* **Articles/Blogposts/Writeups**
		* [Story of a JSON XSS - Nikhil Mittal(2017)](https://c0d3g33k.blogspot.com/2017/11/story-of-json-xss.html)
		* [JSON hijacking for the modern web - Gareth Heyes(2020)](https://portswigger.net/research/json-hijacking-for-the-modern-web)
		* [Exploiting JSON Framework : 7 Attack Shots - Aditya K. Sood](http://www.infosecwriters.com/Papers/ASood_ExploitingJSON.pdf)
		* [Attacking JSON Application : Pentesting JSON Application - Narendra Bhati(2018)](https://www.websecgeeks.com/2015/10/attacking-json-application-pentesting.html)
		* [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities - Brett Buerhaus](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/)
		* [JSON based XSS - Koumudi Garikipati(2020)](https://medium.com/@koumudi.garikipati/json-based-xss-84089141c136)
		* [XSSing Google Code-in thanks to improperly escaped JSON data - Thomas Orlita](https://websecblog.com/vulns/google-code-in-xss/)
* **Testing**
	* [XSS Test String Dump](https://github.com/zsitro/XSS-test-dump/blob/master/xss.txt)
	* [HTML Purifier XSS Attacks Smoketest](http://htmlpurifier.org/live/smoketests/xssAttacks.php)
	* [Cross-site scripting (XSS) cheat sheet - PortSwigger](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
		* This cross-site scripting (XSS) cheat sheet contains many vectors that can help you bypass WAFs and filters. You can select vectors by the event, tag or browser and a proof of concept is included for every vector. This cheat sheet is regularly updated in 2019. Last updated: Fri, 08 Nov 2019
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
	* [XSStrike](https://github.com/UltimateHackers/XSStrike)
		* XSStrike is an advanced XSS detection and exploitation suite.
	* [iframeBusterXSS](https://github.com/tr4l/iframeBusterXSS)
		* Check for know iframeBuster XSS
	* [XSS tag_event analyzer](https://gitlab.com/jlajara/xss-tag_event-analyzer)
		* Script to test suitable XSS payloads when tag/events are validated in a weak way.
	* [Security Headers(scanner)](https://securityheaders.com)
* **Writeups**
	* [Writing an XSS Worm](http://blog.gdssecurity.com/labs/2013/5/8/writing-an-xss-worm.html)
	* [XSS without HTML: Client-Side Template Injection with AngularJS](https://portswigger.net/blog/xss-without-html-client-side-template-injection-with-angularjs)
	* [XSS in AngularJS video series (walkthrough) - explaining some AngularJS sandbox bypasses, which resulted in the removal of the sandbox in 1.6](https://www.reddit.com/r/angularjs/comments/557bhr/xss_in_angularjs_video_series_walkthrough/)
	* [Chaining Cache Poisoning To Stored XSS - Rohan Aggarwal](https://medium.com/@nahoragg/chaining-cache-poisoning-to-stored-xss-b910076bda4f)
	* [Stealing JWTs in localStorage via XSS -David Roccasalva ](https://medium.com/redteam/stealing-jwts-in-localstorage-via-xss-6048d91378a0)
	* [Penetration testing & window.opener — XSS vectors part 1 - Josh Graham](https://medium.com/tsscyber/penetration-testing-window-opener-xss-vectors-part-1-c6be37701cab)
	* [A Questionable Journey From XSS to RCE - Dominik Penner](https://zero.lol/2019-05-13-xss-to-rce/)
	* [Firefox uXSS and CSS XSS - leucosite.com](https://leucosite.com/Firefox-uXSS-and-CSS-XSS/)
	* [Referer XSS with a Side of Link Injection - doyler.net](https://www.doyler.net/security-not-included/referer-xss)
	* [XSS in steam react chat client - Zemmez](https://hackerone.com/reports/409850)
	* [Cerberus FTP Blind Cross-Site Scripting to remote code execution as SYSTEM. (Version 9 and 10) - Kevin(secu.dk)]
	* [Winning Intigriti's XSS Challenge - Ryan Wise](https://ryanwise.me/intigriti-xss-challenge/)
	* [iOS Bug Hunting – Web View XSS - Allyson O'Malley](https://www.allysonomalley.com/2018/12/03/ios-bug-hunting-web-view-xss/)
	* [XSS in GMail’s AMP4Email via DOM Clobbering - Michal Bentkowski](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)
	* [Auditing a Payment Processing of a Booking Framework - Jorge Lajara(2018)](https://jlajara.gitlab.io/web/2018/10/07/payment-processing-booking.html)
		* This article is thanks to the collaboration with Rayco Betancor and his crazy ideas and deep knowledge of how a Payment processing works, and a lot of trying different requests, forcing errors and trying harder.
	* [Sarahah XSS Exploitation Tool - Compromising Sarahah Users. - Shawar Khan](https://www.shawarkhan.com/2017/08/sarahah-xss-exploitation-tool.html)
	* [A Questionable Journey From XSS to RCE - Dominik Penner(2019)](https://zero.lol/2019-05-13-xss-to-rce/)
	* [Documenting the impossible: Unexploitable XSS labs - Gareth Heyes](https://portswigger.net/research/documenting-the-impossible-unexploitable-xss-labs)
	* [Art of bug bounty: a way from JS file analysis to XSS - Jakub Żoczek(2020)](https://research.securitum.com/art-of-bug-bounty-a-way-from-js-file-analysis-to-xss/)
	* [XSS a Paste Service - Pasteurize (web) Google CTF 2020 - LiveOVerflow(2020)](https://www.youtube.com/watch?v=Tw7ucd2lKBk)
	* [URL validation bypass | Filedescriptor solves Intigriti's XSS challenge - Reconless(2020)](https://www.youtube.com/watch?v=KpkrTUHoWsQ)
* **Payloads**
	* [Cross Site Scripting (XSS) Vulnerability Payload List](https://github.com/payloadbox/xss-payload-list)
	* [Stealing HttpOnly Cookie via XSS - Yasser Gersy(2018)](https://medium.com/@yassergersy/xss-to-session-hijack-6039e11e6a81)
	* [Tiny-XSS-Payloads](https://github.com/terjanq/Tiny-XSS-Payloads)
		* A collection of tiny XSS Payloads that can be used in different contexts.

----------------
### Cross-Site History Manipulation <a name="xshm"></a>
* **101**
	* [Cross Site History Manipulation - OWASP](https://www.owasp.org/index.php/Cross_Site_History_Manipulation_(XSHM))
* **Articles/Papers/Talks/Writeups**
* **Tools**
* **Miscellaneous**

----------------
### Tabnabbing Attacks <a name="tabnab"></a>
* **101**
	* [Tabnabbing: A New Type of Phishing Attack - Aza Raskin](http://www.azarask.in/blog/post/a-new-type-of-phishing-attack/)
	* [Reverse Tabnabbing - OWASP](https://www.owasp.org/index.php/Reverse_Tabnabbing)
		* Reverse tabnabbing is an attack where a page linked from the target page is able to rewrite that page, for example to replace it with a phishing site. As the user was originally on the correct page they are less likely to notice that it has been changed to a phishing site, especially it the site looks the same as the target. If the user authenticates to this new page then their credentials (or other sensitive data) are sent to the phishing site rather than the legitimate one.
* **Articles/Papers/Talks/Writeups**
	* [Tabnabbing Protection Bypass - Ziyahan Albeniz](https://www.netsparker.com/blog/web-security/tabnabbing-protection-bypass/)
	* [Tab nabbing via window.opener - Ashish singh(HackerOne)](https://hackerone.com/reports/403891)
* **Tools**

----------------
### Timing / Race Condition Attacks <a name="timing"></a>
* **101**
	* [Timing attack - Wikipedia](https://en.wikipedia.org/wiki/Timing_attack)
* **Articles/Blogposts/Writeups**
	* [Race conditions on the web ](https://www.josipfranjkovic.com/blog/race-conditions-on-web)
	* [Practical Race Condition Vulnerabilities in Web Applications](https://defuse.ca/race-conditions-in-web-applications.htm)
* **Papers**
	* [Race Detection for Web Applications - Boris Petrov, Martin Vechev, Manu Sridharan, Julian Dolby](http://www.cs.columbia.edu/~junfeng/14fa-e6121/papers/js-race.pdf)
		* We present the first formulation of a happens-before relation for common web platform features. Developing this relation was a non-trivial task, due to complex feature interactions and browser differences. We also present a logical memory access model for web applications that abstracts away browser implementation details. Based on the above, we implemented WEBRACER, the first dynamic race detector for web applications. WEBRACER is implemented atop the production-quality WebKit engine, enabling testing of full-featured web sites. WEBRACER can also simulate certain user actions, exposing more races. We evaluated WEBRACER by testing a large set of Fortune 100 company web sites. We discovered many harmful races, and also gained insights into how developers handle asynchrony in practice.
* **Tools**
	* [Requests-Racer](https://github.com/nccgroup/requests-racer)
		* Requests-Racer is a small Python library that lets you use the Requests library to submit multiple requests that will be processed by their destination servers at approximately the same time, even if the requests have different destinations or have payloads of different sizes. This can be helpful for detecting and exploiting race condition vulnerabilities in web applications. (For more information, see motivation.md.)
	* [Race the Web](https://github.com/aaronhnatiw/race-the-web)
		* Tests for race conditions in web applications by sending out a user-specified number of requests to a target URL (or URLs) simultaneously, and then compares the responses from the server for uniqueness. Includes a number of configuration options.
	* [timing_attack](https://github.com/ffleming/timing_attack)
		* Perform timing attacks against web applications
	* [Race condition exploit](https://github.com/andresriancho/race-condition-exploit)
		* Tool to help with the exploitation of web application race conditions
* **Miscellaneous**

----------------
### TLS Redirection (and Virtual Host Confusion) <a name="tls-redirect"></a>
* **101**
	* [TLS Redirection (and Virtual Host Confusion) - GrrDog](https://github.com/GrrrDog/TLS-Redirection)
		* The goal of this document is to raise awareness of a little-known group of attacks, TLS redirection / Virtual Host Confusion, and to bring all the information related to this topic together.
* **Articles/Papers/Talks/Writeups**
	* [Network-based Origin Confusion Attacks against HTTPS Virtual Hosting - Antoine Delignat-Lavaud, Karthikeyan Bhargavan](http://antoine.delignat-lavaud.fr/doc/www15.pdf)
	* [The BEAST Wins Again: Why TLS Keeps Failing to Protect HTTP - BHUSA14](https://www.blackhat.com/docs/us-14/materials/us-14-Delignat-The-BEAST-Wins-Again-Why-TLS-Keeps-Failing-To-Protect-HTTP.pdf)
* **General**
* **Tools**
* **Miscellaneous**

----------------
### TypoSquatting <a name="typosquat"></a>
* **101**

----------------
### Web Cache Deception Attack <a name="webcache"></a>
* **101**
* **Articles/Blogposts/Writeups**
	* [Web Cache Deception Attack - Omer Gil(2017)](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)
	* [Understanding Our Cache and the Web Cache Deception Attack - Joshua Liebow-Feeser(2017)](https://blog.cloudflare.com/understanding-our-cache-and-the-web-cache-deception-attack/)
	* [On Web Cache Deception Attacks - Benjamin Brown(2017)](https://blogs.akamai.com/2017/03/on-web-cache-deception-attacks.html)
* **Papers**
	* [Cached and Confused: Web Cache Deception in the Wild - Seyed Ali Mirheidari, Sajjad Arshad, Kaan Onarlioglu, Bruno Crispo, Engin Kirda, William Robertson(2020)](https://arxiv.org/abs/1912.10190)
		* Web cache deception (WCD) is an attack proposed in 2017, where an attacker tricks a caching proxy into erroneously storing private information transmitted over the Internet and subsequently gains unauthorized access to that cached data. Due to the widespread use of web caches and, in particular, the use of massive networks of caching proxies deployed by content distribution network (CDN) providers as a critical component of the Internet, WCD puts a substantial population of Internet users at risk. We present the first large-scale study that quantifies the prevalence of WCD in 340 high-profile sites among the Alexa Top 5K. Our analysis reveals WCD vulnerabilities that leak private user data as well as secret authentication and authorization tokens that can be leveraged by an attacker to mount damaging web application attacks. Furthermore, we explore WCD in a scientific framework as an instance of the path confusion class of attacks, and demonstrate that variations on the path confusion technique used make it possible to exploit sites that are otherwise not impacted by the original attack. Our findings show that many popular sites remain vulnerable two years after the public disclosure of WCD. Our empirical experiments with popular CDN providers underline the fact that web caches are not plug & play technologies. In order to mitigate WCD, site operators must adopt a holistic view of their web infrastructure and carefully configure cache settings appropriate for their applications.
* **Talks/Presentations/Videos**
	* [Web Cache Deception Attack - Omer Gil(BHUSA 2017)](https://www.youtube.com/watch?v=mroq9eHFOIU)
		* [slides](https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack.pdf)
		* Web Cache Deception attack is a new web attack vector that puts various technologies and frameworks at risk. By manipulating behaviors of web servers and caching mechanisms, anonymous attackers can expose sensitive information of authenticated application users, and in certain cases to even take control over their accounts.
	* [Web Cache Deception attack: A new web attack vector - ](https://www.youtube.com/watch?v=FwFKaXM3QJ0)
	* [Cached and Confused: Web Cache Deception in the Wild - Seyed Ali Mirheidari, Sajjad "JJ" Arshad(h@ckivitycon 2020)](https://www.youtube.com/watch?v=czDfMWBsIKw)
		* Web Cache Deception (WCD) has been introduced in 2017 by Omer Gil, where an intruder lures a caching server to mistakenly store private information publicly and as a result obtains unauthorized access to cached data. In this talk, we will introduce new exploitation techniques based on the semantic disconnect among different framework-independent web technologies (e.g., browsers, CDNs, web servers) which results in different URL path interpretations. We coined the term ‚ÄúPath Confusion‚Äù to represent this disagreement and we will present the effectiveness of this technique on WCD attack. In February 2020, our related research was voted and led to an award as the top web hacking technique of 2019 by PortSwigger.   We explore WCD as an instance of the path confusion class of attacks, and demonstrate that variations on the path confusion technique make it possible to exploit sites that are otherwise not impacted by the original attack. Our findings show that many popular sites remain vulnerable three years after the public disclosure of WCD. To further elucidate the seriousness of path confusion, we will also present the large scale analysis results of WCD attack on high profile sites. We present a semi-automated path confusion crawler which detects hundreds of sites that are still vulnerable to WCD only with specific types of path confusion techniques. We conclude the talk with explaining why path confusion is so complicated to remediate while shedding light on potential areas that researchers and bughunters can apply new attack vectors through different path confusion techniques.
* **Writeups**
	* [Web cache deception attack - expose token information - Memon Irshad(Hackerone2018)](https://hackerone.com/reports/397508)
	* [Web Cache Deception Attack leads to user info disclosure - Kunal Paney(2019)](https://medium.com/@kunal94/web-cache-deception-attack-leads-to-user-info-disclosure-805318f7bb29)
	* [Web cache deception attack on https://open.vanillaforums.com/messages/all - Ron Reshef(Hackerone2019)](https://hackerone.com/reports/593712)
* **Tools**
	* [Web Cache Deception Burp Extension](https://github.com/PortSwigger/web-cache-deception-scanner)
		* A Burp extension to test applications for vulnerability to the Web Cache Deception attack.

----------------
### Web Cache Poisoining Attack <a name="cachepoison"></a>
* **101**
	* [Web Cache Poisoning - PortSwigger](https://portswigger.net/research/practical-web-cache-poisoning)
* **Training**
	* [Web Cache Poisoning Tutorial - PortSwigger](https://portswigger.net/web-security/web-cache-poisoning)
* **Articles/Blogposts/Writeups**
	* [Practical Web Cache Poisoning - James Kettle(2018/20)](https://portswigger.net/research/practical-web-cache-poisoning)
	* [Bypassing Web Cache Poisoning Countermeasures - James Kettle(2018/20)](https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures)
	* [Responsible denial of service with web cache poisoning - James Kettle(2019)](https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning)
	* [CPDoS: Cache Poisoned Denial of Service](https://cpdos.org/)
* **Talks/Presentations/Videos**
	* [Practical Web Cache Poisoning: Redefining 'Unexploitable' - James Kettle(BHUSA2018)](https://www.youtube.com/watch?v=j2RrmNxJZ5c)
		* [Slides](https://i.blackhat.com/us-18/Thu-August-9/us-18-Kettle-Practical-Web-Cache-Poisoning-Redefining-Unexploitable.pdf)
		* Modern web applications are composed from a crude patchwork of caches and content delivery networks. In this session I'll show you how to compromise websites by using esoteric web features to turn their caches into exploit delivery systems, targeting everyone that makes the mistake of visiting their homepage.
* **Tools**
	* [Param-miner](https://github.com/PortSwigger/param-miner)
		* This extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities.

----------------
### XML <a name="xml"></a>
* **101**
	* [XML Schema, DTD, and Entity Attacks: A Compendium of Known Techniques - Timothy D. Morgan, Omar Al Ibrahim(2014)](www.vsecurity.com/download/papers/XMLDTDEntityAttacks.pdf)
* **DOS**
	* **Articles/Papers/Talks/Writeups**
		* [Security Briefs - XML Denial of Service Attacks and Defenses(2009)](https://msdn.microsoft.com/en-us/magazine/ee335713.aspx)
* **XXE Attack**
	* **101**
		* [XXE (Xml eXternal Entity) attack(2002) - Gregory Steuck](https://www.securityfocus.com/archive/1/297714/2002-10-27/2002-11-02/0)
	* **Articles/Papers/Talks/Writeups**
		* [Hunting in the Dark - Blind XXE](https://blog.zsec.uk/blind-xxe-learning/)
		* [Exploiting Out Of Band XXE using internal network and php wrappers - Mahmoud Gamal](https://mahmoudsec.blogspot.com/2019/08/exploiting-out-of-band-xxe-using.html)
		* [Playing with Content-Type – XXE on JSON Endpoints - Antti Rantasaari](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
		* [XXE: How to become a Jedi - Yaroslav Babin(Zeronights 2017)](https://www.slideshare.net/ssuserf09cba/xxe-how-to-become-a-jedi)
		* [Advice From A Researcher: Hunting XXE For Fun and Profit](http://blog.bugcrowd.com/advice-from-a-researcher-xxe/)
		* [Leading the Blind to Light! - A Chain to RCE](https://blog.zsec.uk/rce-chain/)
		* [Generic XXE Detection - Christian Schneider](http://www.christian-schneider.net/GenericXxeDetection.html)
		* [Playing with Content-Type – XXE on JSON Endpoints - NETSPI](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
		* [XXE OOB exploitation at Java 1.7+ - 2014](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html)
		* [Security of applications that parse XML (supplementary) - 2009](http://d.hatena.ne.jp/teracc/20090718)
		* [Exploiting XXE In File Upload Functionality](https://www.blackhat.com/docs/us-15/materials/us-15-Vandevanter-Exploiting-XXE-Vulnerabilities-In-File-Parsing-Functionality.pdf)
		* [XML Parser Evaluation - web-in-security.blogspot.de](https://web-in-security.blogspot.de/2016/03/xml-parser-evaluation.html)
		* [Hiding in Plain Sight: XXE Vulnerability in HP Project & Portfolio Mgmt Center - Benjamin Caudill](https://rhinosecuritylabs.com/application-security/xxe-zeroday-vulnerability-in-hp-project/)
		* [Don’t open that XML: XXE to RCE in XML plugins for VS Code, Eclipse, Theia, … - thezero](https://www.shielder.it/blog/dont-open-that-xml-xxe-to-rce-in-xml-plugins-for-vs-code-eclipse-theia/)
		* [Playing with Content-Type – XXE on JSON Endpoints(2015) - Antti Rantasaari](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
	* **Talks/Presentations/Videos**
		* [Black Hat EU 2013 - XML Out-of-Band Data Retrieval](https://www.youtube.com/watch?v=eBm0YhBrT_c)
			* [Slides: XML Out-­Of-Band Data Retrieval - BHEU 2013](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)
		* [What You Didn't Know About XML External Entities Attacks - Timothy D. Morgan](http://2013.appsecusa.org/2013/wp-content/uploads/2013/12/WhatYouDidntKnowAboutXXEAttacks.pdf)
		* [Exploiting XXE Vulnerabilities In File Parsing Functionality - Willis Vandevanter - BHUSA 2015](https://www.youtube.com/watch?v=LZUlw8hHp44)
			* In this 25-minute briefing, we will discuss techniques for exploiting XXE vulnerabilities in File Parsing/Upload functionality. Specifically, XML Entity Attacks are well known, but their exploitation inside XML supported file formats such as docx, xlsx, pptx, and others are not. Discussing the technically relevant points step by step, we will use real world examples from products and recent bug bounties. Finally, in our experience, creating 'XXE backdoored' files can be a very slow process. We will introduce our battle tested tool for infecting the file formats discussed.
		* [FileCry - The New Age of XXE - BH USA 2015](https://www.blackhat.com/docs/us-15/materials/us-15-Wang-FileCry-The-New-Age-Of-XXE.pdf)
	* **Papers**
		* [Security Implications of DTD Attacks Against a Wide Range of XML Parsers](https://www.nds.rub.de/media/nds/arbeiten/2015/11/04/spaeth-dtd_attacks.pdf)
	* **CVEs**
		* [Exploiting CVE-2016-4264 With OXML_XXE](https://www.silentrobots.com/blog/2016/10/02/exploiting-cve-2016-4264-with-oxml-xxe/)
* **Reference**
	* [Testing for XML Injection (OTG-INPVAL-008) - OWASP](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
	* [XML Security Cheat Sheet - OWASP](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)
	* [XML External Entity (XXE) Prevention Cheat Sheet - OWASP](https://www.owasp.org/index.php/XML_External_Entity_(XXE)\_Prevention_Cheat_Sheet)
	* [XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_(XXE)\_Processing)
* **Tools**
	* [XXEinjector](https://github.com/enjoiz/XXEinjector)
		* XXEinjector automates retrieving files using direct and out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications
	* [oxml_xxe](https://github.com/BuffaloWill/oxml_xxe)
		* This tool is meant to help test XXE vulnerabilities in file formats.
* **Miscellaneous**
	* [XML External Entity Injection in Jive-n (CVE-2018-5758) - Spencer Gietzen](https://rhinosecuritylabs.com/research/xml-external-entity-injection-xxe-cve-2018-5758/)

----------------
## Miscellaneous <a name="misc"></a>

### Burp Stuff/Plugins <a name="burp"></a>
* **Tutorials/Tips/Stuff**
	* **101**
		* [Issue Definitions](https://portswigger.net/kb/issues)
			* This listing contains the definitions of all issues that can be detected by Burp Scanner.
		* [Burp Suite Training - PortSwigger](https://portswigger.net/training)
	* **Articles/Blogposts/Writeups**
		* [Burp Pro : Real-life tips and tricks](https://hackinparis.com/talk-nicolazs-gregoire)
		* [Behind enemy lines: Bug hunting with Burp Infiltrator](http://blog.portswigger.net/2017/06/behind-enemy-lines-bug-hunting-with.html)
		* [Automating Web Apps Input fuzzing via Burp Macros](http://blog.securelayer7.net/automating-web-apps-input-fuzzing-via-burp-macros/)
		* [Burp Suite Visual Aids - lanmaster53](https://www.lanmaster53.com/2015/04/24/burp-suite-visual-aids/)
		* [SSH "accept : too many open files" on OS X when using Burp - dewhurstsecurity.com](https://blog.dewhurstsecurity.com/2013/04/08/ssh-too-many-open-files-burp.html)
		* [Brute Forcing with Burp - Pentesters Tips & Tricks Week 1 - securenetwork.com](https://www.securenetworkinc.com/news/2017/7/16/brute-forcing-with-burp-pentesters-tips-tricks-week-1)
	* **Talks/Presentations/Videos**
		* [OWASP Top 10: Hacking Web Applications with Burp Suite - Chad Furman](https://www.youtube.com/watch?v=2p6twRRXK_o)
		* [Tactical Burp Suite: Next steps webcast - SecureIdeas(2020)](https://www.youtube.com/watch?v=DFnxptySDgI&feature=youtu.be)
			* Secure Ideas' Tactical Burp: Next Steps is a two-hour video exploring topics related to Burp Suite and its use in a web application penetration test. This course explores the various features of Burp Suite, focusing on how we use the system during our penetration testing.
		* [Burp Macro Auto Authentication - CyberSecurityTV(2020)](https://www.youtube.com/watch?v=Ba2EzXP4swE)
			* Burp session handling rules are very powerful. In this episode, we have seen an example of how to configure burp to auto login or activate session after it detects session invalidity.
* **Wordlists**
	* [IntruderPayloads](https://github.com/1N3/IntruderPayloads/blob/master/README.md)
* **Plugins**
	* **Creating**
		* [Adapting Burp Extensions for Tailored Pentesting](http://blog.portswigger.net/2017/08/adapting-burp-extensions-for-tailored.html)
		* [Developing Burp Suite Extensions - DOYENSEC](https://github.com/doyensec/burpdeveltraining)
			* Material for the training "Developing Burp Suite Extensions – From Manual Testing to Security Automation"
	* **API**
		* [burp-rest-api](https://github.com/vmware/burp-rest-api)
			* A REST/JSON API to the Burp Suite security tool.  Upon successfully building the project, an executable JAR file is created with the Burp Suite Professional JAR bundled in it. When the JAR is launched, it provides a REST/JSON endpoint to access the Scanner, Spider, Proxy and other features of the Burp Suite Professional security tool.
	* **AuthN/AuthZ-related**
		* [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)
			* AuthMatrix is a Burp Suite extension that provides a simple way to test authorization in web applications and web services.
		* [Autorize](https://github.com/Quitten/Autorize)
			* Autorize is an automatic authorization enforcement detection extension for Burp Suite. It was written in Python by Barak Tawily, an application security expert, and Federico Dotta, a security expert at Mediaservice.net. Autorize was designed to help security testers by performing automatic authorization tests. With the last release now Autorize also perform automatic authentication tests.
		* [Escalating Privileges like a Pro - Gaurav Narwani](https://gauravnarwani.com/escalating-privileges-like-a-pro/)
		* [AutoRepeater](https://github.com/nccgroup/AutoRepeater)
			* Burp Suite is an intercepting HTTP Proxy, and it is the defacto tool for performing web application security testing. While Burp Suite is a very useful tool, using it to perform authorization testing is often a tedious effort involving a "change request and resend" loop, which can miss vulnerabilities and slow down testing. AutoRepeater, an open source Burp Suite extension, was developed to alleviate this effort. AutoRepeater automates and streamlines web application authorization testing, and provides security researchers with an easy-to-use tool for automatically duplicating, modifying, and resending requests within Burp Suite while quickly evaluating the differences in responses.
		* [Uniqueness plugin for Burp Suite](https://github.com/silentsignal/burp-uniqueness)
			* Makes requests unique based on regular expressions. Handy for registration forms and any other endpoint that requires unique values upon every request.
	* **Collaborator-related**
		* [collaborator-everywhere](https://github.com/PortSwigger/collaborator-everywhere)
			* A Burp Suite Pro extension which augments your proxy traffic by injecting non-invasive headers designed to reveal backend systems by causing pingbacks to Burp Collaborator
	* **Extra-Checks/Scanners**
		* [backslash-powered-scanner](https://github.com/PortSwigger/backslash-powered-scanner)
			* This extension complements Burp's active scanner by using a novel approach capable of finding and confirming both known and unknown classes of server-side injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering.
		* [HUNT](https://github.com/bugcrowd/HUNT)
			* HUNT is a Burp Suite extension to: 1. Identify common parameters vulnerable to certain vulnerability classes; 2. Organize testing methodologies inside of Burp Suite;
		* [Burp-molly-pack](https://github.com/yandex/burp-molly-pack)
			* Burp-molly-pack is Yandex security checks pack for Burp. The main goal of Burp-molly-pack is to extend Burp checks. Plugins contains Active and Passive security checks.
		* [burp-suite-error-message-checks](https://github.com/ewilded/burp-suite-error-message-checks)
			* Burp Suite extension to passively scan for applications revealing server error messages
		* [Asset Discover](https://github.com/redhuntlabs/BurpSuite-Asset_Discover)
			* Burp Suite extension to discover assets from HTTP response using passive scanning.
			* [Blogpost](https://redhuntlabs.com/blog/asset-discovery-burp-extension.html)
		* [Dr. Watson](https://github.com/prodigysml/Dr.-Watson)
			* Dr. Watson is a simple Burp Suite extension that helps find assets, keys, subdomains, IP addresses, and other useful information! It's your very own discovery side kick, the Dr. Watson to your Sherlock!
		* [LinkDumper Burp Plugin](https://github.com/arbazkiraak/LinksDumper)
			* Extract (links/possible endpoints) from responses & filter them via decoding/sorting
		* [BurpExtenderHeaderChecks](https://github.com/eonlight/BurpExtenderHeaderChecks)
		* [SQLTruncScanner](https://github.com/InitRoot/BurpSQLTruncSanner)
			* Messy BurpSuite plugin for SQL Truncation vulnerabilities.
		* [Asset_Discover](https://github.com/redhuntlabs/BurpSuite-Asset_Discover)
			* Burp Suite extension to discover assets from HTTP response using passive scanning.
	* **Extended-Functionality**
		* [burp-highlighter](https://github.com/CarveSystems/burp-highlighter/)
			* [Blogpost](https://carvesystems.com/news/rule-based-highlighter-plugin-for-burpsuite/)
		* [Exporter Extension for Burp Suite](https://github.com/artssec/burp-exporter)
			* Exporter is a Burp Suite extension to copy a request to the clipboard as multiple programming languages functions.
		* [Stepper](https://github.com/portswigger/stepper)
			* Stepper is designed to be a natural evolution of Burp Suite's Repeater tool, providing the ability to create sequences of steps and define regular expressions to extract values from responses which can then be used in subsequent steps.
		* [Piper](https://github.com/silentsignal/burp-piper)
			* [Unix-style approach to web application testing - Andras Veres-Szentkiralyi(2020)](https://www.sans.org/reading-room/whitepapers/testing/paper/39440)
				* Web application testers of our time have lots of tools at their disposal. Some of these offer the option to be extended in ways the original developers did not think of, thus making their tool more useful. However, developing extensions or plugins have entry barriers in the form of fixed costs, boilerplate, et cetera. At the same time, many problems already have a solution designed as a smaller standalone program, which could be combined in the Unix fashion to produce a useful complex tool quickly and easily. In this paper, a (meta)solution is introduced for this integration problem by lowering the entry barriers and offer several examples that demonstrate how it saved time in web application assessments.
	* **Forced-Browsing/File Discovery**
		* [BurpSmartBuster](https://github.com/pathetiq/BurpSmartBuster)
			* Looks for files, directories and file extensions based on current requests received by Burp Suite
	* **J2EE**
		* [J2EEScan](https://github.com/ilmila/J2EEScan)
			* J2EEScan is a plugin for Burp Suite Proxy. The goal of this plugin is to improve the test coverage during web application penetration tests on J2EE applications.
	* **JavaScript**
		* [BitMapper](https://github.com/BitTheByte/BitMapper)
			* Burp-suite Extension For finding .map files
	* **JSONP**
		* [jsonp](https://github.com/kapytein/jsonp)
			* jsonp is a Burp Extension which attempts to reveal JSONP functionality behind JSON endpoints. This could help reveal cross-site script inclusion vulnerabilities or aid in bypassing content security policies.
	* **JWTs**
		* [JWT4B](https://github.com/mvetsch/JWT4B)
			* JSON Web Tokens (JWT) support for the Burp Interception Proxy. JWT4B will let you manipulate a JWT on the fly, automate common attacks against JWT and decode it for you in the proxy history. JWT4B automagically detects JWTs in the form of 'Authorization Bearer' headers as well as customizable post body parameters.
		* [jwt-heartbreaker](https://github.com/wallarm/jwt-heartbreaker)
			* The Burp extension to check JWT (JSON Web Tokens) for using keys from known from public sources
			* [Blogpost](https://lab.wallarm.com/meet-jwt-heartbreaker-a-burp-extension-that-finds-thousands-weak-secrets-automatically/)
	* **Proxy**
		* [NoPE Proxy](https://github.com/summitt/Burp-Non-HTTP-Extension)
			* Non-HTTP Protocol Extension (NoPE) Proxy and DNS for Burp Suite.
	* **Postman**
		* [Postman-Integration](https://github.com/PortSwigger/postman-integration)
			* Postman Integration is an extension for burp to generate Postman collection fomat json file.
	* **SAML**
		* [SAML Raider](https://github.com/SAMLRaider/SAMLRaider)
			* SAML Raider is a Burp Suite extension for testing SAML infrastructures. It contains two core functionalities: Manipulating SAML Messages and manage X.509 certificates.
	* **Serialization**
		* [Freddy the Serial(isation) Killer - Deserialization Bug Finder](https://github.com/nccgroup/freddy)
			* A Burp Suite extension to aid in detecting and exploiting serialisation libraries/APIs.
	* **Single-Page-Apps**
		* [BurpKit](https://github.com/allfro/BurpKit)
			* BurpKit is a BurpSuite plugin which helps in assessing complex web apps that render the contents of their pages dynamically. It also provides a bi-directional Script bridge API which allows users to create quick one-off BurpSuite plugin prototypes which can interact directly with the DOM and Burp's extender API.
	* **Sitemap**
		* [PwnBack](https://github.com/k4ch0w/PwnBack)
			* Burp Extender plugin that generates a sitemap of a website using Wayback Machine
	* **SQL Injection**
		* [sqlipy](https://github.com/portswigger/sqli-py)
			 * SQLiPy is a Python plugin for Burp Suite that integrates SQLMap using the SQLMap API.
		* [SQLi Query Tampering](https://github.com/xer0days/SQLi-Query-Tampering)
			* SQLi Query Tampering extends and adds custom Payload Generator/Processor in Burp Suite's Intruder. This extension gives you the flexibility of manual testing with many powerful evasion techniques.
	* **Swagger**
		* [swurg](https://github.com/AresS31/swurg)
			* Parses Swagger files into the BurpSuite for automating RESTful API testing – approved by Burp for inclusion in their official BApp Store.
	* **WAFs**
		* [HTTPSmuggler](https://github.com/nccgroup/BurpSuiteHTTPSmuggler)
			* A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques. This extension has been developed by Soroush Dalili (@irsdl) from NCC Group.
	* **Wordlists**
		* [Golden Nuggets](https://github.com/GainSec/GoldenNuggets-1)
			* Burp Suite Extension to easily create Wordlists based off URI, URI Parameters and Single Words (Minus the Domain)
	* **Other**
		* [C02](https://code.google.com/p/burp-co2/)
			* Co2 includes several useful enhancements bundled into a single Java-based Burp Extension. The extension has it's own configuration tab with multiple sub-tabs (for each Co2 module). Modules that interact with other Burp tools can be disabled from within the Co2 configuration tab, so there is no need to disable the entire extension when using just part of the functionality.
		* [distribute-damage](https://github.com/PortSwigger/distribute-damage)
			* Designed to make Burp evenly distribute load across multiple scanner targets, this extension introduces a per-host throttle, and a context menu to trigger scans from. It may also come in useful for avoiding detection.
		* [Office Open XML Editor - burp extension](https://github.com/maxence-schmitt/OfficeOpenXMLEditor)
		* [Bumpster](https://github.com/markclayton/bumpster)
			* The Unofficial Burp Extension for DNSDumpster.com. You simply supply a domain name and it returns a ton of DNS information and basically lays out the external network topology.
		* [ParrotNG - burp plugin](https://portswigger.net/bappstore/bapps/details/f99325340a404c67a8de2ce593824e0e)
		* [Brida](https://github.com/federicodotta/Brida)
			* Brida is a Burp Suite Extension that, working as a bridge between Burp Suite and Frida, lets you use and manipulate applications’ own methods while tampering the traffic exchanged between the applications and their back-end services/servers. It supports all platforms supported by Frida (Windows, macOS, Linux, iOS, Android, and QNX)
		* [Cyber Security Transformation Chef](https://github.com/usdAG/cstc)
			* The Cyber Security Transformation Chef (CSTC) is a Burp Suite extension. It is build for security experts to extend Burp Suite for chaining simple operations for each incomming or outgoing message. It can also be used to quickly make a special custom formatting for the message.
		* [Hackbar](https://github.com/d3vilbug/HackBar)
			* Hackbar plugin for Burp
		* [progress-burp](https://github.com/dariusztytko/progress-burp)
			* Burp Suite extension to track vulnerability assessment progress

----------------
### Cloudflare <a name="cloudflare"></a>
* **101**
* **Articles/Blogposts/Writeups**
	* [CloudFlair: Bypassing Cloudflare using Internet-wide scan data - blog.christophetd](https://blog.christophetd.fr/bypassing-cloudflare-using-internet-wide-scan-data/)
	* [Exposing Server IPs Behind CloudFlare - chokepoint](http://www.chokepoint.net/2017/10/exposing-server-ips-behind-cloudflare.html)
	* [Introducing CFire: Evading CloudFlare Security Protections - rhinosecuritylabs](https://rhinosecuritylabs.com/cloud-security/cloudflare-bypassing-cloud-security/)
* **Tools**
	* [CloudFlair](https://github.com/christophetd/CloudFlair)
		* CloudFlair is a tool to find origin servers of websites protected by CloudFlare who are publicly exposed and don't restrict network access to the CloudFlare IP ranges as they should. The tool uses Internet-wide scan data from Censys to find exposed IPv4 hosts presenting an SSL certificate associated with the target's domain name.
	* [CloudFire](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/cfire)
		* This project focuses on discovering potential IP's leaking from behind cloud-proxied services, e.g. Cloudflare. Although there are many ways to tackle this task, we are focusing right now on CrimeFlare database lookups, search engine scraping and other enumeration techniques.

----------------
### Bug Bounty Writeups <a name="bugbounty"></a>
* [List of bug bounty writeups](https://pentester.land/list-of-bug-bounty-writeups.html)
* [HackerOne H1-212 Capture the Flag Solution - Corben Douglas](http://www.sxcurity.pro/H1-212%20CTF%20Solution.pdf)
* [ebay.com: RCE using CCS](http://secalert.net/#ebay-rce-ccs)
* [$10k host header - eze2307](https://sites.google.com/site/testsitehacking/10k-host-header)
* [REMOTE CODE EXECUTION! Recon Wins - vishnuraj](https://medium.com/@vishnu0002/remote-code-execution-recon-wins-e9c1db79f3da)
* [Analyzing a Creative Attack Chain Used To Compromise A Web Application](https://www.offensive-security.com/offsec/analyzing-a-creative-attack-chain/)
* [RCE in Hubspot with EL injection in HubL - betterhacker.com](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html)
	* "This is the story of how I was able to get remote code execution on Hubspot's servers by exploiting a vulnerability in HubL expression language, which is used for creating templates and custom modules within the Hubspot CRM."
* [Hacking Slack using postMessage and WebSocket-reconnect to steal your precious token - labs.detectify](https://labs.detectify.com/2017/02/28/hacking-slack-using-postmessage-and-websocket-reconnect-to-steal-your-precious-token/)
* **Tools**
	* [Boucan: A Bug Bounty Canary Platform](https://github.com/3lpsy/boucanpy)
		* This project is an attempt to implement a lightweight burp collaborator-esc application and consists of two main components: a DNS Server (Custom Python Implemention with dnslib) and an API. It is still very much in the early days of development. You can think of Boucan as sort of a Canary that will notify you when an external asset (DNS Record, HTTP Server, SMTP Server) has been interacted with. This is useful for blind payload injection.
	* [Keyhacks](https://github.com/streaak/keyhacks)
		* Keyhacks is a repository which shows quick ways in which API keys leaked by a bug bounty program can be checked to see if they're valid.

----------------
### Random <a name="random"></a>
* [unindexed](https://github.com/mroth/unindexed)
	* The site is constantly searching for itself in Google, over and over and over, 24 hours a day. The instant it finds itself in Google search results, the site will instantaneously and irrevocably securely delete itself. Visitors can contribute to the public content of the site, these contributions will also be destroyed when the site deletes itself.
* [COWL: A Confinement System for the Web](http://cowl.ws/)
	* Robust JavaScript confinement system for modern web browsers. COWL introduces label-based mandatory access control to browsing contexts (pages, iframes, etc.) in a way that is fully backward-compatible with legacy web content.
	* [Paper](http://www.scs.stanford.edu/~deian/pubs/stefan:2014:protecting.pdf)
