# The Web, Web Applications & Browsers

----------------------------------
## Table of Contents
- [General](#general)
	- Purposely Vulnerable Web Apps -> See 'Building a Lab' page.
- [Standards](#standards)
	- [Content Security Policy(CSP)](#csp)
	- [Common Origin Resource Sharing (CORS)](#cors)
	- [Document Object Model(DOM)](#dom)
	- [HTML](#html)
	- [Hyper Text Transport Protocol (HTTP)](#http)
	- [OAUTH](#oauth)
	- [Robots.txt](#robots)
	- [Same-Origin-Policy](#sop)
	- [Security Assertion Markup Language (SAML))](#saml)
	- [Service Workers](#serviceworkers)
	- [SubResource Integrity](#sri)
	- [Uniform Resource Identifier/Locator(URIs/URLs)](#uri)
	- [WebAuthentication](#webauthn)
	- [WebBluetooth](#webbt)
	- [Web Hooks](#webhook)
	- [WebNFC](#webnfc)
	- [WebRTC](#webrtc)
	- [WebSockets](#websockets)
	- [WebUSB](#webusb)
- [Technologies](#technologies)
	- [APIs](#api)
	- [Browser Security](#browsersec)
		- [Browser Extensions](#be)
	- [SSL/TLS](#ssltls)
		- [Certificate Transparency](#ct)
		- [TLS Redirection/VirtualHost Confusion](#tls-redirect)
	- [CMS Specific Tools](#cms)
	- [Cold Fusion](#coldfusion)
	- [Continous Integration/Build Systems](#cii)
	- [Electron](#electron)
	- [Flash/SWF](#swf)
	- [Javascript](#javascript)
	- [Java Server Faces](#jsf)
	- [Java Server Pages](#jsp)
	- [JSON Web Tokens](#jwt)
	- [MIME Sniffing](#mime)
	- [NodeJS](#nodejs)
	- [PASETO](#paseto)
	- [PHP](#php)
	- [REST & Web Services](#rest)
	- [Ruby](#ruby)
	- [Single Sign-On](#sso)
	- [Web Application Firewalls(WAFs)](#waf)
	- [Web Assembly](#webasm)
	- [Web Frameworks](#webframeworks)
	- [Web Proxies](#webproxy)
	- [Web Servers](#webservers)
- [Cloud-Related](#cloud)
	- [AWS stuff](#aws)
	- [Cloudflare related](#cloudflare)
	- [Google Compute Cloud/AppEngine](#gcc)
- [Tactics & Techniques](#tt)
	- [Discovery](#disco)
	- [Scraping](#scraping)
	- [Site/WebApp Scanners](#scanners)
- [Different Types of Attacks](#difatk)
	- [Abuse of Functionality](#abuse)
	- [Brute Force Fuzzing](#brute)
	- [Attacking Continous Integration Systems](#ci)
	- [ClickJacking](#clickjack)
	- [Cross-Protocol Request](#cpr)
	- [Cross-Site History Manipulation (XHSM)](#xhsm)
	- [Cross-Site-Request Forgery](#csrf)
	- [CSV Injection](#csv)
	- [De/Encoders](#encode)
	- [Data Structure Attacks](#dsa)
	- [Embedded Malicious Code](#emc)
	- [Exploitation of Authentication](#eoa) 
	- [File Upload Testing](#file)
	- [HTML Smuggling](#hsmug)
	- [HTTP Request Smuggling](#httprs)
	- [Insecure Direct Object Reference](#idor)
	- [Injection Based Attacks](#ija)
		- [OS Command Injection](#osc)
		- [(NO)SQL Injection](#sql)
	- [JNDI](#jndi)
	- [Java Serialization Attacks](#jsa) 
	- [LFI & RFI](#lrfi)
	- [Path Traversal Attacks](#pta)
	- [Reflected File Download](#rfd)
	- [Server Side Request Forgery](#ssrf)
	- [Server Side Include](#ssi)
	- [Server Side Template Injection](#ssti)
	- [Tabnabbing](#tabnab)
	- [Timing Attacks](#timing)
	- [Typosquatting Attacks](#typosquatting)
	- [Web Cache Deception](#webcache)
	- [Web Shells](#shells)
	- [XML Related](#xml)
	- [XSS](#xss)
- [Miscellaneous](#misc)
	- [Web Application Attack Writeups](#writeups)
	- [Non-Attack Writeups](#nonwriteup)
	- [Burp Stuff/Plugins](#burp)
	- [BugBounty Writeups](#bugbounty)



* **To Do**
	* Fix ToC
	* Flesh out
		* CORS
		* SRI
		* CSP
		* Identity Providers/SSO Stuff
		* Web Assembly
		* Web Frameworks
		* webrtc
		* XML



----------------
### <a name="general">General</a>

* **101**
	ASVS
	* [OWASP Top Ten Project](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)
		* The OWASP Top 10 is a powerful awareness document for web application security. It represents a broad consensus about the most critical security risks to web applications. Project members include a variety of security experts from around the world who have shared their expertise to produce this list.
	* [The Website Obesity Crisis](http://idlewords.com/talks/website_obesity.htm)
	* [Video Testing stateful web application workflows - András Veres-Szentkirályi](https://www.youtube.com/watch?v=xiTFKigyncg)
	* [Paper Testing stateful web application workflows - SANS - András Veres-Szentkirályi](https://www.sans.org/reading-room/whitepapers/testing/testing-stateful-web-application-workflows-36637)
		* Most web applications used for complex business operations and/or employing advanced GUI frameworks have stateful functionality. Certain workflows, for example, might require completing certain steps before a transaction is committed, or a request sent by a client-side UI element might need several preceding requests that all contribute to the session state. Most automated tools focus on a request and maybe a redirection, thus completely missing the point in these cases, where resending a request gets ignored by the target application. As a result, while these tools are getting better day by day, using them for testing such execution paths are usually out of the question. Since thorough assessment is cumbersome without such tools, there's progress, but we are far from plug-and-play products. This paper focuses on the capabilities of currently available solutions, demonstrating their pros and cons, along with opportunities for improvement.
* **Cheat Sheets**
	* See 'Cheats.md' for cheatsheets




----------------------------------
## <a name="standards"></a>Standards

------------------------
### <a name="csp"></a> Content Security Policy (CSP)
* **101**
	* [Intro to content Security Policy](http://www.html5rocks.com/en/tutorials/security/content-security-policy/)
	* [Content Security Policy Level 3 - W3c Oct2018](https://www.w3.org/TR/CSP3/#intro)
	* [Content Security Policy - Wikipedia](https://en.wikipedia.org/wiki/Content_Security_Policy)
* **Articles/Papers/Talks/Writeups**
	* [GitHub's post-CSP journey - githubengineering](https://githubengineering.com/githubs-post-csp-journey/)
	* [Github's CSP Journey - githubengineering](https://githubengineering.com/githubs-csp-journey/)
	* [ CVE-2018-5175: Universal CSP strict-dynamic bypass in Firefox - Masato Kinugawa](https://mksben.l0.cm/2018/05/cve-2018-5175-firefox-csp-strict-dynamic-bypass.html)
	* [Content Security Policy Level 3 - w3c Feb2019](https://w3c.github.io/webappsec-csp/)
* **Tools**
* **Miscellaneous**


-------------------
### <a name="cors"></a> Cross-Origin Resource Sharing (CORS)
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
* **Papers/Talks/Writeups**
	* [Exploiting CORS Misconfigurations For Bitcoins And Bounties by James Kettle](https://www.youtube.com/watch?v=wgkj4ZgxI4c)
		*  Cross-Origin Resource Sharing (CORS) is a mechanism for relaxing the Same Origin Policy to enable communication between websites via browsers. It's already widely understood that certain CORS configurations are dangerous. In this presentation, I'll skim over the old knowledge then coax out and share with you an array of under-appreciated but dangerous subtleties and implications buried in the CORS specification. I'll illustrate each of these with recent attacks on real websites, showing how I could have used them to steal bitcoins from two different exchanges, partially bypass Google's use of HTTPS, and requisition API keys from numerous others. I'll also show how CORS blunders can provide an invaluable link in crafting exploit chains to pivot across protocols, exploit the unexploitable via server and client-side cache poisoning, and even escalate certain open redirects into vulnerabilities that are actually notable.
		* [Blogpost](http://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html)
* **Tools**
	* [CORStest](https://github.com/RUB-NDS/CORStest/blob/master/README.md)
		* A simple CORS misconfiguration scanner
* **Miscellaneous**


-------------------
### <a name="dom"></a>Document Object Model(DOM)
* **101**
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [DOM - Standard](https://dom.spec.whatwg.org/)
	* [DOM - Living Standard(Aug 2019)](https://dom.spec.whatwg.org/)


### <a name="html"></a>Hyper Text Markup Language HTML
* **101**
	* [HTML - spec.whatwg.org](https://html.spec.whatwg.org/multipage/)
	* [HTML 5 Standards](http://w3c.github.io/html/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [The HTML Handbook - Flavio Copes](https://www.freecodecamp.org/news/the-html-handbook/)
	* [HTML Punctuation Symbols, Punctuation Entities and ASCII Character Code Reference - toptotal.com](https://www.toptal.com/designers/htmlarrows/punctuation/)


---------------
### <a name="fetch"></a>Fetch
* * [Fetch Living Standard — 2019/7/16 - whatwg](https://fetch.spec.whatwg.org/#concept-fetch)
	* The Fetch standard defines requests, responses, and the process that binds them: fetching.

---------------
### <a name="http"></a>Hyper Text Transport Protocol (HTTP)
* **101**
	* [RFC 2068: Hypertext Transfer Protocol -- HTTP/1.1](https://www.ietf.org/rfc/rfc2068.txt)
	* [RFC 2616: Hypertext Transfer Protocol -- HTTP/1.1](https://www.ietf.org/rfc/rfc2616.txt)
	* [http-decision-diagram](https://github.com/for-GET/http-decision-diagram)
		* An activity diagram to describe the resolution of HTTP response status codes, given various headers, implemented via semantical callbacks.
* **Caching**
	* [RFC 7234: Hypertext Transfer Protocol (HTTP/1.1): Caching](https://httpwg.org/specs/rfc7234.html)
		* The Hypertext Transfer Protocol (HTTP) is a stateless application-level protocol for distributed, collaborative, hypertext information systems. This document defines HTTP caches and the associated header fields that control cache behavior or indicate cacheable response messages.
* **HTTP Headers**
	* [OWASP Secure Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)
	* [Guidelines for Setting Security Headers - Isaac Dawson](https://www.veracode.com/blog/2014/03/guidelines-for-setting-security-headers)
	* [HTTP Strict Transport Security - cio.gov](https://https.cio.gov/hsts/)
	* [IETF RFC 7034: HTTP Header Field X-Frame-Options](https://tools.ietf.org/html/rfc7034)
* **HTTP Methods**
	* [Detecting and Exploiting the HTTP PUT Method](http://www.smeegesec.com/2014/10/detecting-and-exploiting-http-put-method.html)
* **HTTP Objects**
	* [Object MetaInformation](https://www.w3.org/Protocols/HTTP/Object_Headers.html#public)
* **HTTP Parameters**

* **Syntax & Routing**
	* [RFC 7230: Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing](https://httpwg.org/specs/rfc7230.html)
		* The Hypertext Transfer Protocol (HTTP) is a stateless application-level protocol for distributed, collaborative, hypertext information systems. This document provides an overview of HTTP architecture and its associated terminology, defines the "http" and "https" Uniform Resource Identifier (URI) schemes, defines the HTTP/1.1 message syntax and parsing requirements, and describes related security concerns for implementations.
* **101**
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [HTTP Evasion](http://noxxi.de/research/http-evader-explained-8-borderline-robustness.html)	



---------------
### <a name="msniff"></a>MIME Sniffing
* **101**
	* [MIME Sniffing - whatwg.org](https://mimesniff.spec.whatwg.org/#matching-a-mime-type-pattern)
	* [Media Type Sniffing | draft-ietf-websec-mime-sniff-03](https://tools.ietf.org/html/draft-ietf-websec-mime-sniff-03)
		* Many web servers supply incorrect Content-Type header fields with their HTTP responses. In order to be compatible with these servers, user agents consider the content of HTTP responses as well as the Content-Type header fields when determining the effective media type of the response. This document describes an algorithm for determining the effective media type of HTTP responses that balances security and compatibility considerations
* **Articles/Blogposts/Presentations/Talks/Writeups**




---------------
### <a name="oauth"></a>OAUTH
* **101**
	* [OAuth 2.0 Security Best Current Practice draft-ietf-oauth-security-topics-05 - Expires Sept19,2018](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-05)
		* This document describes best current security practices for OAuth 2.0.. It updates and extends the OAuth 2.0 Security Threat Model to incorporate practical experiences gathered since OAuth 2.0 was published and cover new threats relevant due to the broader application of OAuth 2.0.
	* [OAuth 2.0 Dynamic Client Registration Protocol - rfc7591](https://tools.ietf.org/html/rfc7591)
		* This specification defines mechanisms for dynamically registering OAuth 2.0 clients with authorization servers. Registration requests send a set of desired client metadata values to the authorization server. The resulting registration responses return a client identifier to use at the authorization server and the client metadata values registered for the client. The client can then use this registration information to communicate with the authorization server using the OAuth 2.0 protocol. This specification also defines a set of common client metadata fields and values for clients to use during registration.
	* [The OAuth 2.0 Authorization Framework: JWT Secured Authorization Request - ietf.org](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-15)
		* The authorization request in OAuth 2.0 described in RFC 6749 utilizes query parameter serialization, which means that Authorization Request parameters are encoded in the URI of the request and sent through user agents such as web browsers. While it is easy to implement, it means that (a) the communication through the user agents are not integrity protected and thus the parameters can be tainted, and (b) the source of the communication is not authenticated. Because of these weaknesses, several attacks to the protocol have now been put forward. This document introduces the ability to send request parameters in a JSON Web Token (JWT) instead, which allows the request to be signed with JSON Web Signature (JWS) and encrypted with JSON Web Encryption (JWE) so that the integrity, source authentication and confidentiality property of the Authorization Request is attained. The request can be sent by value or by reference.
	* [OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound Access Tokens - ietf](https://tools.ietf.org/html/draft-ietf-oauth-mtls-07)
		* This document describes Transport Layer Security (TLS) mutual authentication using X.509 certificates as a mechanism for OAuth client authentication to the authorization sever as well as for certificate bound sender constrained access tokens as a method for a protected resource to ensure that an access token presented to it by a given client was issued to that client by the authorization server.
* **Articles/Blogposts/Writeups**
	* [Dancing with OAuth: Understanding how Authorization Works - Ashish Mathur](https://medium.com/@imashishmathur/0auth-a142656859c6)
	* [Shining a Light on OAuth Abuse with PwnAuth - Douglas Bienstock](https://www.fireeye.com/blog/threat-research/2018/05/shining-a-light-on-oauth-abuse-with-pwnauth.html)
	* [OAUTH – Everything you wanted to know but not really! - Elaheh Samani, Kevin Watkins](https://sector.ca/sessions/oauth-everything-you-wanted-to-know-but-not-really/)
	* [An Illustrated Guide to OAuth and OpenID Connect - David Neal](https://developer.okta.com/blog/2019/10/21/illustrated-guide-to-oauth-and-oidc)
	* [Analysis of Common Federated Identity Protocols: OpenID Connect vs OAuth 2.0 vs SAML 2.0 - hackedu.io](https://blog.hackedu.io/analysis-of-common-federated-identity-protocols/)
* **Presentations/Talks/Videos**
* **Attacking**
	* [The most common OAuth 2.0 Hacks - Okhomiak](https://habr.com/en/post/449182/)
	* [Bypassing GitHub's OAuth flow - Teddy Katz](https://blog.teddykatz.com/2019/11/05/github-oauth-bypass.html)




-----------------
### <a name="robots"></a> robots.txt
* **101**
	* [About /robots.txt - robotstxt.org](https://www.robotstxt.org/robotstxt.html)








-----------------
### <a name="sop"></a> Same-Origin Policy
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




-----------------
### <a name="saml"></a>Security Assertion Markup Language (SAML)
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
### <a name="serviceworkers"></a> Service Workers
* **101**
	* [Service Worker - w3c](https://w3c.github.io/ServiceWorker/)
		* This specification describes a method that enables applications to take advantage of persistent background processing, including hooks to enable bootstrapping of web applications while offline.  The core of this system is an event-driven Web Worker, which responds to events dispatched from documents and other sources. A system for managing installation, versions, and upgrades is provided.  The service worker is a generic entry point for event-driven background processing in the Web Platform that is extensible by other specifications.


----------------
### <a name="sri"></a> Subresource Integrity
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
### <a name="ssltls"></a>Secure Sockets Layer/Transport Layer Security(SSL/TLS)
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
### <a name="streams"></a>Streans
* **101**
	* [Streams - Dec12 2019](https://streams.spec.whatwg.org)
		* This specification provides APIs for creating, composing, and consuming streams of data that map efficiently to low-level I/O primitives.

---------------
### <a name="uri"></a>Uniform Resource Identifier/Locator(URIs/URLs)
* **101**
	* [RFC5785: Defining Well-Known Uniform Resource Identifiers (URIs)](https://tools.ietf.org/html/rfc5785)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [How to Obscure Any URL](http://www.pc-help.org/obscure.htm)




---------------
### <a name="webauthn"></a>Web Authentication
* **101**
	* [Web Authentication: An API for accessing Public Key Credentials](https://www.w3.org/TR/webauthn/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Security Concerns Surrounding WebAuthn: Don't Implement ECDAA (Yet) - P.I.E. Staff](https://paragonie.com/blog/2018/08/security-concerns-surrounding-webauthn-don-t-implement-ecdaa-yet)



---------------
### <a name="webbt"></a>WebBluetooth
* **101**
	* [Web Bluetooth](https://webbluetoothcg.github.io/web-bluetooth/)


-------------------
### <a name="webhooks"></a>Web Hooks
* **101**
	* [Webhooks - pbworks](https://webhooks.pbworks.com/w/page/13385124/FrontPage)
	* [WebHook - Wikipedia](https://en.wikipedia.org/wiki/Webhook)
* **Articles/Blogposts/Writeups**
	* [Abusing Webhooks for Command and Control - Dimitry Snezhkov - BSides LV 2017](https://www.youtube.com/watch?v=TmLoTrJuung)
		* [octohook](https://github.com/dsnezhkov/octohook)

---------------
### <a name="webnfc"></a>WebNFC
* **101**
	* [Web NFC](https://w3c.github.io/web-nfc/)

-------------
### <a name="webrtc"></a>WebRTC
* **101**
* **Articles/Papers/Talks/Writeups**
* **General**
* **Tools**
	* [STUN IP Address requests for WebRTC](https://github.com/diafygi/webrtc-ips)
* **Miscellaneous**


---------------
### <a name="websocket"></a>WebSockets
* **101**
	* [The WebSocket Protocol Standard - IETF](https://tools.ietf.org/html/rfc6455)
	* [WebSocket Protocol - RFC Draft 17](https://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17)
	* [Websockets - An Introduction - subudeepak](https://gist.github.com/subudeepak/9897212)
* **Articles/Papers/Talks/Writeups**
	* [What’s wrong with WebSocket APIs? Unveiling vulnerabilities in WebSocket APIs. - Mikhail Egorov](https://speakerdeck.com/0ang3el/whats-wrong-with-websocket-apis-unveiling-vulnerabilities-in-websocket-apis)
* **General**
* **Tools**
	* [WSSiP: A WebSocket Manipulation Proxy])(https://github.com/nccgroup/wssip)
		* Short for "WebSocket/Socket.io Proxy", this tool, written in Node.js, provides a user interface to capture, intercept, send custom messages and view all WebSocket and Socket.IO communications between the client and server.
* **Miscellaneous**


---------------
### <a name="webusb"></a>WebUSB
* **101**
	* [WebUSB API - Sept2017](https://wicg.github.io/webusb/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [WebUSB - How a website could steal data off your phone](https://labs.mwrinfosecurity.com/blog/webusb/)
		* This blog post looks in to the capabilities of WebUSB to understand how it works, the new attack surface, and privacy issues. We will describe the processes necessary to get access to devices and how permissions are handled in the browser. Then we will discuss some security implications and shows, how a website can use WebUSB to establish an ADB connection and effectively compromise a connected Android phone.


























----------------
## <a name="technologies">Technologies</a>

--------------------
### <a name="api"></a>API Stuff
* **General**
	* [WebSocket API Standards](https://www.w3.org/TR/2011/WD-websockets-20110929/)
	* [White House Web API Standards](https://github.com/WhiteHouse/api-standards)
		* This document provides guidelines and examples for White House Web APIs, encouraging consistency, maintainability, and best practices across applications. White House APIs aim to balance a truly RESTful API interface with a positive developer experience (DX).
	* [Build Simple Restful Api With Python and Flask Part 1 - Mukhammad Ginanjar Azie](https://medium.com/python-pandemonium/build-simple-restful-api-with-python-and-flask-part-1-fae9ff66a706)
	* [What Is OpenAPI?](https://swagger.io/docs/specification/about/)
	* [The OpenAPI Specification](https://github.com/OAI/OpenAPI-Specification)
		* The OpenAPI Specification (OAS) defines a standard, programming language-agnostic interface description for REST APIs, which allows both humans and computers to discover and understand the capabilities of a service without requiring access to source code, additional documentation, or inspection of network traffic. When properly defined via OpenAPI, a consumer can understand and interact with the remote service with a minimal amount of implementation logic. Similar to what interface descriptions have done for lower-level programming, the OpenAPI Specification removes guesswork in calling a service.
	* [The OpenAPI Specification](https://github.com/OAI/OpenAPI-Specification)
		* The OpenAPI Specification is a community-driven open specification within the OpenAPI Initiative, a Linux Foundation Collaborative Project. The OpenAPI Specification (OAS) defines a standard, programming language-agnostic interface description for REST APIs, which allows both humans and computers to discover and understand the capabilities of a service without requiring access to source code, additional documentation, or inspection of network traffic. When properly defined via OpenAPI, a consumer can understand and interact with the remote service with a minimal amount of implementation logic. Similar to what interface descriptions have done for lower-level programming, the OpenAPI Specification removes guesswork in calling a service.
* **Fuzzing**
	* [Fuzzapi](https://github.com/lalithr95/Fuzzapi/)
		* Fuzzapi is rails application which uses API_Fuzzer and provide UI solution for gem.
	* [Automating API Penetration Testing using fuzzapi - AppSecUSA 2016](https://www.youtube.com/watch?v=43G_nSTdxLk)
* **Building One**
	* [Building beautiful REST APIs using Flask, Swagger UI and Flask-RESTPlus](http://michal.karzynski.pl/blog/2016/06/19/building-beautiful-restful-apis-using-flask-swagger-ui-flask-restplus/)
* **Securing**
	* [OWASP API Security Project](https://www.owasp.org/index.php/OWASP_API_Security_Project)
	* [OWASP API Security Top 10](https://github.com/OWASP/API-Security)
	* [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist/)
		* Checklist of the most important security countermeasures when designing, testing, and releasing your API
* **Tools**
	* [Postman - chrome plugin](https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop)
	* [restclient - Firefox addon](https://addons.mozilla.org/de/firefox/addon/restclient/)
	* [Astra](https://github.com/flipkart-incubator/Astra)
		* REST API penetration testing is complex due to continuous changes in existing APIs and newly added APIs. Astra can be used by security engineers or developers as an integral part of their process, so they can detect and patch vulnerabilities early during development cycle. Astra can automatically detect and test login & logout (Authentication API), so it's easy for anyone to integrate this into CICD pipeline. Astra can take API collection as an input so this can also be used for testing apis in standalone mode.
	* [API-fuzzer](https://github.com/Fuzzapi/API-fuzzer)
		* API Fuzzer which allows to fuzz request attributes using common pentesting techniques and lists vulnerabilities


-------------------
### <a name="browsersec">Browser Security</a>
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
	* **Talks & Presentations**
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
### <a name="ct">Certificate Transparency</a>
* **General**
	* [Abusing Certificate Transparency Or How To Hack Web Applications BEfore Installation - Hanno Bock](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Hanno-Boeck-Abusing-Certificate-Transparency-Logs.pdf)
	* [The Spy in the Sandbox – Practical Cache Attacks in Javascript](http://iss.oy.ne.ro/SpyInTheSandbox.pdf)
		* We present the first micro-architectural side-channel attack which runs entirely in the browser. In contrast to other works in this genre, this attack does not require the attacker to install any software on the victim’s machine to facilitate the attack, the victim needs only to browse to an untrusted webpage with attacker-controlled content. This makes the attack model highly scalable and extremely relevant and practical to today’s web, especially since most desktop browsers currently accessing the In- ternet are vulnerable to this attack. Our attack, which is an extension of the last-level cache attacks of Yarom et al., allows a remote adversary recover information belonging to other processes, other users and even other virtual machines running on the same physical host as the victim web browser. We describe the fundamentals behind our attack, evaluate its performance using a high bandwidth covert channel and finally use it to construct a system-wide mouse/network activity logger. Defending against this attack is possible, but the required counter- measures can exact an impractical cost on other benign uses of the web browser and of the computer.
* **Tools**
	* [CTFR](https://github.com/UnaPibaGeek/ctfr)
		* Do you miss AXFR technique? This tool allows to get the subdomains from a HTTPS website in a few seconds. How it works? CTFR does not use neither dictionary attack nor brute-force, it just abuses of Certificate Transparency logs.
	* [Certificate Transparency Subdomains](https://github.com/internetwache/CT_subdomains)
		* An hourly updated list of subdomains gathered from certificate transparency logs.
https://github.com/SSLMate/certspotter
https://github.com/AnikHasibul/crtscan
https://github.com/chris408/ct-exposer



----------------
###<a name="cms">Content Management Systems
* **Drupal**
	* [Drupal Security Checklist](https://github.com/gfoss/attacking-drupal/blob/master/presentation/drupal-security-checklist.pdf)
	* [Drupal Attack Scripts](https://github.com/gfoss/attacking-drupal)
		* Set of brute force scripts and Checklist	
	* [Droopescan](https://github.com/droope/droopescan)
		* A plugin-based scanner that aids security researchers in identifying issues with several CMSs, mainly Drupal & Silverstripe.
	* [Uncovering Drupalgeddon 2 - Checkpoint](https://research.checkpoint.com/uncovering-drupalgeddon-2/)
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
### <a name="cii"></a>Continous Integration/Delivery/Build Systems
* [Hacking Jenkins Servers With No Password](https://www.pentestgeek.com/penetration-testing/hacking-jenkins-servers-with-no-password)
* [Hacking Jenkins - Ideas - Zeroknock](http://zeroknock.blogspot.com/search/label/Hacking%20Jenkins)
* [pwn_jenkins](https://github.com/gquere/pwn_jenkins)
	* Notes about attacking Jenkins servers
* [Hacking Jenkins Part 1 - Play with Dynamic Routing - Orange](http://blog.orange.tw/2019/01/hacking-jenkins-part-1-play-with-dynamic-routing.html)

--------------
### <a name="coldfusion"></a> ColdFusion
* [Attacking Adobe ColdFusion](http://jumpespjump.blogspot.com/2014/03/attacking-adobe-coldfusion.html)
* [ColdFusion Security Resources](https://www.owasp.org/index.php/ColdFusion_Security_Resources)
* [ColdFusion for Penetration Testers](http://www.slideshare.net/chrisgates/coldfusion-for-penetration-testers)


----------------
#### <a name="electron"></a>Electron
* **Articles**
	* [From Markdown to RCE in Atom](https://statuscode.ch/2017/11/from-markdown-to-rce-in-atom/)
	* [As It Stands - Electron Security - 2016](http://blog.scottlogic.com/2016/03/09/As-It-Stands-Electron-Security.html)
	* [As It Stands - Update on Electorn Security - 2016](http://blog.scottlogic.com/2016/06/01/An-update-on-Electron-Security.html)
	* [Modern Alchemy: Turning XSS into RCE](https://blog.doyensec.com/2017/08/03/electron-framework-security.html)
	* [Build cross platform desktop XSS, it’s easier than you think by Yosuke Hasegawa - CodeBlue16](https://www.slideshare.net/codeblue_jp/cb16-hasegawa-en)
	* [Modern Alchemy: Turning XSS into RCE - doyensec](https://blog.doyensec.com/2017/08/03/electron-framework-security.html)
	* [From Markdown to RCE in Atom - statuscode.ch](https://statuscode.ch/2017/11/from-markdown-to-rce-in-atom/)
	* [Instrumenting Electron Apps for Security Testing - Paolo Stagno](https://blog.doyensec.com/2018/07/19/instrumenting-electron-app.html)
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







----------------
### <a name="swf"></a>Flash/SWF
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
### <a name="javascript">JavaScript</a>
* **General**
	* [DOM Clobbering Attack](http://www.thespanner.co.uk/2013/05/16/dom-clobbering/)
* **101**
* **Articles/Blogposts/Writeups**
	* [Static Analysis of Client-Side JavaScript for pen testers and bug bounty hunters - Bharath](https://blog.appsecco.com/static-analysis-of-client-side-javascript-for-pen-testers-and-bug-bounty-hunters-f1cb1a5d5288)
* **Reverse-Engineering**
	* [Reverse engineering obfuscated JavaScript - PopUnder Chrome 59 - LiveOverflow](https://www.youtube.com/watch?v=8UqHCrGdxOM)
	* [Reverse engineering PopUnder trick for Chrome 60 - LiveOverflow](https://www.youtube.com/watch?v=PPzRcZLNCPY)
	* [Custom Chromium Build to Reverse Engineer Pop-Under Trick - LiveOverflow](https://www.youtube.com/watch?v=y6Uzinz3DRU)
	* [[Live] Reverse Engineering new PopUnder for Chrome 63 on Windows - LiveOverflow](https://www.youtube.com/watch?v=VcFQeimLH1c)
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
### <a name="jsf"></a>Java Server Faces (JSF)
* **101**
	* [Java Server Faces - Wikipedia](https://en.wikipedia.org/wiki/JavaServer_Faces)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Misconfigured JSF ViewStates can lead to severe RCE vulnerabilities - alphabot](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)



----------------
### <a name="jsp"></a>Java Server Pages (JSP)
* **101**
	* [Java Server Pages - Wikipedia](https://en.wikipedia.org/wiki/JavaServer_Pages)
	* [JSP Tutorial - javapoint](https://www.javatpoint.com/jsp-tutorial)
	* [JSP Tutorial - some Examples of Java Servlet Pages - imperial.ac.uk](http://www.imperial.ac.uk/computing/csg/guides/java/jsp-tutorial---some-examples-of-java-servlet-pages/)
* **Articles/Blogposts/Presentations/Talks/Writeups**
	* [Hacking with JSP Shells - NetSPI](https://blog.netspi.com/hacking-with-jsp-shells/)
	* [A Smaller, Better JSP Web Shell - securityriskadvisors](https://securityriskadvisors.com/blog/post/a-smaller-better-jsp-web-shell/)
		* [Code](https://github.com/SecurityRiskAdvisors/cmd.jsp)



-------------------
### <a name="jwt"></a>JSON Web Tokens
* **101**
	* [JSON Web Token - Wikipedia](https://en.wikipedia.org/wiki/JSON_Web_Token)
	* [RFC 7159: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
	* [The Anatomy of a JSON Web Token](https://scotch.io/tutorials/the-anatomy-of-a-json-web-token)
	* [Introduction to JSON Web Tokens](https://jwt.io/introduction/) 
	* [JSON Web Token Flowchart](http://cryto.net/%7Ejoepie91/blog/attachments/jwt-flowchart.png)
	* [JSON Web Token Security Cheat Sheet](https://assets.pentesterlab.com/jwt_security_cheatsheet/jwt_security_cheatsheet.pdf)
	* [Learn JSON Web Token(JWT) in 10 Minutes - tutorialdocs.com](https://www.tutorialdocs.com/article/jwt-learn.html)
* **Articles/Blogposts/Writeups**
	* [JWT Handbook - Auth0](https://auth0.com/resources/ebooks/jwt-handbook)
	* [Friday the 13th: JSON Attacks - Defcon25](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Alvaro-Munoz-JSON-attacks.pdf)
	* [Critical vulnerabilities in JSON Web Token libraries - 2015](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
	* [Stop using JWT for sessions, part 2: Why your solution doesn't work - joepie91](http://cryto.net/~joepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/)
	* [JSON Web Token Best Current Practices - draft-ietf-oauth-jwt-bcp-07](https://tools.ietf.org/html/draft-ietf-oauth-jwt-bcp-07)
* **Presentations/Talks/Videos**
	* [Jwt==insecurity? - Ruxcon2018](https://www.slideshare.net/snyff/jwt-insecurity)
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
* **Writeups**
	* [How to configure Json.NET to create a vulnerable web API - alphabot](https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html)
	* [🔐 Learn how to use JSON Web Token (JWT) to secure your next Web App! (Tutorial/Example with Tests!!)](https://github.com/dwyl/learn-json-web-tokens)
	* [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
	* [Brute Forcing HS256 is Possible: The Importance of Using Strong Keys in Signing JWTs](https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/)
	* [Hacking JSON Web Token (JWT) - Hate_401](https://medium.com/101-writeups/hacking-json-web-token-jwt-233fe6c862e6)
* [JWT (JSON Web Token) (in)security - Michal Sadjak]
* [Practical Approaches for Testing and Breaking JWT Authentication - Mazin Ahmed](https://mazinahmed.net/blog/breaking-jwt/)




-------------
### <a name="mime">MIME Sniffing</a>
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




-------------------
### <a name="nodejs"></a> NodeJS
* **101**
* **Educational**
	* [A Roadmap for Node.js Security](https://nodesecroadmap.fyi/)	
	* [NodeGoat](https://github.com/OWASP/NodeGoat)
		* Being lightweight, fast, and scalable, Node.js is becoming a widely adopted platform for developing web applications. This project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
* **Articles/Blogposts/Writeups**	
	* [Reverse shell on a Node.js application](https://wiremask.eu/writeups/reverse-shell-on-a-nodejs-application/)
	* [Pen Testing Node.js: Staying N Sync Can Make the Server Go Bye Bye Bye - Tim Medin](https://pen-testing.sans.org/blog/2015/12/20/pen-testing-node-js-staying-n-sync-can-make-the-server-go-bye-bye-bye)
	* [Debugging Node.js with Google Chrome - Jacopo Daeli](https://medium.com/the-node-js-collection/debugging-node-js-with-google-chrome-4965b5f910f4)
* **Presentations/Talks/Videos**
	* [NodeJS: Remote Code Execution as a Service - Peabnuts123 – Kiwicon 2016](https://www.youtube.com/watch?v=Qvtfagwlfwg)
		* [SLIDES](http://archivedchaos.com/post/153372061089/kiwicon-2016-slides-upload)
* **Tools**
	* [faker.js](https://github.com/Marak/faker.js)
		* generate massive amounts of fake data in Node.js and the browser



-----------------
### <a name="paseto"></a> Platform Agnostic Security Token (PASETO)
* **101**
	* [PASETO.io](https://paseto.io)
	* [A Thorough Introduction to PASETO - Randall Degges](https://developer.okta.com/blog/2019/10/17/a-thorough-introduction-to-paseto)
* **Articles/Blogposts/Writeups**
	* [Paseto is a Secure Alternative to the JOSE Standards (JWT, etc.) - Scott Arciszewski](https://paragonie.com/blog/2018/03/paseto-platform-agnostic-security-tokens-is-secure-alternative-jose-standards-jwt-etc)




--------------
### <a name="php"></a>PHP
* **101**
* **Articles/Blogposts/Writeups**
	* [Pwning PHP mail() function For Fun And RCE | New Exploitation Techniques And Vectors](https://exploitbox.io/paper/Pwning-PHP-Mail-Function-For-Fun-And-RCE.html)
	* [The unexpected dangers of preg_replace](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace)
	* [Imagecreatefromgif-Bypass](https://github.com/JohnHoder/Imagecreatefromgif-Bypass)
		* A simple helper script to find byte sequences present in both of 2 given files. The main purpose of this is to find bytes that remain untouched after being processed with imagecreatefromgif() PHP function from GD-LIB. That is the place where a malicious PHP script can be inserted to achieve some nasty RCE.
	* [Is PHP vulnerable and under what conditions?](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
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
		* [Writing Exploits For Exotic Bug Classes: unserialize()](https://www.alertlogic.com/blog/writing-exploits-for-exotic-bug-classes-unserialize()/)
		* [Remote code execution via PHP [Unserialize] - notsosecure](https://www.notsosecure.com/remote-code-execution-via-php-unserialize/)
		* [PHP Generic Gadget Chains: Exploiting unserialize in unknown environments](https://www.ambionics.io/blog/php-generic-gadget-chains)
		* [PHPGGC: PHP Generic Gadget Chains](https://github.com/ambionics/phpggc)
			* PHPGGC is a library of unserialize() payloads along with a tool to generate them, from command line or programmatically. When encountering an unserialize on a website you don't have the code of, or simply when trying to build an exploit, this tool allows you to generate the payload without having to go through the tedious steps of finding gadgets and combining them. Currently, the tool supports: Doctrine, Guzzle, Laravel, Monolog, Slim, SwiftMailer.
		* [File Operation Induced Unserialization via the "phar://" Stream Wrapper - secarma labs](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf)
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
* **Bypassing Disabled Functions**
	* [Bypass of Disabled System Functions - Netsparker](https://www.netsparker.com/blog/web-security/bypass-disabled-system-functions/)
* **Type Juggling**
	* [Writing Exploits For Exotic Bug Classes: PHP Type Juggling](https://turbochaos.blogspot.com.au/2013/08/exploiting-exotic-bugs-php-type-juggling.html)
	* [PHP Magic Tricks: Type Juggling](https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf)
	* [PHP’s “Magic Hash” Vulnerability (Or Beware Of Type Juggling)](https://web.archive.org/web/20150530075600/http://blog.astrumfutura.com/2015/05/phps-magic-hash-vulnerability-or-beware-of-type-juggling)
	* [From hacked client to 0day discovery - infoteam](https://security.infoteam.ch/en/blog/posts/from-hacked-client-to-0day-discovery.html)
		* PHP equivalency check failure writeup
	* [(Super) Magic Hashes - myst404](https://offsec.almond.consulting/super-magic-hash.html)
* **Writeups**
	* [Php Codz Hacking](https://github.com/80vul/phpcodz)
		* Writeups of specific PHP vulns




----------------
### <a name="rest"></a>REST/SOAP/Web Services(WSDL)
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
	* [ Cracking and fixing REST services - Bill Sempf - Converge 2015](https://www.irongeek.com/i.php?page=videos/converge2015/track109-cracking-and-fixing-rest-services-bill-sempf)
		* REST, or Representational State Transfer, just refers to the protocol with which the whole Web works. No big. We are used to using REST with a browser, but there is more to it - we can write programs with REST. The problem is that writing properties and functions using the web's transfer protocol open them up to all of the security weaknesses of the web, and we know there are a few of those. Finding those bugs is just half of the battle - fixing them is a whole other story. You'll need the details, and you'll get them here.
* **Attacking**
	* [Exploiting CVE-2017-8759: SOAP WSDL Parser Code Injection](https://www.mdsec.co.uk/2017/09/exploiting-cve-2017-8759-soap-wsdl-parser-code-injection/)
	* [Cracking and Fixing REST APIs](http://www.sempf.net/post/Cracking-and-Fixing-REST-APIs)
	* [Cracking and fixing REST services](http://www.irongeek.com/i.php?page=videos/converge2015/track109-cracking-and-fixing-rest-services-bill-sempf)
* **Tools**
	* [WS-Attacker](https://github.com/RUB-NDS/WS-Attacker)
		* WS-Attacker is a modular framework for web services penetration testing. It is developed by the Chair of Network and Data Security, Ruhr University Bochum (http://nds.rub.de/ ) and the Hackmanit GmbH (http://hackmanit.de/).
	* [Damn Vulnerable Web Services dvws](https://github.com/snoopysecurity/dvws)
		* Damn Vulnerable Web Services is an insecure web application with multiple vulnerable web service components that can be used to learn real world web service vulnerabilities.
	* [WS-Attacks.org](http://www.ws-attacks.org/Welcome_to_WS-Attacks)
		* WS-Attacks.org is not a new web service standard by the OASIS Group or W3C; instead it presents the flaws of today's web service standards and implementations in regard to web service security! WS-Attacks.org aims at delivering the most comprehensive enumeration of all known web service attacks.
	* [Astra](https://github.com/flipkart-incubator/Astra)
		* REST API penetration testing is complex due to continuous changes in existing APIs and newly added APIs. Astra can be used by security engineers or developers as an integral part of their process, so they can detect and patch vulnerabilities early during development cycle. Astra can automatically detect and test login & logout (Authentication API), so it's easy for anyone to integrate this into CICD pipeline. Astra can take API collection as an input so this can also be used for testing apis in standalone mode.
* **Reference**
	* [Web Services Security Testing Cheat Sheet Introduction - OWASP](https://www.owasp.org/index.php/Web_Service_Security_Testing_Cheat_Sheet)
	* [REST Security Cheat Sheet](REST Security Cheat Sheet)
	* [REST Assessment Cheat Sheet](https://www.owasp.org/index.php/REST_Assessment_Cheat_Sheet)
	* [RESTful API Best Practices and Common Pitfalls - Spencer Schneidenbach](https://medium.com/@schneidenbach/restful-api-best-practices-and-common-pitfalls-7a83ba3763b5)




--------------------------------
### <a name="ruby"></a>Ruby/Ruby on Rails
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
### <a name="webasm"></a>Web Assembly
* **101**
	* [Web Assembly](http://webassembly.org/)
	* [A cartoon intro to WebAssembly Articles](https://hacks.mozilla.org/category/code-cartoons/a-cartoon-intro-to-webassembly/)
	* [Lin Clark: A Cartoon Intro to WebAssembly | JSConf EU 2017](https://www.youtube.com/watch?v=HktWin_LPf4&app=desktop)
	* [WebAssembly Design Documents](https://github.com/WebAssembly/design)
		* This repository contains documents describing the design and high-level overview of WebAssembly.
* **Articles/Papers/Talks/Writeups**
	* [WebAssembly security: potentials and pitfalls - John Bergbom](https://www.forcepoint.com/blog/x-labs/webassembly-potentials-and-pitfalls)
* **Tools**
	* [WebAssembly for .NET](https://github.com/RyanLamansky/dotnet-webassembly)
		* A library able to create, read, modify, write and execute WebAssembly (WASM) files from .NET-based applications. Execution does not use an interpreter. WASM instructions are mapped to their .NET equivalents and converted to native machine language by the .NET JIT compiler.
* **Reversing**
	* [Web-(Dis)Assembly - Christophe Alladoum - Shakacon X](https://github.com/sophos/WebAssembly/blob/master/Misc/Web-(Dis)Assembly.pdf)
		* `https://github.com/sophos/WebAssembly/blob/master/Misc/Web-(Dis)Assembly.pdf`
	* [Analyzing WebAssembly binaries: initial feel and behavioral analysis - John Bergbom](https://www.forcepoint.com/blog/x-labs/analyzing-webassembly-binaries-initial-feel-and-behavioral-analysis)
	* [Analyzing WebAssembly binaries - Wasm Reverse Engineering - John Bergbom](https://www.forcepoint.com/blog/x-labs/analyzing-webassembly-binaries)
	* [Manual reverse engineering of WebAssembly: static code analysis - John Bergbom](https://www.forcepoint.com/blog/security-labs/manual-reverse-engineering-webassembly-static-code-analysis)




--------------------
### <a name="ssltls"></a>Secure Sockets Layer / Transport Layer Security
* **101**
* **Articles/Blogposts/Writeups**
	* [Downgrade Attack on TLS 1.3 and Vulnerabilities in Major TLS Libraries - David Wong](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/february/downgrade-attack-on-tls-1.3-and-vulnerabilities-in-major-tls-libraries/)



----------------
### <a name="waf">Single Sign-On(SSO)</a>
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
### <a name="waf">Web Application Firewalls(WAFs)</a>
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
* **Talks & Presentations**
	* [HTTP Invisibility Cloak by Soroush Dalili - SteelCon2017](https://www.youtube.com/watch?reload=9&v=sHEv_EoQJwc)
		* This talk illustrates a number of techniques to smuggle and reshape HTTP requests using features such as HTTP Pipelining that are not normally used by testers. The strange behaviour of web servers with different technologies will be reviewed using HTTP versions 1.1, 1.0, and 0.9 before HTTP v2 becomes too popular! Some of these techniques might come in handy when dealing with a dumb WAF or load balancer that blocks your attacks.
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


-------------------
### <a name="webframeworks"></a> JS Frameworks
* **101**
* **Articles/Blogposts/Writeups**
	* [JSMVCOMFG - To sternly look at JavaScript MVC and Templating Frameworks - Mario Heiderich](https://www.youtube.com/watch?v=SLH_IgaQWjs)
		* [Slides](https://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks)
	* [JavaScript Template Attacks](https://github.com/IAIK/jstemplate)
* **Specific Frameworks**
	* **Angular**
		* [AngularJS Security Documentation](https://docs.angularjs.org/guide/security)
		* [Adapting AngularJS payloads to exploit real world applications - Gareth Heyes](https://portswigger.net/research/adapting-angularjs-payloads-to-exploit-real-world-applications)
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
	* **Flask**
		* See [SSI/Template Injection](#ssti)
		* [Injecting Flask - Ryan Reid](https://nvisium.com/blog/2015/12/07/injecting-flask/)
			* In this adventure we will discuss some of the security features available and potential issues within the [Flask micro-framework](http://flask.pocoo.org/docs/0.10/) with respect to Server-Side Template Injection, Cross-Site Scripting, and HTML attribute injection attacks, a subset of XSS. If you’ve never had the pleasure of working with Flask, you’re in for a treat. Flask is a lightweight python framework that provides a simple yet powerful and extensible structure (it is [Python](https://xkcd.com/353/) after all).
	* **mustache.js**
		* [mustache-security(2013)](https://code.google.com/archive/p/mustache-security/)
			* This place will host a collection of security tips and tricks for JavaScript MVC frameworks and templating libraries.
			* [Wikis](https://code.google.com/archive/p/mustache-security/wikis)
	* **ReactJS**
		* [Exploiting Script Injection Flaws in ReactJS Apps](https://medium.com/dailyjs/exploiting-script-injection-flaws-in-reactjs-883fb1fe36c1)
	* **Spring**
		* [How Spring Web MVC Really Works - Stackify.com](https://stackify.com/spring-mvc/)



----------------
### <a name="webproxy">Web Proxies</a>
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
### <a name="webserver">Web Servers</a>
* **Apache**
* **Jetty**
	* [Making Jetty Bleed - Stephen Haywood](https://www.appsecconsulting.com/blog/making-jetty-bleed)
	* [JetLeak Vulnerability: Remote Leakage Of Shared Buffers In Jetty Web Server [CVE-2015-2080] - Stephen Komal](https://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html)
* **NGINX**




















----------------
## <a name="tt">Tactics & Techniques</a>
* **Attacking**
	* [OWASP Web Application Security Testing Cheat Sheet](https://www.owasp.org/index.php/Web_Application_Security_Testing_Cheat_Sheet)
	* [Web Application testing approach and cheating to win Jim McMurry Lee Neely Chelle Clements - Derbycon7](https://www.youtube.com/watch?v=Z8ZAv_EN-9M) 
	* [Attacking Modern SaaS Companies](https://github.com/cxxr/talks/blob/master/2017/nolacon/Attacking%20Modern%20SaaS%20Companies%20%E2%80%93%20NolaCon.pdf)
		* [Presentation](https://www.youtube.com/watch?v=J0otoKRh1Vk&app=desktop)
* **Securing**
	* [Center for Internet Security Apache Server 2.4 Hardening Guide](https://benchmarks.cisecurity.org/tools2/apache/CIS_Apache_HTTP_Server_2.4_Benchmark_v1.1.0.pdf)
	* [Securing Web Application Technologies Checklist](http://www.securingthehuman.org/developer/swat)
	* [Wordpress Security Guide - WPBeginner](http://www.wpbeginner.com/wordpress-security/)
	* [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist/blob/master/README.md)
	* [OWASP Application Security Verification Standard Project(ASVS)](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
		* The OWASP Application Security Verification Standard (ASVS) Project provides a basis for testing web application technical security controls and also provides developers with a list of requirements for secure development. 
	* [Magical Code Injection Rainbow Framework](https://github.com/SpiderLabs/MCIR)
		* The Magical Code Injection Rainbow! MCIR is a framework for building configurable vulnerability testbeds. MCIR is also a collection of configurable vulnerability testbeds. Has testing lessons for xss/csrf/sql
* **Guides & Methodologies**
	* [OWASP Testing Checklist](https://www.owasp.org/index.php/Testing_Checklist)
	* [WebAppSec Testing Checklist](http://tuppad.com/blog/wp-content/uploads/2012/03/WebApp_Sec_Testing_Checklist.pdf)
	* [OWASP Testing Checklist(OTGv4)](https://github.com/tanprathan/OWASP-Testing-Checklist)
		* OWASP based Web Application Security Testing Checklist is an Excel based checklist which helps you to track the status of completed and pending test cases. This checklist is completely based on OWASP Testing Guide v 4. The OWASP Testing Guide includes a “best practice” penetration testing framework which users can implement in their own organizations and a “low level” penetration testing guide that describes techniques for testing most common web application security issues. Moreover, the checklist also contains OWASP Risk Assessment Calculator and Summary Findings template.
	* [LTR101: Web App Testing - Methods to The Madness - Andy Gill](https://blog.zsec.uk/ltr101-method-to-madness/)
	* [LTR101: Web Application Testing Methodologies - Andy Gill](https://blog.zsec.uk/ltr101-methodologies/)
* **Payloads**
	* [Seclists](https://github.com/danielmiessler/SecLists)
	* [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
	* [weapons4pentester](https://github.com/merttasci/weapons4pentester)
* **Tactics**
	* [Using HTTP Pipelining to hide requests - digi.ninja](https://digi.ninja/blog/pipelining.php)
* **General Reconnaissance Techniques**
	* [Insecure HTTP Header Removal](https://www.aspectsecurity.com/blog/insecure-http-header-removal)
	* [Backslash Powered Scanning: Hunting Unknown Vulnerability Classes](http://blog.portswigger.net/2016/11/backslash-powered-scanning-hunting.html)
		* Existing web scanners search for server-side injection vulnerabilities by throwing a canned list of technology-specific payloads at a target and looking for signatures - almost like an anti-virus. In this document, I'll share the conception and development of an alternative approach, capable of finding and confirming both known and unknown classes of injection vulnerabilities. Evolved from classic manual techniques, this approach reaps many of the benefits of manual testing including casual WAF evasion, a tiny network footprint, and flexibility in the face of input filtering.
* **Attack Surface Reconaissance**
	* **Articles/Blogposts/Writeups**
		* [Asset Enumeration: Expanding a Target's Attack Surface - Capt. Meelo](https://captmeelo.com/bugbounty/2019/09/02/asset-enumeration.html)
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
* **(Sub)Domain Reconnaissance**
	* **Articles/Blogposts/Writeups**
		* [A penetration tester’s guide to subdomain enumeration - Bharath](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)
		* [Subdomain Enumeration: 2019 Workflow - Patrik Hudak](https://0xpatrik.com/subdomain-enumeration-2019/)
	* **Domain Discovery**
		* [DRROBOT](https://github.com/sandialabs/dr_robot)
			* Dr.ROBOT is a tool for Domain Reconnaissance and Enumeration. By utilizing containers to reduce the overhead of dealing with dependencies, inconsistencies across operating systems, and different languages, Dr.ROBOT is built to be highly portable and configurable.
	* **Subdomain Discovery Tools**
		* [Sudomy](https://github.com/Screetsec/Sudomy)
			* Sudomy is a subdomain enumeration tool, created using a bash script, to analyze domains and collect subdomains in fast and comprehensive way.
		* [domains-from-csp](https://github.com/0xbharath/domains-from-csp)
			* A Python script to parse domain names from CSP header
		* [pdlist. A passive subdomain finder](https://github.com/gnebbia/pdlist)
			* pdlist is a passive subdomain finder written in python3. This tool can be used effectively to collect information about a domain without ever sending a single packet to any of its hosts. Given a domain like "example.com" it will find all the hosts which have a `hostname <something>.example.com` or URLs strictly related to `example.com`.
* **Subdomain Takeover**
	* [Hostile Subdomain Takeover using Heroku/Github/Desk + more - Detectify](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)
	* [5 Subdomain Takeover #ProTips - Patrik Hudak](https://securitytrails.com/blog/subdomain-takeover-tips)
* **Virtual Hosts**
	* **101**
		* [Virtual Hosting - Wikipedia](https://en.wikipedia.org/wiki/Virtual_hosting)
	* **Tools**
		* [virtual-host-discovery](https://github.com/jobertabma/virtual-host-discovery)
			* This is a basic HTTP scanner that'll enumerate virtual hosts on a given IP address. During recon, this might help expand the target by detecting old or deprecated code. It may also reveal hidden hosts that are statically mapped in the developer's /etc/hosts file.
		* [blacksheepwall](https://github.com/tomsteele/blacksheepwall)
			* blacksheepwall is a hostname reconnaissance tool
		* [VHostScan](https://github.com/codingo/VHostScan)
			* A virtual host scanner that performs reverse lookups, can be used with pivot tools, detect catch-all scenarios, work around wildcards, aliases and dynamic default pages.
* **Visual Reconnaissance**
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
* **Recon**
	* [HTTPLeaks](https://github.com/cure53/HTTPLeaks)
		* HTTPLeaks - All possible ways, a website can leak HTTP requests
	* **General**
		* [hackability](https://github.com/PortSwigger/hackability)
			* Rendering Engine Hackability Probe performs a variety of tests to discover what the unknown rendering engine supports. To use it simply extract it to your web server and visit the url in the rendering engine you want to test. The more successful probes you get the more likely the target engine is vulnerable to attack.
	* **Content/Folder Discovery**
		* [Tachyon](https://github.com/delvelabs/tachyon)
			* Tachyon is a Fast Multi-Threaded Web Discovery Tool
		* [dirsearch](https://github.com/maurosoria/dirsearch)
			* dirsearch is a simple command line tool designed to brute force directories and files in websites.
		* [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
			* LinkFinder is a python script written to discover endpoints and their parameters in JavaScript files. This way penetration testers and bug hunters are able to gather new, hidden endpoints on the websites they are testing. Resulting in new testing ground, possibility containing new vulnerabilities. It does so by using [jsbeautifier](https://github.com/beautify-web/js-beautify) for python in combination with a fairly large regular expression.
	* **JS-based scanning**
		* [lan-js](https://github.com/jvennix-r7/lan-js)
			* Probe LAN devices from a web browser.
		* [sonar.js](https://thehackerblog.com/sonar-a-framework-for-scanning-and-exploiting-internal-hosts-with-a-webpage/)
			* A Framework for Scanning and Exploiting Internal Hosts With a Webpage
	* **Web Page**
		* [HTCAP](https://github.com/segment-srl/htcap)
			* htcap is a web application scanner able to crawl single page application (SPA) in a recursive manner by intercepting ajax calls and DOM changes
		* [gethead](https://github.com/httphacker/gethead)
			* HTTP Header Analysis Vulnerability Tool 
	* **Web Server**	
		* [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
		* [httprecon - Advanced Web Server Fingerprinting](https://github.com/scipag/httprecon-win32)
			* The httprecon project is doing some research in the field of web server fingerprinting, also known as http fingerprinting. The goal is the highly accurate identification of given httpd implementations. This is very important within professional vulnerability analysis. Besides the discussion of different approaches and the documentation of gathered results also an implementation for automated analysis is provided. This software shall improve the easyness and efficiency of this kind of enumeration. Traditional approaches as like banner-grabbing, status code enumeration and header ordering analysis are used. However, many other analysis techniques were introduced to increase the possibilities of accurate web server fingerprinting. Some of them were already discussed in the book Die Kunst des Penetration Testing (Chapter 9.3, HTTP-Fingerprinting, pp. 530-550).
* **HTTP Enumeration**
	* **Articles/Blogposts/Writeups**
	* **Tools**
		* [Arjun](https://github.com/s0md3v/Arjun)
			* HTTP parameter discovery suite.
		* [Psi-Probe](https://github.com/psi-probe/psi-probe)
			* Advanced manager and monitor for Apache Tomcat, forked from Lambda Probe
		* [HTTPie - curl for humans](https://gith*ub.com/jakubroztocil/httpie)
			* HTTPie (pronounced aych-tee-tee-pie) is a command line HTTP client. Its goal is to make CLI interaction with web services as human-friendly as possible. It provides a simple http command that allows for sending arbitrary HTTP requests using a simple and natural syntax, and displays colorized output. HTTPie can be used for testing, debugging, and generally interacting with HTTP servers.
* **Enpdoint Discovery**
	* **Articles/Blogposts/Writeups**
	* **Tools**
		* [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
			* A python script that finds endpoints in JavaScript files
		* [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
			* A python script that finds endpoints in JavaScript files
		* [JSParser](https://github.com/nahamsec/JSParser)
			* A python 2.7 script using Tornado and JSBeautifier to parse relative URLs from JavaScript files. Useful for easily discovering AJAX requests when performing security research or bug bounty hunting.
* **Forced-Browsing**
	* **Articles/Blogposts/Writeups**
		* [Turbo Intruder: Embracing the billion-request attack - James Kettle](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
	* **Tools**
		* [Tachyon](https://github.com/delvelabs/tachyon)
		* [Dirsearch](https://github.com/maurosoria/dirsearch)
		* [OpenDoor](https://github.com/stanislav-web/OpenDoor)
			* OpenDoor OWASP is console multifunctional web sites scanner. This application find all possible ways to login, index of/ directories, web shells, restricted access points, subdomains, hidden data and large backups. The scanning is performed by the built-in dictionary and external dictionaries as well. Anonymity and speed are provided by means of using proxy servers.
		* [ffuf - Fuzz Faster U Fool](https://github.com/ffuf/ffuf)
			* A fast web fuzzer written in Go.
		* [rustbuster](https://github.com/phra/rustbuster)
			* A Comprehensive Web Fuzzer and Content Discovery Tool
* **Site/Technology Identification**
	* [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
		* WhatWeb identifies websites. Its goal is to answer the question, "What is that Website?". WhatWeb recognises web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1500 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.
	* [CMSExplorer](https://code.google.com/p/cms-explorer/)
		* CMS Explorer is designed to reveal the the specific modules, plugins, components and themes that various CMS driven web sites are running. Additionally, CMS Explorer can be used to aid in security testing. While it performs no direct security checks, the "explore" option can be used to reveal hidden/library files which are not typically accessed by web clients but are nonetheless accessible. This is done by retrieving the module's current source tree and then requesting those file names from the target system. These requests can be sent through a distinct proxy to help "bootstrap" security testing tools like Burp, Paros, Webinspect, etc. 
	* [BlindElephant Web Application Fingerprinter](http://blindelephant.sourceforge.net/)
		* The BlindElephant Web Application Fingerprinter attempts to discover the version of a (known) web application by comparing static files at known locations against precomputed hashes for versions of those files in all all available releases. The technique is fast, low-bandwidth, non-invasive, generic, and highly automatable. 
	* [Fingerprinter](https://github.com/erwanlr/Fingerprinter)
		*  CMS/LMS/Library etc Versions Fingerprinter. This script's goal is to try to find the version of the remote application/third party script etc by using a fingerprinting approach.
	* [Web Filter External Enumeration Tool (WebFEET)](https://github.com/nccgroup/WebFEET)
		* WebFEET is a web application for the drive-by enumeration of web security proxies and policies. See associated [white paper](https://www.nccgroup.com/media/481438/whitepaper-ben-web-filt.pdf) (Drive-by enumeration of web filtering solutions)
	* [Fingerprinter](https://github.com/erwanlr/Fingerprinter)
		* This script goal is to try to find the version of the remote application/third party script etc by using a fingerprinting approach.
* **Vulnerability Scanner**
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
* [autochrome](https://github.com/nccgroup/autochrome)
	* This tool downloads, installs, and configures a shiny new copy of Chromium.
	* [Article](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/march/autochrome/)














































----------------------------------
## <a name="difatk"></a>Different Types of Attacks


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
#### <a name="ci"></a> Attacking Continous Integration Systems
* [cider - Continuous Integration and Deployment Exploiter](https://github.com/spaceB0x/cider)
	* CIDER is a framework written in node js that aims to harness the functions necessary for exploiting Continuous Integration (CI) systems and their related infrastructure and build chain (eg. Travis-CI, Drone, Circle-CI). Most of the exploits in CIDER exploit CI build systems through open GitHub repositories via malicious Pull Requests. It is built modularly to encourage contributions, so more exploits, attack surfaces, and build chain services will be integrated in the future.
* [Rotten Apple](https://github.com/claudijd/rotten_apple)
	* A tool for testing continuous integration (CI) or continuous delivery (CD) system security
* [Exploiting Continuous Integration (CI) and Automated Build Systems - spaceb0x](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-spaceB0x-Exploiting-Continuous-Integration.pdf)





------------------
#### <a name="csv"></a> CSV Injection
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




----------------
#### <a name="click"></a>Clickjacking
* **101**
* **Articles/Blogposts/Writeups**
	* [Clickjacking DOM XSS on Google.org - Thomas Orlita](https://appio.dev/vulns/clickjacking-xss-on-google-org/)
	* [Busting Frame Busting: A Study of Clickjacking Vulnerabilities on Popular Sites - Gustav Rydstedt, Elie Bursztein, Dan Boneh, Collin Jackson](https://seclab.stanford.edu/websec/framebusting/framebust.pdf)
* **Papers**
* **Presentations/Talks/Videos**
* **Tools**



------------------
#### <a name="cpr"></a> Cross Protocol Scripting/Request Attack
* **101**
* **Articles/Blogposts/Writeups**
	* [How to steal any developer's local database - bouk.co](https://web.archive.org/web/20170119060232/https://bouk.co/blog/hacking-developers/)
* **Papers**
	* [HTML Form Protocol Attack - Jochen Topf(2001)](https://web.archive.org/web/20170810193321/https://www.jochentopf.com/hfpa/hfpa.pdf)
		* This paper describes how some HTML browsers can be tricked through the use of HTML forms into sending more or less arbitrary data to any TCP port. This can be used to send commands to servers using ASCII based protocols like SMTP, NNTP, POP3, IMAP, IRC, and others. By sending HTML email to unsuspecting users or using a trojan HTML page, an attacker might be able to send mail or post Usenet News through servers normally not accessible to him. In special cases an attacker might be able to do other harm, e.g. deleting mail from a POP3 mailbox.
* **Presentations/Talks/Videos**
* **Tools**
	* [Extract data](https://github.com/bouk/extractdata)
		* Extract data is a demo combining a cross-protocol request attack with DNS rebinding




------------------
#### <a name="xshm"></a> Cross Site Content Hijacking
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




------------------
#### <a name="xshm"></a> Cross Site History Manipulation
* **101**
* **Articles/Blogposts/Writeups**
* **Papers**
* **Presentations/Talks/Videos**
* **Tools**




----------------
#### <a name="csrf"></a>Cross Site Request Forgery (CSRF)
* **101**
	* [Cross Site Request Forgery - OWASP](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29)
* **Articles/Blogposts/Writeups**
	* [Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)\_Prevention_Cheat_Sheet)
	* [The OWASP Top Ten and ESAPI – Part 5 – Cross Site Request Forgery (CSRF)](http://www.jtmelton.com/2010/05/16/the-owasp-top-ten-and-esapi-part-6-cross-site-request-forgery-csrf/)
	* [Testing for CSRF (OTG-SESS-005) - OWASP](https://www.owasp.org/index.php/Testing_for_CSRF_(OTG-SESS-005)\)
	* [A most Neglected Fact About CSRF - pdf](http://yehg.net/lab/pr0js/view.php/A_Most-Neglected_Fact_About_CSRF.pdf)
	* [Bypassing CSRF Protection - Vickie Li](https://medium.com/swlh/bypassing-csrf-protection-c9b217175ee)
* **Papers**
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
#### <a name="cssi"></a>Cascading StyleSheets Injection
* **101**
	* [CSS Injection Primitives - x-c3ll](https://x-c3ll.github.io//posts/CSS-Injection-Primitives/)
* **Articles/Blogposts/Writeups**
* **Presentations/Talks/Videos**



----------------
#### <a name="cswsh"></a>Cross Site WebSocket Hijacking
* **101**
	* [Cross-Site WebSocket Hijacking (CSWSH)](https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html)
* **Articles/Blogposts/Presentations/Talks/Videos**
	* [How Cross-Site WebSocket Hijacking could lead to full Session Compromise](https://www.notsosecure.com/how-cross-site-websocket-hijacking-could-lead-to-full-session-compromise/)
* **Tools**





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
* [Exploiting Out Of Band XXE using internal network and php wrappers - Mahmoud Gamal](https://mahmoudsec.blogspot.com/2019/08/exploiting-out-of-band-xxe-using.html)
* [Playing with Content-Type – XXE on JSON Endpoints - Antti Rantasaari](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
* [Exploiting CVE-2016-4264 With OXML_XXE](https://www.silentrobots.com/blog/2016/10/02/exploiting-cve-2016-4264-with-oxml-xxe/)
* [XXE: How to become a Jedi - Yaroslav Babin(Zeronights 2017)](https://www.slideshare.net/ssuserf09cba/xxe-how-to-become-a-jedi)
* [Exploiting XXE Vulnerabilities In File Parsing Functionality - Willis Vandevanter - BHUSA 2015](https://www.youtube.com/watch?v=LZUlw8hHp44)
	* In this 25-minute briefing, we will discuss techniques for exploiting XXE vulnerabilities in File Parsing/Upload functionality. Specifically, XML Entity Attacks are well known, but their exploitation inside XML supported file formats such as docx, xlsx, pptx, and others are not. Discussing the technically relevant points step by step, we will use real world examples from products and recent bug bounties. Finally, in our experience, creating 'XXE backdoored' files can be a very slow process. We will introduce our battle tested tool for infecting the file formats discussed.


----------------
#### <a name="emc">Embedded Malicious Code</a>
* **101**
* **Articles/Blogposts/Writeups**
* **Papers**
* **Presentations/Talks/Videos**
* **Tools**

----------------
#### <a name="eoa">Exploitation of Authentication </a>
* **101**
* **Articles/Blogposts/Writeups**
* **Papers**
* **Presentations/Talks/Videos**
* **Tools**






----------------
#### <a name="idor">Insecure Direct Object Reference</a>
* [Airbnb – Web to App Phone Notification IDOR to view Everyone’s Airbnb Messages - Brett Buerhaus](https://buer.haus/2017/03/31/airbnb-web-to-app-phone-notification-idor-to-view-everyones-airbnb-messages/)


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


------------
#### <a name="file"></a>File Upload Testing
* **101**
* **Articles/Blogposts/Writeups**
	* [Unrestricted File Upload Testing](https://www.aptive.co.uk/blog/unrestricted-file-upload-testing/)
	* [BookFresh Tricky File Upload Bypass to RCE - secgeek.net](https://secgeek.net/bookfresh-vulnerability/)
	* [15 Technique to Exploit File Upload Pages - Ebrahim Hegazy(HackIT17)](https://es.slideshare.net/HackIT-ukraine/15-technique-to-exploit-file-upload-pages-ebrahim-hegazy)
	* [File Upload and PHP on IIS: `>=?` and `<=*` and `"=.` - Soroush Dalili](https://soroush.secproject.com/blog/2014/07/file-upload-and-php-on-iis-wildcards/)
* **Papers**
* **Presentations/Talks/Videos**
* **Tools**
	* [fuxploider](https://github.com/almandin/fuxploider)
		* File upload vulnerability scanner and exploitation tool.




-------------------
#### <a name="httprs">HTTP Request Smuggling</a>
* **101**
	* [HTTP request smuggling - Portswigger](https://portswigger.net/web-security/request-smuggling)
	* [HTTP Desync Attacks: Request Smuggling Reborn - James Kettle](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
	* [‘HTTP Request Smuggling’ - Securiteam](https://securiteam.com/securityreviews/5gp0220g0u/)
* **Articles/Blogposts/Writeups**
* **Papers**
	* [HTTP Request Smuggling - Chaim Linhart, Amit Klein, Ronen Heled, Steve Orrin](https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf)
* **Presentations/Talks/Videos**
* **Tools**





-------------------
#### <a name="ibe">* **Image-based Exploitation AKA Exploiting Polyglot features of File standards**
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
	* [An XSS on Facebook via PNGs & Wonky Content Types - fin1te](https://whitton.io/articles/xss-on-facebook-via-png-content-types/)
* **Tools**
	* [xss2png](https://github.com/vavkamil/xss2png)
		* A simple tool to generate PNG images with XSS payloads stored in PNG IDAT chunks
	* [pixload](https://github.com/chinarulezzz/pixload)
		* Set of tools for creating/injecting payload into images.
	* [PNG-IDAT-Payload-Generator](https://github.com/huntergregal/PNG-IDAT-Payload-Generator)
		* Generate a PNG with a payload embedded in the IDAT chunk (Based off of previous concepts and code -- credit in README)
	* [Imagecreatefromgif-Bypass](https://github.com/JohnHoder/Imagecreatefromgif-Bypass)






-------------------
#### <a name="ija">Injection Based Attacks</a>
* **101**
* **Articles/Blogposts/Writeups**
	* [Exploiting ShellShock getting a reverse shell](http://www.fantaghost.com/exploiting-shellshock-getting-reverse-shell)
	* [Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)
	* [Exploiting Python Code Injection in Web Applications - sethsec](https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html)
* **Papers**
* **Presentations/Talks/Videos**
	* [Popular Approaches to Preventing Code Injection Attacks are Dangerously Wrong - AppSecUSA 2017](https://www.youtube.com/watch?v=GjK0bB4K2zA&app=desktop)
	* [Remote Code Execution in Firefox beyond memory corruptions(2019) - Frederik Braun](https://frederik-braun.com/firefox-ui-xss-leading-to-rce.html)
		* Browsers are complicated enough to have attack surface beyond memory safety issues. This talk will look into injection flaws in the user interface of Mozilla Firefox, which is implemented in JS, HTML, and an XML-dialect called XUL. With an Cross-Site Scripting (XSS) in the user interface attackers can execute arbitrary code in the context of the main browser application process. This allows for cross-platform exploits of high reliability. The talk discusses past vulnerabilities and will also suggest mitigations that benefit Single Page Applications and other platforms that may suffer from DOM-based XSS, like Electron.
* **Tools**
* See also: JNDI, JSON, SQLi, XSS



-------------------
#### <a name="osci"></a> OS Command Injection
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
### <a name="serialization">(De-)Serialization Attacks</a>
* **General**
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
		* [The perils of Java deserialization](https://community.hpe.com/t5/Security-Research/The-perils-of-Java-deserialization/ba-p/6838995)
		* [Java Deserialization Security FAQ](https://christian-schneider.net/JavaDeserializationSecurityFAQ.html)
		* [The Perils of Java Deserialization](http://community.hpe.com/hpeb/attachments/hpeb/off-by-on-software-security-blog/722/1/HPE-SR%20whitepaper%20java%20deserialization%20RSA2016.pdf)
		* [Detecting deserialization bugs with DNS exfiltration](http://gosecure.net/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltration/)
		* [Reliable discovery and Exploitation of Java Deserialization vulns](https://techblog.mediaservice.net/2017/05/reliable-discovery-and-exploitation-of-java-deserialization-vulnerabilities/)
	* **General**
		* [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
			* A cheat sheet for pentesters about Java Native Binary Deserialization vulnerabilities
	* **Presentations/Talks/Videos**
		* [Pwning Your Java Messaging With De- serialization Vulnerabilities](https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities-wp.pdf)
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
	* **Exploits**
		* [SerialKiller: Bypass Gadget Collection](https://github.com/pwntester/SerialKillerBypassGadgetCollection)
			* Collection of Bypass Gadgets that can be used in JVM Deserialization Gadget chains to bypass "Look-Ahead ObjectInputStreams" desfensive deserialization.
		* [Serianalyzer](https://github.com/mbechler/serianalyzer)
			* A static byte code analyzer for Java deserialization gadget research
		* [Java Deserialization Exploits](https://github.com/CoalfireLabs/java_deserialization_exploits)
			* A collection of Java Deserialization Exploits
		* [Java Deserialization Exploits](https://github.com/Coalfire-Research/java-deserialization-exploits)
			* A collection of curated Java Deserialization Exploits
* **PHP**
	* **Articles/Blogposts/Writeups**
		* [Diving into unserialize() - Vickie Li](https://medium.com/swlh/diving-into-unserialize-3586c1ec97e)
		* [Diving into unserialize(): POP Chains](https://medium.com/@vickieli/diving-into-unserialize-pop-chains-35bc1141b69a)
		* [Diving into unserialize(): Magic Methods - Vickie Li](https://medium.com/swlh/diving-into-unserialize-magic-methods-386d41c1b16a)
* **Python**
	* **Articles/Blogposts/Writeups**
		* [Exploiting Python Deserialization Vulnerabilities](https://crowdshield.com/blog.php?name=exploiting-python-deserialization-vulnerabilities)
		* [Exploiting misuse of Python's "pickle"](https://blog.nelhage.com/2011/03/exploiting-pickle/)
		* [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability. - breenmachine](https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/)
		* [Python web frameworks and pickles - Nicolas Oberli](https://www.balda.ch/posts/2013/Jun/23/python-web-frameworks-pickle/)




-------------------
### <a name="hsmug">HTML Smuggling</a>
* **101**
	* [HTML Smuggling Explained - Stan Hegt](https://outflank.nl/blog/2018/08/14/html-smuggling-explained/)
* **Articles/Blogposts/Writeups**
	* [File Smuggling with HTML and JavaScript - ired.team](https://ired.team/offensive-security/defense-evasion/file-smuggling-with-html-and-javascript)
	* [Strange Bits: HTML Smuggling and GitHub Hosted Malware - gdatasoftware.com](https://www.gdatasoftware.com/blog/2019/05/31695-strange-bits-smuggling-malware-github)
	* [Smuggling HTA files in Internet Explorer/Edge - Richard Warren](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/august/smuggling-hta-files-in-internet-exploreredge/)
* **Tools**
	* [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
	* [Demiguise](https://github.com/nccgroup/demiguise)




-------------------
### <a name="lrfi">LFI & RFI</a>
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
* **Cheat Sheets/Reference Lists**
	* [HighOn.coffee LFI Cheat](https://highon.coffee/blog/lfi-cheat-sheet/)
	* [Local File Inclusion (LFI) [Definitive Guide] - aptive.co.uk](https://www.aptive.co.uk/blog/local-file-inclusion-lfi-testing/)
* **Testing**
	* [OWASP LFI](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
	* [LFI Local File Inclusion Techniques (paper)](http://www.ush.it/2008/08/18/lfi2rce-local-file-inclusion-to-remote-code-execution-advanced-exploitation-proc-shortcuts/)
		* This paper exposes the ability from the attacker standpoint to use /proc in order to exploit LFI (Local File Inclusion) vulnerabilities. While using /proc for such aim is well known this one is a specific technique that was not been previously published as far as we know. A tool to automatically exploit LFI using the shown approach is released accordingly. 
	* [Update: a third (known) technique has been dissected here](http://www_ush_it/2008/07/09/local-file-inclusion-lfi-of-session-files-to-root-escalation/ ) 
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



-------------------
### <a name="sqli"></a>(No)SQL Injection
* **101**
	* [NT Web Technology Vulnerabilities - rain.forest.puppy](http://phrack.org/issues/54/8.html)
* **General**
	* [SQL Injection wiki](http://www.sqlinjectionwiki.com/)
* **Reference**
	* [SQL Injection Knowledge Base](http://websec.ca/kb/sql_injection#MySQL_Testing_Injection)
	* [SQL Injection Cheat Sheet](http://ferruh.mavituna.com/sql-injection-cheatsheet-oku/)
	* [SQL Injection Cheat Sheet - NetSparker](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
* **Articles/Blogposts/Writeups**
	* [Abusing NoSQL Databases - Ming Chow](https://www.defcon.org/images/defcon-21/dc-21-presentations/Chow/DEFCON-21-Chow-Abusing-NoSQL-Databases.pdf)
	* [No SQL, No Injection? - Examining NoSQL Security](https://arxiv.org/pdf/1506.04082.pdf)
	* [NoSQL Injection in Modern Web Applications - petecorey.com](http://www.petecorey.com/blog/2016/03/21/nosql-injection-in-modern-web-applications/)
	* [Finding SQL injections fast with white-box analysis — a recent bug example - Frycos](https://medium.com/@frycos/finding-sql-injections-fast-with-white-box-analysis-a-recent-bug-example-ca449bce6c76)
	* [Blind (time-based) SQLi - Bug Bounty - jspin.re](https://jspin.re/fileupload-blind-sqli/)
	* [SELECT code_execution FROM * USING SQLite; Gaining code execution using a malicious SQLite database - Omer Gull](https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/)
	* [Beyond SQLi: Obfuscate and Bypass - CWH Underground](https://www.exploit-db.com/papers/17934/)
* **Tools**
	* [sqlmap](https://github.com/sqlmapproject/sqlmap)
	* [jSQL Injection](https://github.com/ron190/jsql-injection)
		* jSQL Injection is a Java application for automatic SQL database injection.
	* [mongoaudit](https://github.com/stampery/mongoaudit)
	* [Laduanum](http://laudanum.sourceforge.net/)
		* “Laudanum is a collection of injectable files, designed to be used in a pentest when SQL injection flaws are found and are in multiple languages for different environments.They provide functionality such as shell, DNS query, LDAP retrieval and others.”
	* [GraFScaN](https://github.com/grafscan/GraFScaN)
* **Training**
	* [SQLi Lab lessons](https://github.com/Audi-1/sqli-labs)
		* SQLI-LABS is a platform to learn SQLI
* **Writeups**
	* [Use google bots to perform SQL injections on websites](http://blog.sucuri.net/2013/11/google-bots-doing-sql-injection-attacks.html)
	* [Performing sqlmap POST request injection](https://hackertarget.com/sqlmap-post-request-injection/)
* **DB2**
	* [DB2 SQL injection cheat sheet](https://securityetalii.es/2012/05/20/db2-sql-injection-cheat-sheet/)
* **MongoDB**
	* [Intro to Hacking Mongo DB - SecuritySynapse](https://securitysynapse.blogspot.com/2015/07/intro-to-hacking-mongo-db.html)
	* [Attacking MongoDB - ZeroNights2012](http://blog.ptsecurity.com/2012/11/attacking-mongodb.html)
	* [MongoDB Injection - How To Hack MongoDB](http://www.technopy.com/mongodb-injection-how-to-hack-mongodb-html/)
	* [Hacking NodeJS and MongoDB - websecurify](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)
	* [mongoaudit](https://github.com/stampery/mongoaudit)
		* mongoaudit is a CLI tool for auditing MongoDB servers, detecting poor security settings and performing automated penetration testing.
* **MS-SQL**
	* [Pen test and hack microsoft sql server (mssql)](http://travisaltman.com/pen-test-and-hack-microsoft-sql-server-mssql/)
* **MySQL**
	* [MySQL UDF Exploitation](https://osandamalith.com/2018/02/11/mysql-udf-exploitation/)
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
* ["How I hacked PacketStorm" - rain forest puppy](http://www.ouah.org/rfp.txt)
* [Albatar](https://github.com/lanjelot/albatar)
	* Albatar is a SQLi exploitation framework in Python


-------------------
### <a name="pta">Path Traversal Attacks</a>
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
### <a name="rfd"></a>Prototype Pollution Attack
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
### <a name="rfd"></a>Reflected File Download
* **101**
* **Articles/Blogposts/Writeups**
* **Tools**
* **Talks/Presentations/Videos**
	* [Reflected File Download - A New Web Attack Vector - BHEU 2014](https://www.youtube.com/watch?v=dl1BJUNk8V4)
		* Skip to 19:24 for technical content
	* [Paper](https://drive.google.com/file/d/0B0KLoHg_gR_XQnV4RVhlNl96MHM/view)



----------------
### <a name="rpo"></a>Relative Path Overwrite
* **101**
	* [Relative Path Overwrite Explanation/Writeup](http://www.thespanner.co.uk/2014/03/21/rpo/)
		* RPO (Relative Path Overwrite) is a technique to take advantage of relative URLs by overwriting their target file. To understand the technique we must first look into the differences between relative and absolute URLs. An absolute URL is basically the full URL for a destination address including the protocol and domain name whereas a relative URL doesn’t specify a domain or protocol and uses the existing destination to determine the protocol and domain.
* **Articles/Papers/Talks/Writeups**
	* [A few RPO exploitation techniques - Takeshi Terada](https://www.mbsd.jp/Whitepaper/rpo.pdf)
	* [Non-Root-Relative Path Overwrite (RPO) in IIS and .Net applications - soroush.techproject](https://soroush.secproject.com/blog/tag/non-root-relative-path-overwrite/)
* **General**
* **Tools**
* **Miscellaneous**


-------------
### <a name="ssrf"></a>Server Side Request Forgery (SSRF)
* **101**
	* [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
	* [What is Server Side Request Forgery (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)
	* [What is the Server Side Request Forgery Vulnerability & How to Prevent It? - netsparker](https://www.netsparker.com/blog/web-security/server-side-request-forgery-vulnerability-ssrf/)
	* [Vulnerable by Design: Understanding Server-Side Request Forgery - BishopFox](https://www.bishopfox.com/blog/2015/04/vulnerable-by-design-understanding-server-side-request-forgery/)
* **General**
	* [AllThingsSSRF](https://github.com/jdonsec/AllThingsSSRF)
		* This is a collection of writeups, cheatsheets, videos, related to SSRF in one single location
	* [A New Era of SSRF  - Exploiting URL Parser in  Trending Programming Languages](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
	* [Cracking the Lens: Targeting HTTP's Hidden Attack Surface](https://portswigger.net/knowledgebase/papers/CrackingTheLens-whitepaper.pdf)
* **Presentations, Talks, Videos**
	* [Server-Side Browsing Considered Harmful - Nicolas Gregoire(AppSec EU15)](https://www.youtube.com/watch?v=8t5-A4ASTIU)
		* [Slides](http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf)
* **Writeups**
	* [SSRF VS BUSINESS-CRITICAL APPLICATIONS PART 1: XXE TUNNELING IN SAP NET WEAVER - erpscan](https://erpscan.com/wp-content/uploads/publications/SSRF-vs-Businness-critical-applications-final-edit.pdf)
	* [A New Era of SSRF  - Exploiting URL Parser in  Trending Programming Languages! - Orange Tsai - BH USA 17](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
	* [curl Based SSRF Exploits Against Redis](https://maxchadwick.xyz/blog/ssrf-exploits-against-redis)
	* [Pivoting from blind SSRF to RCE with HashiCorp Consul](http://www.kernelpicnic.net/2017/05/29/Pivoting-from-blind-SSRF-to-RCE-with-Hashicorp-Consul.html)
	* [ How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)
	* [Airbnb – Chaining Third-Party Open Redirect into Server-Side Request Forgery (SSRF) via LivePerson Chat - Brett Buerhaus](https://buer.haus/2017/03/09/airbnb-chaining-third-party-open-redirect-into-server-side-request-forgery-ssrf-via-liveperson-chat/)
* **Testing**
	* [SSRF bible. Cheatsheet](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#heading=h.t4tsk5ixehdd)	
	* [SSRF (Server Side Request Forgery) testing resources](https://github.com/cujanovic/SSRF-Testing/)	
	* [How To: Server-Side Request Forgery (SSRF)](https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF)
	* [Port scanning with Server Side Request Forgery (SSRF) - acunetix](https://www.acunetix.com/blog/articles/ssrf-vulnerability-used-to-scan-the-web-servers-network/)
	* [SVG SSRF Cheatsheet](https://github.com/allanlw/svg-cheatsheet)
* **Tools**




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
	* [hackable - JasonHinds](https://github.com/JasonHinds13/hackable)
		* A python flask app that is purposfully vulnerable to SQL injection and XSS attacks
* **Writeups**
	* [Exploring SSTI in Flask/Jinja2](https://nvisium.com/blog/2016/03/09/exploring-ssti-in-flask-jinja2/)
	* [Exploring SSTI in Flask/Jinja2, Part II](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
	* [Ruby ERB Template Injection](https://www.trustedsec.com/2017/09/rubyerb-template-injection/)
	* [Remote Code Execution via Server Side Template Injection at OFBiz 13.07.03 (CVE-2016-4462)](https://insinuator.net/2016/07/dilligent-bug/)
	* [Injecting Flask - Nvisium](https://nvisium.com/blog/2015/12/07/injecting-flask/)
	* [Spring Boot RCE](deadpool.sh/2017/RCE-Springs/)
	* [Fuzzing `{{7*7}} Till {{P1}}` - err0rr](http://verneet.com/fuzzing-77-till-p1/)
* **Tools**
	* [tplmap](https://github.com/epinna/tplmap)
		* Code and Server-Side Template Injection Detection and Exploitation Tool
	* [Templates Injections - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections)
* [Exploiting Custom Template Engines - Dalton Campbell](https://depthsecurity.com/blog/exploiting-custom-template-engines)

-------------------
### <a name="typosquatting"></a> Typosquatting
* [Typosquatting programming language package managers](http://incolumitas.com/2016/06/08/typosquatting-package-managers/)


------------------
### <a name="shells">Web Shells</a>
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




-------------------
### <a name="xss">XSS</a>
* **101**
	* [Types of Cross-Site Scripting - OWASP](https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting)
	* [Postcards from a Post-XSS World - Michael Zalewski](http://lcamtuf.coredump.cx/postxss/#dangling-markup-injection)
		* This page is a rough collection of notes on some of the fundamental alternatives to direct script injection that would be available to attackers following the universal deployment of CSP or other security mechanisms designed to prevent the execution of unauthorized scripts. I hope to demonstrate that in many cases, the capabilities offered by these alternative methods are highly compatible with the goals of contemporary XSS attacks.
	* ["Gimme a bit!" - Exploring Attacks in the "Post-XSS" World - Takashi Yoneuchi]
* **Bypass Techniques/Writeups**
	* [XSS bypass strtoupper & htmlspecialchars](https://security.stackexchange.com/questions/145716/xss-bypass-strtoupper-htmlspecialchars)
	* [Is htmlspecialchars enough to prevent an SQL injection on a variable enclosed in single quotes? - StackOverflow](https://stackoverflow.com/questions/22116934/is-htmlspecialchars-enough-to-prevent-an-sql-injection-on-a-variable-enclosed-in)
	* [XSS Web Filter Bypass list - rvrsh3ll](https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec#file-xxsfilterbypass-lst-L1)
	* [XSS Filter Bypass List](https://gist.github.com/rvrsh3ll/09a8b933291f9f98e8ec)
	* [XSS without parentheses and semi-colons - Gareth Heyes](https://portswigger.net/research/xss-without-parentheses-and-semi-colons)
	* [Bypass XSS filters using JavaScript global variables - theMiddle](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/)
	* [Bypass XSS Protection with xmp, noscript, noframes.. etc.. - Hahwul](https://www.hahwul.com/2019/04/bypass-xss-protection-with-xmp-noscript-etc....html)
	* [Executing non-alphanumeric JavaScript without parenthesis - Gareth Heyes](https://portswigger.net/research/executing-non-alphanumeric-javascript-without-parenthesis)
	* [Non-alphanumeric code With JavaScript & PHP - Gareth Heyes](http://www.businessinfo.co.uk/labs/talk/Nonalpha.pdf)
	* [CTF Challenge: INS Hack 2019 / Bypasses Everywhere -corb3nik](https://corb3nik.github.io/blog/ins-hack-2019/bypasses-everywhere)
* **DOM-based**
	* [DOM XSS Intro - MechaTechSec](https://mechatechsec.blogspot.com/2018/01/dom-xss-intro.html)
	* [DOM Based Angular Sandbox Escapes by Gareth Heyes - BSides Manchester2017](https://www.youtube.com/watch?v=jlSI5aVTEIg&index=16&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)
* **Presentations, Talks, Videos**
	* [Self XSS: we’re not so different you and I - Mathias Karlsson](https://www.youtube.com/watch?v=l3yThCIF7e4)	
	* [Scriptless Attacks – Stealing the Pie Without Touching the Sill](http://www.syssec.rub.de/media/emma/veroeffentlichungen/2012/08/16/scriptlessAttacks-ccs2012.pdf)
		* Due to their high practical impact, Cross-Site Scripting (XSS) attacks have attracted a lot of attention from the security community members. In the same way, a plethora of more or less effective defense techniques have been proposed, addressing the causes and effects of XSS vulnerabilities. As a result, an adversary often can no longer inject or even execute arbitrary scripting code in several real-life scenarios. In this paper, we examine the attack surface that remains after XSS and similar scripting attacks are supposedly mitigated by preventing an attacker from executing JavaScript code. We address the question of whether an attacker really needs JavaScript or similar functionality to perform attacks aiming for information theft. The surprising result is that an attacker can also abuse Cascading Style Sheets (CSS) in combination with other Web techniques like plain HTML, inactive SVG images or font files. Through several case studies, we introduce the so called scriptless attacks and demonstrate that an adversary might not need to execute code to preserve his ability to extract sensitive informati on from well protected websites. More precisely, we show that an attacker can use seemingly benign features to build side channel attacks that measure and exfiltrate almost arbitrar y data displayed on a given website. We conclude this paper with a discussion of potential mitigation techniques against this class of attacks. In addition, we have implemented a browser patch that enables a website to make a vital determination as to being loaded in a detached view or pop-up window. This approach proves useful for prevention of certain types of attacks we here discuss.	
* **Mutation XSS**
	* [What is mutation XSS (mXSS)? - StackOverflow](https://security.stackexchange.com/questions/46836/what-is-mutation-xss-mxss)
	* [How mXSS attacks change everything we believed to know so far - Mario Heiderich - OWASP AppSec EU 2013](https://www.youtube.com/watch?v=Haum9UpIQzU)
	* [mXSS - TheSpanner](http://www.thespanner.co.uk/2014/05/06/mxss/)
	* [Exploiting the unexploitable with lesser known browser tricks - filedescriptor](https://speakerdeck.com/filedescriptor/exploiting-the-unexploitable-with-lesser-known-browser-tricks)
	* [Running Your Instance of Burp Collaborator Server - blog.fabiopires.pt](https://blog.fabiopires.pt/running-your-instance-of-burp-collaborator-server/)
	* [Piercing the Veil: Server Side Request Forgery to NIPRNet access](https://web.archive.org/web/20180410080115/https://medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-171018bca2c3)
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
	* [XSS in GMail’s AMP4Email via DOM Clobbering - Michal Bentkowski](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)





------------------------
### <a name="xshm"></a> Cross-Site History Manipulation
* **101**
	* [Cross Site History Manipulation - OWASP](https://www.owasp.org/index.php/Cross_Site_History_Manipulation_(XSHM))
* **Articles/Papers/Talks/Writeups**
* **Tools**
* **Miscellaneous**






-----------------
### <a name="scraping"></a>Scraping
* **101**
* **Articles/Papers/Talks/Writeups**
* **General**
* **Tools**
	* [Puppeteer](https://github.com/GoogleChrome/puppeteer)
		* Puppeteer is a Node library which provides a high-level API to control Chrome or Chromium over the DevTools Protocol. Puppeteer runs headless by default, but can be configured to run full (non-headless) Chrome or Chromium.
	* [dvcs-ripper](https://github.com/kost/dvcs-ripper)
		* Rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr, ... It can rip repositories even when directory browsing is turned off.
	* [Scrapy](https://scrapy.org/)
		* An open source and collaborative framework for extracting the data you need from websites. 
* **Miscellaneous**
	* [WeasyPrint](http://weasyprint.org/)
		* WeasyPrint is a visual rendering engine for HTML and CSS that can export to PDF. It aims to support web standards for printing. WeasyPrint is free software made available under a BSD license.
BeautifulSoup




----------------
### <a name="tabnab"></a>Tabnabbing Attacks
* **101**
	* [Tabnabbing: A New Type of Phishing Attack - Aza Raskin](http://www.azarask.in/blog/post/a-new-type-of-phishing-attack/)
	* [Reverse Tabnabbing - OWASP](https://www.owasp.org/index.php/Reverse_Tabnabbing)
		* Reverse tabnabbing is an attack where a page linked from the target page is able to rewrite that page, for example to replace it with a phishing site. As the user was originally on the correct page they are less likely to notice that it has been changed to a phishing site, especially it the site looks the same as the target. If the user authenticates to this new page then their credentials (or other sensitive data) are sent to the phishing site rather than the legitimate one.
* **Articles/Papers/Talks/Writeups**
	* [Tabnabbing Protection Bypass - Ziyahan Albeniz](https://www.netsparker.com/blog/web-security/tabnabbing-protection-bypass/)
	* [Tab nabbing via window.opener - Ashish singh(HackerOne)](https://hackerone.com/reports/403891)
* **Tools**


----------------
### <a name="timing"></a>Timing-based Attacks/Data race Attacks
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
### <a name="tls-redirect"></a> TLS Redirection (and Virtual Host Confusion)
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
### <a name="webcache"></a>Web Cache Deception Attack
* **101**
* **Articles/Papers/Talks/Writeups**
	* [Web Cache Deception Attack - Omer Gil](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html)
* **Tools**











----------------
### <a name="xml"></a>XML
* **101**
	* [XXE (Xml eXternal Entity) attack(2002) - Gregory Steuck](https://www.securityfocus.com/archive/1/297714/2002-10-27/2002-11-02/0)
	* [XML Schema, DTD, and Entity Attacks A Compendium of Known Techniques - Timothy D. Morgan, Omar Al Ibrahim]
	* [Hunting in the Dark - Blind XXE](https://blog.zsec.uk/blind-xxe-learning/)
* **Articles/Papers/Talks/Writeups**
	* [Security Briefs - XML Denial of Service Attacks and Defenses(2009)](https://msdn.microsoft.com/en-us/magazine/ee335713.aspx)
	* [Advice From A Researcher: Hunting XXE For Fun and Profit](http://blog.bugcrowd.com/advice-from-a-researcher-xxe/)
	* [What You Didn't Know About XML External Entities Attacks](http://2013.appsecusa.org/2013/wp-content/uploads/2013/12/WhatYouDidntKnowAboutXXEAttacks.pdf)
	* [Leading the Blind to Light! - A Chain to RCE](https://blog.zsec.uk/rce-chain/)
	* [What You Didn't Know About XML External Entities Attacks - Timothy D. Morgan](http://2013.appsecusa.org/2013/wp-content/uploads/2013/12/WhatYouDidntKnowAboutXXEAttacks.pdf)
	* [Black Hat EU 2013 - XML Out-of-Band Data Retrieval](https://www.youtube.com/watch?v=eBm0YhBrT_c)
		* [Slides: XML Out-­Of-Band Data Retrieval - BHEU 2013](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)
	* [Generic XXE Detection](http://www.christian-schneider.net/GenericXxeDetection.html)
	* [Playing with Content-Type – XXE on JSON Endpoints - NETSPI](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
	* [FileCry - The New Age of XXE - BH USA 2015](https://www.blackhat.com/docs/us-15/materials/us-15-Wang-FileCry-The-New-Age-Of-XXE.pdf)
	* [XXE OOB exploitation at Java 1.7+ - 2014](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html)
	* [Security of applications that parse XML (supplementary) - 2009](http://d.hatena.ne.jp/teracc/20090718)
	* [Exploiting XXE In File Upload Functionality](https://www.blackhat.com/docs/us-15/materials/us-15-Vandevanter-Exploiting-XXE-Vulnerabilities-In-File-Parsing-Functionality.pdf)
	* [XML Parser Evaluation - web-in-security.blogspot.de](https://web-in-security.blogspot.de/2016/03/xml-parser-evaluation.html)
	* [Hiding in Plain Sight: XXE Vulnerability in HP Project & Portfolio Mgmt Center - Benjamin Caudill](https://rhinosecuritylabs.com/application-security/xxe-zeroday-vulnerability-in-hp-project/)
* [Don’t open that XML: XXE to RCE in XML plugins for VS Code, Eclipse, Theia, … - thezero](https://www.shielder.it/blog/dont-open-that-xml-xxe-to-rce-in-xml-plugins-for-vs-code-eclipse-theia/)
* [Playing with Content-Type – XXE on JSON Endpoints(2015) - Antti Rantasaari](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
www.vsecurity.com/download/papers/XMLDTDEntityAttacks.pdf
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
	* [Developing Burp Suite Extensions - DOYENSEC](https://github.com/doyensec/burpdeveltraining)
		* Material for the training "Developing Burp Suite Extensions – From Manual Testing to Security Automation"
	* [Burp Suite Visual Aids - lanmaster53](https://www.lanmaster53.com/2015/04/24/burp-suite-visual-aids/)
	* [SSH "accept : too many open files" on OS X when using Burp - dewhurstsecurity.com](https://blog.dewhurstsecurity.com/2013/04/08/ssh-too-many-open-files-burp.html)
* **Plugins**
	* [Adapting Burp Extensions for Tailored Pentesting](http://blog.portswigger.net/2017/08/adapting-burp-extensions-for-tailored.html)
	* [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix)
		* AuthMatrix is a Burp Suite extension that provides a simple way to test authorization in web applications and web services. 
	* [Autorize](https://github.com/Quitten/Autorize)
		* Autorize is an automatic authorization enforcement detection extension for Burp Suite. It was written in Python by Barak Tawily, an application security expert, and Federico Dotta, a security expert at Mediaservice.net. Autorize was designed to help security testers by performing automatic authorization tests. With the last release now Autorize also perform automatic authentication tests.
		* [Escalating Privileges like a Pro - Gaurav Narwani](https://gauravnarwani.com/escalating-privileges-like-a-pro/)
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
	* [Burp-molly-pack](https://github.com/yandex/burp-molly-pack)
		* Burp-molly-pack is Yandex security checks pack for Burp. The main goal of Burp-molly-pack is to extend Burp checks. Plugins contains Active and Passive security checks.
	* [NoPE Proxy](https://github.com/summitt/Burp-Non-HTTP-Extension)
		* Non-HTTP Protocol Extension (NoPE) Proxy and DNS for Burp Suite.
	* [AutoRepeater](https://github.com/nccgroup/AutoRepeater)
		* Burp Suite is an intercepting HTTP Proxy, and it is the defacto tool for performing web application security testing. While Burp Suite is a very useful tool, using it to perform authorization testing is often a tedious effort involving a "change request and resend" loop, which can miss vulnerabilities and slow down testing. AutoRepeater, an open source Burp Suite extension, was developed to alleviate this effort. AutoRepeater automates and streamlines web application authorization testing, and provides security researchers with an easy-to-use tool for automatically duplicating, modifying, and resending requests within Burp Suite while quickly evaluating the differences in responses.
	* [Uniqueness plugin for Burp Suite](https://github.com/silentsignal/burp-uniqueness)
		* Makes requests unique based on regular expressions. Handy for registration forms and any other endpoint that requires unique values upon every request.
	* [Bumpster](https://github.com/markclayton/bumpster)
		* The Unofficial Burp Extension for DNSDumpster.com. You simply supply a domain name and it returns a ton of DNS information and basically lays out the external network topology. 
	* [J2EEScan](https://github.com/ilmila/J2EEScan)
		* J2EEScan is a plugin for Burp Suite Proxy. The goal of this plugin is to improve the test coverage during web application penetration tests on J2EE applications.
	* [JWT4B](https://github.com/mvetsch/JWT4B)
		* JSON Web Tokens (JWT) support for the Burp Interception Proxy. JWT4B will let you manipulate a JWT on the fly, automate common attacks against JWT and decode it for you in the proxy history. JWT4B automagically detects JWTs in the form of 'Authorization Bearer' headers as well as customizable post body parameters.
	* [Brida](https://github.com/federicodotta/Brida)
		* Brida is a Burp Suite Extension that, working as a bridge between Burp Suite and Frida, lets you use and manipulate applications’ own methods while tampering the traffic exchanged between the applications and their back-end services/servers. It supports all platforms supported by Frida (Windows, macOS, Linux, iOS, Android, and QNX)
	* [burp-suite-error-message-checks](https://github.com/ewilded/burp-suite-error-message-checks)
		* Burp Suite extension to passively scan for applications revealing server error messages
	* [Postman-Integration](https://github.com/PortSwigger/postman-integration)
		* Postman Integration is an extension for burp to generate Postman collection fomat json file.
	* [Stepper](https://github.com/portswigger/stepper)
		* Stepper is designed to be a natural evolution of Burp Suite's Repeater tool, providing the ability to create sequences of steps and define regular expressions to extract values from responses which can then be used in subsequent steps.
	* [LinkDumper Burp Plugin](https://github.com/arbazkiraak/LinksDumper)
		* Extract (links/possible endpoints) from responses & filter them via decoding/sorting
	* [Cyber Security Transformation Chef](https://github.com/usdAG/cstc)
		* The Cyber Security Transformation Chef (CSTC) is a Burp Suite extension. It is build for security experts to extend Burp Suite for chaining simple operations for each incomming or outgoing message. It can also be used to quickly make a special custom formatting for the message.
	* [jsonp](https://github.com/kapytein/jsonp)
		* jsonp is a Burp Extension which attempts to reveal JSONP functionality behind JSON endpoints. This could help reveal cross-site script inclusion vulnerabilities or aid in bypassing content security policies.
	* [Asset Discover](https://github.com/redhuntlabs/BurpSuite-Asset_Discover)
		* Burp Suite extension to discover assets from HTTP response using passive scanning.
		* [Blogpost](https://redhuntlabs.com/blog/asset-discovery-burp-extension.html)
	* [Dr. Watson](https://github.com/prodigysml/Dr.-Watson)
		* Dr. Watson is a simple Burp Suite extension that helps find assets, keys, subdomains, IP addresses, and other useful information! It's your very own discovery side kick, the Dr. Watson to your Sherlock!
	* [Stepper](https://portswigger.net/bappstore/065d156ecefd480fa3efa36e05d55f77)
		* Stepper is designed to be a natural evolution of Burp Suite's Repeater tool, providing the ability to create sequences of steps and define regular expressions to extract values from responses which can then be used in subsequent steps.
	* [BurpExtenderHeaderChecks](https://github.com/eonlight/BurpExtenderHeaderChecks)
	* [Hackbar](https://github.com/d3vilbug/HackBar)
		* Hackbar plugin for Burp
	* [HTTPSmuggler](https://github.com/nccgroup/BurpSuiteHTTPSmuggler)
		* A Burp Suite extension to help pentesters to bypass WAFs or test their effectiveness using a number of techniques. This extension has been developed by Soroush Dalili (@irsdl) from NCC Group.






--------------------
### <a name="cloud"></a>General Cloud Services
* [A Placement Vulnerability Study in Multi-Tenant Public Clouds](https://www.usenix.org/node/191017)
* [Cloud Security Suite](https://github.com/SecurityFTW/cs-suite)
	* One stop tool for auditing the security posture of AWS & GCP infrastructure.
* [Cloud Security Wiki - NotSoSecure](https://cloudsecwiki.com)
	* Cloud Security Wiki is an initiative to provide all Cloud security related resources to Security Researchers and developers at one place.
* **"Serverless"**
	* [Peeking Behind the Curtains of Serverless Platforms - Liang Wang, Mengyuan Li, Yinqian Zhang, Thomas Ristenpart, Michael Swift](http://pages.cs.wisc.edu/~liangw/pub/atc18-final298.pdf)
		* Taking on the viewpoint of a serverless customer, we conduct the largest measurement study to date, launching more than 50,000 function instances across these three services, in order to characterize their architectures, performance, and resource management efficiency. We explain how the platforms isolate the functions of different accounts, using either virtual machines or containers, which has important security implications. We characterize performance in terms of scalability, coldstart latency, and resource efficiency, with highlights including that AWS Lambda adopts a bin-packing-like strategy to maximize VM memory utilization, that severe contention between functions can arise in AWS and Azure, and that Google had bugs that allow customers to use resources for free.



* [cloud-service-enum](https://github.com/NotSoSecure/cloud-service-enum)


--------------------
### <a name="aws"></a>AWS
* **101**
	* [Request form for performing Pentesting on AWS Infrastructure](https://aws.amazon.com/premiumsupport/knowledge-center/penetration-testing/)
	* [AWS Security Audit Guidelines - docs.aws](https://docs.aws.amazon.com/general/latest/gr/aws-security-audit-guide.html)
* **Attacking**
	* [AWS IAM Privilege Escalation – Methods and Mitigation – Part 2 - Spencer Gietzen](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/)
	* [Gone in 60 Milliseconds - Intrusion and Exfiltration in Server-less Architectures](https://media.ccc.de/v/33c3-7865-gone_in_60_milliseconds)
		* More and more businesses are moving away from monolithic servers and turning to event-driven microservices powered by cloud function providers like AWS Lambda. So, how do we hack in to a server that only exists for 60 milliseconds? This talk will show novel attack vectors using cloud event sources, exploitabilities in common server-less patterns and frameworks, abuse of undocumented features in AWS Lambda for persistent malware injection, identifying valuable targets for pilfering, and, of course, how to exfiltrate juicy data out of a secure Virtual Private Cloud. 
	* [Step By Step AWS Cloud Hacking - Andres Riancho(SecTor19)](https://sector.ca/sessions/step-by-step-aws-cloud-hacking/)
	* [Penetration Testing AWS Storage: Kicking the S3 Bucket](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/)
	* [AWS pwn](https://github.com/dagrz/aws_pwn)
		* This is a collection of horribly written scripts for performing various tasks related to penetration testing AWS. Please don't be sad if it doesn't work for you. It might be that AWS has changed since a given tool was written or it might be that the code sux. Either way, please feel free to contribute. Most of this junk was written by Daniel Grzelak but there's been plenty of contributions, most notably Mike Fuller.
	* [Pivoting in Amazon Clouds - Andres Riancho - BHUSA14](https://www.youtube.com/watch?v=2NF4LjjwoZw)
		* "From no access at all, to the company Amazon's root account, this talk will teach attendees about the components used in cloud applications like: EC2, SQS, IAM, RDS, meta-data, user-data, Celery; and how misconfigurations in each can be abused to gain access to operating systems, database information, application source code, and Amazon's services through its API. The talk will follow a knowledgeable intruder from the first second after identifying a vulnerability in a cloud-deployed Web application and all the steps he takes to reach the root account for the Amazon user. Except for the initial vulnerability, a classic remote file included in a Web application which grants access to the front-end EC2 instance, all the other vulnerabilities and weaknesses exploited by this intruder are going to be cloud-specific.
		* [Paper](https://andresriancho.github.io/nimbostratus/pivoting-in-amazon-clouds.pdf)
	* [Disrupting AWS logging - Daniel Grzelak](https://danielgrzelak.com/disrupting-aws-logging-a42e437d6594?gi=dde97e1f07f7)
	* [Abusing AWS Metadata Service - Casey Goodrich](https://www.youtube.com/watch?v=gZsmpPLZQJM)
	* [Step by step AWS Cloud Hacking - Andres Riancho(SecTor19)](https://sector.ca/sessions/step-by-step-aws-cloud-hacking/)
	* [Abusing the AWS metadata service using SSRF vulnerabilities - Christophe Tafani-Dereeper](https://blog.christophetd.fr/abusing-aws-metadata-service-using-ssrf-vulnerabilities/https://0xdf.gitlab.io/2019/08/02/bypassing-php-disable_functions-with-chankro.html)
	* [Bypass GuardDuty PenTest Alerts - Nick Frichette](https://frichetten.com/blog/bypass-guardduty-pentest-alerts)
	* [Getting shell and data access in AWS by chaining vulnerabilities - Riyaz Wilaker](https://blog.appsecco.com/getting-shell-and-data-access-in-aws-by-chaining-vulnerabilities-7630fa57c7ed)
	* [Account Jumping Post Infection Perstistency & Lateral Movement In AWS - Dan Amiga, Dor Knafo(BH-US16)](https://www.blackhat.com/docs/us-16/materials/us-16-Amiga-Account-Jumping-Post-Infection-Persistency-And-Lateral-Movement-In-AWS-wp.pdf)
	* [Securing the Cloud: A Story of Research, Discovery, and Disclosure - Jordan Drysdale](https://www.blackhillsinfosec.com/securing-the-cloud-a-story-of-research-discovery-and-disclosure/)
		* BHIS made some interesting discoveries while working with a customer to audit their Amazon Web Services (AWS) infrastructure. At the time of the discovery, we found two paths to ingress the customer’s virtual private cloud (VPC) through the elastic map reduce (EMR) application stacks. One of the vulns that gained us internal access was the Hadoop Unauthenticated RCE, which was patched by Apache a while back now. Another, and a bit more interesting entry point, was the HUE interface, which, by default, allows the creation of a new admin user for the web interface. Once in the web interface, HUE is similar to Jupyter in that it helps visualize code flow and operations. Here, you can create schedules that will send egress shells from the cluster worker nodes. Which, consequently, provides a window to a virtual private cloud network.
* **General**
	* [An Introduction to Penetration Testing AWS: Same Same, but Different - GracefulSecurity](https://www.gracefulsecurity.com/an-introduction-to-penetration-testing-aws/)
	* [Using DNS to Break Out of Isolated Networks in a AWS Cloud Environment](https://dejandayoff.com/using-dns-to-break-out-of-isolated-networks-in-a-aws-cloud-environment/)
		* Customers can utilize AWS' DNS infrastructure in VPCs (enabled by default). Traffic destined to the AmazonProvidedDNS is traffic bound for AWS management infrastructure and does not egress via the same network links as standard customer traffic and is not evaluated by Security Groups. Using DNS exfiltration, it is possible to exfiltrate data out of an isolated network.
* **IAM**
	* [AWS IAM Privilege Escalation – Methods and Mitigation - Spencer Gietzen](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
	* [AWS IAM Exploitation - Evan Perotti](https://securityriskadvisors.com/blog/aws-iam-exploitation/)
* **Lambda**
	* [Gaining Persistency on Vulnerable Lambdas - Yuval Avrahami](https://www.twistlock.com/labs-blog/gaining-persistency-vulnerable-lambdas/)
	* [Reverse engineering AWS Lambda - denialof.service](https://www.denialof.services/lambda/)
* **Mapping**
	* [Cartography](https://github.com/lyft/cartography)
		* Cartography is a Python tool that consolidates infrastructure assets and the relationships between them in an intuitive graph view powered by a Neo4j database.
* **S3**
	* **Articles/Blogposts/Writeups**
		* [A deep dive into AWS S3 access controls – taking full control over your assets - labs.detectify](https://labs.detectify.com/2017/07/13/a-deep-dive-into-aws-s3-access-controls-taking-full-control-over-your-assets/)
		* [S3 Bucket Namesquatting - Abusing predictable S3 bucket names - Ian Mckay](https://onecloudplease.com/blog/s3-bucket-namesquatting)
		* [A deep dive into AWS S3 access controls – taking full control over your assets(2017)](https://labs.detectify.com/2017/07/13/a-deep-dive-into-aws-s3-access-controls-taking-full-control-over-your-assets/)
	* **Tools**
		* [bucket-stream](https://github.com/eth0izzle/bucket-stream/blob/master/README.md)
			* This tool simply listens to various certificate transparency logs (via certstream) and attempts to find public S3 buckets from permutations of the certificates domain name.	
		* [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)
			* Security Tool to Look For Interesting Files in S3 Buckets
		* [buckethead.py](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/aws-pentest-tools)
			* buckethead.py searches across every AWS region for a variety of bucket names based on a domain name, subdomains, affixes given and more. Currently the tool will only present to you whether or not the bucket exists or if they're listable. If the bucket is listable, then further interrogation of the resource can be done. It does not attempt download or upload permissions currently but could be added as a module in the future. You will need the awscli to run this tool as this is a python wrapper around this tool.
		* [slurp](https://github.com/bbb31/slurp)
			* Enumerate S3 buckets via certstream, domain, or keywords
		* [Bucketlist](https://github.com/michenriksen/bucketlist)
			* Bucketlist is a quick project I threw together to find and crawl Amazon S3 buckets and put all the data into a PostgreSQL database for querying.
		* [Slurp](https://github.com/hehnope/slurp)
			* Blackbox/whitebox S3 bucket enumerator
* **Securing**
	* [CIS Amazon Web Services Foundations](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)
	* [asecure.cloud](https://asecure.cloud)
		* A free repository of customizable AWS security configurations and best practices
	* [AWS Security Primer](https://cloudonaut.io/aws-security-primer/#fn:2)
	* [CloudMapper](https://github.com/duo-labs/cloudmapper)
		* CloudMapper generates network diagrams of Amazon Web Services (AWS) environments and displays them via your browser. It helps you understand visually what exists in your accounts and identify possible network misconfigurations.
	* [CloudTracker](https://github.com/duo-labs/cloudtracker)
		* CloudTracker helps you find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.
		* [Blogpost](https://duo.com/blog/introducing-cloudtracker-an-aws-cloudtrail-log-analyzer)
	* [Amazon Inspector](https://aws.amazon.com/inspector/)
		* Amazon Inspector is an automated security assessment service that helps improve the security and compliance of applications deployed on AWS. Amazon Inspector automatically assesses applications for vulnerabilities or deviations from best practices. After performing an assessment, Amazon Inspector produces a detailed list of security findings prioritized by level of severity. These findings can be reviewed directly or as part of detailed assessment reports which are available via the Amazon Inspector console or API.
	* [repokid](https://github.com/Netflix/repokid)
		* AWS Least Privilege for Distributed, High-Velocity Deployment
* **Tools**
	* [Scout2](https://github.com/nccgroup/Scout2)
		* Scout2 is a security tool that lets AWS administrators assess their environment's security posture. Using the AWS API, Scout2 gathers configuration data for manual inspection and highlights high-risk areas automatically. Rather than pouring through dozens of pages on the web, Scout2 supplies a clear view of the attack surface automatically.
	* [aws_pwn](https://github.com/dagrz/aws_pwn)
		* This is a collection of horribly written scripts for performing various tasks related to penetration testing AWS. Please don't be sad if it doesn't work for you. It might be that AWS has changed since a given tool was written or it might be that the code sux. Either way, please feel free to contribute. Most of this junk was written by Daniel Grzelak but there's been plenty of contributions, most notably Mike Fuller.
	* [Nimbostratus](https://github.com/andresriancho/nimbostratus)
		* Tools for fingerprinting and exploiting Amazon cloud infrastructures
	* [cloudfrunt](https://github.com/MindPointGroup/cloudfrunt)
		* A tool for identifying misconfigured CloudFront domains
	* [cred_scanner](https://github.com/disruptops/cred_scanner)
		* A simple command line tool for finding AWS credentials in files. Optimized for use with Jenkins and other CI systems.
* **Training**
	* [AWS Security Workshops](https://github.com/aws-samples/aws-security-workshops)
		* Here you'll find a collection of security workshops and other hands-on content that will guide you through prepared scenarios that represent common use cases and security operational tasks on Amazon Web Services (AWS). The workshops closely align with the NIST Cyber Security Framework and will provide a deep dive into a variety of AWS security services, techniques, and best practices that'll you'll be able to apply to your own environments to better improve your security posture.
	* [Serverless Security Workshop](https://github.com/aws-samples/aws-serverless-security-workshop)
		* In this workshop, you will learn techniques to secure a serverless application built with AWS Lambda, Amazon API Gateway and RDS Aurora. 



----------------
### <a name="ms-azure"></a>Microsoft Azure
* **101**
	* [Microsoft Azure: Penetration Testing - Official Documentation](https://docs.microsoft.com/en-us/azure/security/azure-security-pen-testing)
	* [Microsoft Azure Datacenter IP Ranges - ms.com](https://www.microsoft.com/en-us/download/details.aspx?id=41653)
* **Documentation**
	* [Azure ATP Security Alerts - docs.ms](https://docs.microsoft.com/en-us/azure-advanced-threat-protection/suspicious-activity-guide)
* **Articles/Writeups**
	* [An Introduction to PenTesting Azure](https://www.gracefulsecurity.com/an-introduction-to-pentesting-azure/)
	* [Azure operational security checklist - docs.ms](https://docs.microsoft.com/en-us/azure/security/azure-operational-security-checklist)
	* [Security services and technologies available on Azure - docs.ms](https://docs.microsoft.com/en-us/azure/security/azure-security-services-technologies)
	* [Red Teaming Microsoft: Part 1 – Active Directory Leaks via Azure - Mike Felch](https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/)
	* [Identifying & Exploiting Leaked Azure Storage Keys - Sunil Yadav](https://www.notsosecure.com/identifying-exploiting-leaked-azure-storage-keys/)
* **Presentations/Talks/Videos**
	* [Blue Cloud of Death: Red Teaming Azure - Bryce Kunz](https://speakerdeck.com/tweekfawkes/blue-cloud-of-death-red-teaming-azure-1B)
	* [I'm in your cloud: A year of hacking Azure AD - Dirk-Jan Mollema](https://www.youtube.com/watch?v=fpUZJxFK72k)
* **Tools**
	* [Azurite - Azurite Explorer and Azurite Visualizer](https://github.com/mwrlabs/Azurite)
		* consists of two helper scripts: Azurite Explorer and Azurite Visualizer. The scripts are used to collect, passively, verbose information of the main components within a deployment to be reviewed offline, and visulise the assosiation between the resources using an interactive representation. One of the main features of the visual representation is to provide a quick way to identify insecure Network Security Groups (NSGs) in a subnet or Virtual Machine configuration.




------------------
### <a name="cloudflare"></a> Cloudflare
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



------------------
### <a name="gcloud"></a>Google Cloud
* **Articles/Writeups**
	* [Abusing Google App Scripting Through Social Engineering](http://www.redblue.team/2017/02/abusing-google-app-scripting-through.html)
	* [Persistent GCP backdoors with Google’s Cloud Shell - Juan Berner](https://medium.com/@89berner/persistant-gcp-backdoors-with-googles-cloud-shell-2f75c83096ec)
	* [Red Team Tactics for Cracking the GSuite Perimeter - Michael Felch](https://www.slideshare.net/MichaelFelch/red-team-tactics-for-cracking-the-gsuite-perimeter)
* **Presentations/Talks/Videos**
	* [G-Jacking AppEngine-based applications - HITB2014](https://conference.hitb.org/hitbsecconf2014ams/materials/D2T1-G-Jacking-AppEngine-based-Applications.pdf)
* **Tools**
	* **Attacking**
		* [Introducing G-Scout](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/august/introducing-g-scout/)
			* G-Scout is a tool to help assess the security of Google Cloud Platform (GCP) environment configurations. By leveraging the Google Cloud API, G-Scout automatically gathers a variety of configuration data and analyzes this data to determine security risks. It produces HTML output.
		* [Google Cloud Platform Security Tool](https://github.com/nccgroup/G-Scout)
	* **Securing**
		* [Google Cloud Security Scanner](https://cloud.google.com/security-scanner/)
			* Cloud Security Scanner is a web security scanner for common vulnerabilities in Google App Engine applications. It can automatically scan and detect four common vulnerabilities, including cross-site-scripting (XSS), Flash injection, mixed content (HTTP in HTTPS), and outdated/insecure libraries. It enables early identification and delivers very low false positive rates. You can easily setup, run, schedule, and manage security scans and it is free for Google Cloud Platform users.
		* [Hayat](https://github.com/DenizParlak/Hayat)
			* Google Cloud Platform Auditing & Hardening Script



--------------------------
### <a name="bugbounty"></a> Bug Bounty Writeups
* [HackerOne H1-212 Capture the Flag Solution - Corben Douglas](http://www.sxcurity.pro/H1-212%20CTF%20Solution.pdf)
* [ebay.com: RCE using CCS](http://secalert.net/#ebay-rce-ccs)
* [$10k host header - eze2307](https://sites.google.com/site/testsitehacking/10k-host-header)
* [REMOTE CODE EXECUTION! Recon Wins - vishnuraj](https://medium.com/@vishnu0002/remote-code-execution-recon-wins-e9c1db79f3da)
* [Analyzing a Creative Attack Chain Used To Compromise A Web Application](https://www.offensive-security.com/offsec/analyzing-a-creative-attack-chain/)
* [RCE in Hubspot with EL injection in HubL - betterhacker.com](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html)
	* "This is the story of how I was able to get remote code execution on Hubspot's servers by exploiting a vulnerability in HubL expression language, which is used for creating templates and custom modules within the Hubspot CRM."
* **Tools**
	* [Boucan: A Bug Bounty Canary Platform](https://github.com/3lpsy/boucanpy)
		* This project is an attempt to implement a lightweight burp collaborator-esc application and consists of two main components: a DNS Server (Custom Python Implemention with dnslib) and an API. It is still very much in the early days of development. You can think of Boucan as sort of a Canary that will notify you when an external asset (DNS Record, HTTP Server, SMTP Server) has been interacted with. This is useful for blind payload injection.
	* [Keyhacks](https://github.com/streaak/keyhacks)
		* Keyhacks is a repository which shows quick ways in which API keys leaked by a bug bounty program can be checked to see if they're valid.
























































* [AWS Services Explained through Pictures](https://www.awsgeek.com/?mc_cid=065d80dbfd&mc_eid=f956a0c5ca)

* [Hacking Slack using postMessage and WebSocket-reconnect to steal your precious token - labs.detectify](https://labs.detectify.com/2017/02/28/hacking-slack-using-postmessage-and-websocket-reconnect-to-steal-your-precious-token/)

* [Building a 1-Day Exploit for Google Chrome - Brian Pak, Andrew Wesie](https://github.com/theori-io/zer0con2018_bpak/blob/master/Chrome_Analysis_Zer0Con_2018_Final.pdf)

### Client to Authenticator Protocol (CTAP) & FIDO2
* **101**
	* [Client to Authenticator Protocol (CTAP) - fido alliance](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
	* [FIDO2: WebAuthn & CTAP - fidoalliance.com](https://fidoalliance.org/fido2/)
* **A/B/W**
	* [FIDO2: Solving The Password Problem - Nils Amiet](https://research.kudelskisecurity.com/2019/10/08/fido2-solving-the-password-problem/)


https://d1.awsstatic.com/whitepapers/Security/AWS_Security_Whitepaper.pdf
https://d1.awsstatic.com/whitepapers/Storage/AWS%20Storage%20Services%20Whitepaper-v9.pdf

* [Breaking and abusing specifications and policies - Frans Rosén(SecurityFest 2018)](https://www.youtube.com/watch?v=_VsFrYAjJ8k&feature=youtu.be)
	* Last year at Secfest, Frans Rosén talked about DNS hijacking using cloud services. This time, he approaches technologies where verification methods actually exists and how to break them. Let’s Encrypt closed down one of their three blessed verification methods due to a bug Frans found in January. Cloud storage containers already patched from being publicly exposed are still often vulnerable to full modification, extraction and deletion by abusing weak policies and application logic. Frans goes through some weak design patterns, policy structures and explains how to bypass them which have netted him over $45,000 in bug bounties.

* [Turtles All The Way Down: Storing Secrets in the Cloud and in the Data Center - Daniel Somerfield](https://danielsomerfield.github.io/turtles/)
	* [OWASP AppSec SF15](https://www.youtube.com/watch?v=OUSvv2maMYI)

* [Web IDL Standards](https://heycam.github.io/webidl/)
	* This document defines an interface definition language, Web IDL, that can be used to describe interfaces that are intended to be implemented in web browsers. Web IDL is an IDL variant with a number of features that allow the behavior of common script objects in the web platform to be specified more readily. How interfaces described with Web IDL correspond to constructs within ECMAScript execution environments is also detailed in this document. It is expected that this document acts as a guide to implementors of already-published specifications, and that newly published specifications reference this document to ensure conforming implementations of interfaces are interoperable.

* [Big List of Naughty Strings](https://github.com/minimaxir/big-list-of-naughty-strings)
	* The Big List of Naughty Strings is an evolving list of strings which have a high probability of causing issues when used as user-input data. This is intended for use in helping both automated and manual QA testing; useful for whenever your QA engineer walks into a bar.

http://l0.cm/encodings/table/

### JSON
* [Fuzzing JSON Web Services: Simple guide how to fuzz JSON web services properly - secapps](https://secapps.com/blog/2018/03/fuzzing-json-web-services)
* [XSSI and JSONP leaks](https://github.com/EdOverflow/bugbountywiki/wiki/XSSI-and-JSONP-leaks)

Add links to SSL/TLS RFCs

* [Red Team Diary, Entry #2: Stealthily Backdooring CMS Through Redis’ Memory Space - Dimitrios Bougioukas](https://medium.com/@d.bougioukas/red-team-diary-entry-2-stealthily-backdooring-cms-through-redis-memory-space-5813c62f8add)

Homograph attacks
* [IDN homograph attack - Wikipedia](https://en.wikipedia.org/wiki/IDN_homograph_attack)

XSSI
* [The Tale of a Fameless but Widespread Web Vulnerability Class - Veit Hailperin](https://www.youtube.com/watch?v=5qA0CtS6cZ4)
	* Two keys components account for finding vulnerabilities of a certain class: awareness of the vulnerability and ease of finding the vulnerability. Cross-Site Script Inclusion (XSSI) vulnerabilities are not mentioned in the de facto standard for public attention - the OWASP Top 10. Additionally there is no public tool available to facilitate finding XSSI. The impact reaches from leaking personal information stored, circumvention of token-based protection to complete compromise of accounts. XSSI vulnerabilities are fairly wide spread and the lack of detection increases the risk of each XSSI. In this talk we are going to demonstrate how to find XSSI, exploit XSSI and also how to protect against XSSI.

* [0d1n](https://github.com/CoolerVoid/0d1n)
	* 0d1n is a tool for automating customized attacks against web applications.