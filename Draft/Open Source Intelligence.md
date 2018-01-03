# Open Source Intelligence


## Table of Contents
* [General](#general)
* [Articles/Writeups](#writeups)
* [Presentations & Talks](#talks)
* [Tools](#tools))
* [CVS/Git/Similar](#cvs)
* [DNS Stuff/related](#dns)
* [Email Gathering](#email)
* [Fancy Search Engines](#search)
* [General Meta Data](#meta)
* [General Data Scrapers](#scrape)
* [Google Hacking](#gh)
* [Site Specific Tools](#site)
* [Social Media Search/Enumeration](#social)
* [Company/People Searching](#ppl)
* [Reference Sites](#reference)
* [Miscellaneous](#misc)




#### Sort

http://computercrimeinfo.com/cleaningid.html

* [OSINT - onstrat](http://www.onstrat.com/osint/)
* [PDF Creative Commons OSINT toolbag guide](http://www.phibetaiota.net/wp-content/uploads/2013/07/2013-07-11-OSINT-2ool-Kit-On-The-Go-Bag-O-Tradecraft.pdf)

http://toddington.com/resources/

www.osintinsight.com/shared.php?user=Mediaquest&folderid=0\

* Add list of Sources:
* UCC - Uniform Commercial Code; DOC - Current Industrial Patents; DMV - Vehicle Ownership applications; Patents - Patent DBs; Operating Licenses/Permits; Trade Journals;

* [RSOE EDIS - Emergency and Disaster Information Service](http://hisz.rsoe.hu/alertmap/index2.php)

[Hunting Pastebin with PasteHunter](https://techanarchy.net/2017/09/hunting-pastebin-with-pastehunter/)

[Pattern](https://github.com/clips/pattern/blob/master/README.md)
	* Pattern is a web mining module for Python. It has tools for: Data Mining: web services (Google,; Twitter, Wikipedia), web crawler, HTML DOM parser; Natural Language Processing: part-of-speech taggers, n-gram search, sentiment analysis, WordNet; Machine Learning: vector space model, clustering, classification (KNN, SVM, Perceptron); Network Analysis: graph centrality and visualization.

* [Cr3dOv3r](https://github.com/D4Vinci/Cr3dOv3r)
	* Cr3dOv3r simply you give it an email then it does two simple jobs (but useful): Search for public leaks for the email and if it any, it returns with all available details about the leak (Using hacked-emails site API). Now you give it this email's old or leaked password then it checks this credentials against 16 websites (ex: facebook, twitter, google...) then it tells you if login successful in any website!


#### End Sort




--------------------
### <a name="general"></a>General
* **General**
	* SWOT - Strengths, Weaknesses, Opportunities, Threats
* 101
	* [Open Source Intelligence - Wikipedia](http://en.wikipedia.org/wiki/Open-source_intelligence)
* Alerting
	* [Google Trends](https://trends.google.com/trends/)
		* See what are the popular related topics people are searching for. This will help widen your search scope.
	* [Google Alerts](https://www.google.com/alerts)
		* Google Alerts are email updates of the latest relevant Google results (web, news, etc.) based on your queries.
	* [PasteLert](https://www.andrewmohawk.com/pasteLert/)
		* PasteLert is a simple system to search pastebin.com and set up alerts (like google alerts) for pastebin.com entries. This means you will automatically recieve email whenever your term(s) is/are found in new pastebin entries!
* Educational
	* [Intelligence Gathering - PTES](http://www.pentest-standard.org/index.php/Intelligence_Gathering)
	* [Corporate Espionage without the Hassle of Committing Felonies](https://www.slideshare.net/JohnCABambenek/corporate-espionage-without-the-hassle-of-committing-felonies)
* General
	* [NATO Open Source Intelligence Handbook](http://www.oss.net/dynamaster/file_archive/030201/ca5fb66734f540fbb4f8f6ef759b258c/NATO%20OSINT%20Handbook%20v1.2%20%2d%20Jan%202002.pdf)
* OSINT Based News
	* [JustSecurity](https://www.justsecurity.org/)
		* Just Security is an online forum for the rigorous analysis of U.S. national security law and policy. We aim to promote principled and pragmatic solutions to national security problems that decision-makers face. Our Board of Editors includes individuals with significant government experience, civil society attorneys, academics, and other leading voices. Just Security is based at the Center for Human Rights and Global Justice at New York University School of Law.
	* [OSINTInsight](http://www.osintinsight.com/shared.php?user=Mediaquest&folderid=0)
	* [Janes](http://www.janes.com/)
	* [bell?ngcat](https://www.bellingcat.com/) 
		* By and for citizen investigative journalists
	* [NightWatch](http://www.kforcegov.com/Solutions/IAO/NightWatch/About.aspx)
		* NightWatch is an executive commentary and analysis of events that pose or advance threats to US national security interests. It is deliberately edgy in the interest of clarity and brevity. As a product for executives, the distribution and all feedback comments are anonymous. 
* Resources
	* [Awesome-OSINT](https://github.com/jivoi/awesome-osint)
	* [OSINT Framework](http://osintframework.com/)
	* [OSINT Resources - greynetwork2](https://sites.google.com/site/greynetwork2/home/osint-resources)
	* [Intel Techniques - Links](http://www.inteltechniques.com/links.html)
	* [toddington - resources](https://www.toddington.com/resources/)
	* [onstrat - osint](http://www.onstrat.com/osint/)
	* http://osintinsight.com/shared.php?expand=169,175&folderid=0&user=Mediaquest
* Writeups
	* [Fantastic OSINT and where to find it - blindseeker/malware focused](http://archive.is/sYzcP#selection-62.0-62.1)
	* [Some blog posts describing/bringing you up to speed on OSINT by krypt3ia](http://krypt3ia.wordpress.com/2012/01/11/the-subtle-art-of-osint/)
	* [Glass Reflections in Pictures + OSINT = More Accurate Location](http://blog.ioactive.com/2014/05/glass-reflections-in-pictures-osint.html)
	* [Exploring the Github Firehose](http://blog.scalyr.com/2013/10/exploring-the-github-firehose/)
	* [OSINT Through Sender Policy Framework (SPF) Records](https://community.rapid7.com/community/infosec/blog/2015/02/23/osint-through-sender-policy-framework-spf-records)
* Talks & Presentations
	* [Cognitive Bias and Critical Thinking in Open Source Intelligence - Defcamp 2014](https://www.youtube.com/watch?v=pVAM21UERLU&index=24&list=PLnwq8gv9MEKgSryzYIFhpmCcqnVzdUWfH)
	* [Dark Arts of OSINT Skydogcon](https://www.youtube.com/watch?v=062pLOoZhk8)
	* [Developing a Open Source Threat Intelligence Program—Edward McCabe](http://www.irongeek.com/i.php?page=videos/circlecitycon2014/105-developing-a-open-source-threat-intelligence-program-edward-mccabe)
		* What if you could get out in front of common threats such as botnets, scanners and malware? Good news, you can. Learn about one geeks struggle with life on the Internet of (bad) things when it comes to being online, identifying “odd” things, and developing an Open Source Threat Intelligence Program from Open Source Tools and Public Sources.
	* [Corporate Espionage: Gathering Actionable Intelligence Via Covert Operations - Brent White - Defcon22](https://www.youtube.com/watch?v=D2N6FclMMTg)
	* [How to Use Python to Spy on Your Friends: Web APIs, Recon ng, & OSINT](https://www.youtube.com/watch?v=BOjz7NfsLpA)
	* [Practical OSINT - Shane MacDougall](https://www.youtube.com/watch?v=cLmEJLy7dv8)
		*  There’s more to life to OSINT than google scraping and social media harvesting. Learn some practical methods to automate information gathering, explore some of the most useful tools, and learn how to recognize valuable data when you see it. Not only will we explore various tools, attendees will get access to unpublished transforms they can use/modify for their own use.
	* [Pwning People Personally - Josh Schwartz](https://www.youtube.com/watch?v=T2Ha-ZLZTz0)
	* [You're Leaking Trade Secrets - Defcon22 Michael Schrenk](https://www.youtube.com/watch?v=JTd5TL6_zgY)
		* Networks don't need to be hacked for information to be compromised. This is particularly true for organizations that are trying to keep trade secrets. While we hear a lot about personal privacy, little is said in regard to organizational privacy. Organizations, in fact, leak information at a much greater rate than individuals, and usually do so with little fanfare. There are greater consequences for organizations when information is leaked because the secrets often fall into the hands of competitors. This talk uses a variety of real world examples to show how trade secrets are leaked online, and how organizational privacy is compromised by seemingly innocent use of The Internet.
	* [ZOMG Its OSINT Heaven Tazz Tazz](https://www.youtube.com/watch?v=cLmEJLy7dv8)










-------------
### <a name="tools"></a>OSINT Tools/Resources
* **Tools**
	* [blacksheepwall](https://github.com/tomsteele/blacksheepwall)
		* blacksheepwall is a hostname reconnaissance tool
	* [Creepy.py](http://ilektrojohn.github.io/creepy/)
		* Description: Creepy is a geolocation OSINT tool. Gathers geolocation related information from online sources, and allows for presentation on map, search filtering based on exact location and/or date, export in csv format or kml for further analysis in Google Maps.
	* [Maltego](https://www.paterva.com/web6/products/maltego.php)
		* Description: What you use to tie everything together.
	* [OpenRefine](https://github.com/OpenRefine/OpenRefine)	
		* Description: OpenRefine is a power tool that allows you to load data, understand it, clean it up, reconcile it to master database, and augment it with data coming from Freebase or other web sources. All with the comfort and privacy of your own computer.
	* [Oryon C Portable](http://osintinsight.com/oryon.php)
		* Oryon C Portable is a web browser designed to assist researchers in conducting Open Source Intelligence investigations. Oryon comes with dozens of pre-installed tools and a select set of links cataloged by category – including those that can be found in the OI Shared Resources.
	* [OSINT Mantra](http://www.getmantra.com/hackery/osint.html)
	* [Recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng)
		* Description: Recon-ng is a full-featured Web Reconnaissance framework written in Python. Complete with independent modules, database interaction, built in convenience functions, interactive help, and command completion, Recon-ng provides a powerful environment in which open source web-based reconnaissance can be conducted quickly and thoroughly.
	* [TouchGraph SEO Browser](http://www.touchgraph.com/seo)
		* Use this free Java application to explore the connections between related websites.


------------------
#### <a name="ppl"></a>Company/People Searching
* [data.com](https://www.data.com/)
* [LittleSis](https://littlesis.org/)
	* LittleSis is a free database of who-knows-who at the heights of business and government.
* [Jigsaw](http://jigsawbusinessgroup.com/what-we-do/people/)
	* Jigsaw is a prospecting tool used by sales professionals, marketers and recruiters to get fresh and accurate sales leads and business contact information.
* [Spokeo](https://www.spokeo.com/)
	* Spokeo is a people search engine that organizes white pages listings, public records and social network information into simple profiles to help you safely find and learn about people.\
* [Hoovers](http://www.hoovers.com/)
	* Search over 85 million companies within 900 industry segments; Hoover's Reports Easy-to-read reports on key competitors, financials, and executives
* [Market Visual](http://www.marketvisual.com/)
	* Search Professionals by Name, Company or Title
* [Glass Door](https://www.glassdoor.com/)
	* Search jobs then look inside. Company salaries, reviews, interview questions, and more all posted anonymously by employees and job seekers.
* [192](http://www.192.com/)
	* Find people, businesses and places in the UK with 192.com. Directory enquiries, a people finder, business listings and detailed maps with aerial photos.
* [corporationwiki](https://www.corporationwiki.com/)
* [orbis](https://orbisdirectory.bvdinfo.com/version-2017821/OrbisDirectory/Companies)
	* Company information across the globe


-------------
#### <a name="cvs"></a>CVS/Git/Similar Focused
* [repo-supervisor](https://github.com/auth0/repo-supervisor)
* [GitPrey](https://github.com/repoog/GitPrey)
	* GitPrey is a tool for searching sensitive information or data according to company name or key word something.The design mind is from searching sensitive data leakling in Github:
* [git-all-secrets](https://github.com/anshumanbh/git-all-secrets)
	* A tool to capture all the git secrets by leveraging multiple open source git searching tools
* [github-firehose](https://www.npmjs.com/package/github-firehose)
	* A library that will connect to github and emit events from the Github Event API in near-real-time
	* [Exploring the Github Firehose](http://blog.scalyr.com/2013/10/exploring-the-github-firehose/)
* [Gitem](https://github.com/mschwager/gitem)
	* Gitem is a tool for performing Github organizational reconnaissance.
* [Truffle Hog](https://github.com/dxa4481/truffleHog)
	* Searches through git repositories for high entropy strings, digging deep into commit history and branches. This is effective at finding secrets accidentally committed that contain high entropy.
* [dvcs-ripper](https://github.com/kost/dvcs-ripper)
	* Rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr, ... It can rip repositories even 
when directory browsing is turned off.
* [Truffle Hog](https://github.com/dxa4481/truffleHog)
	* Searches through git repositories for high entropy strings, digging deep into commit history



----------------
###### <a name="dns"></a>DNS Stuff
* [dauntless](https://github.com/cmeister2/dauntless)
	* Tools for analysing the forward DNS data set published at https://scans.io/study/sonar.fdns_v2
* [dnstwist](https://github.com/elceef/dnstwist)
	* Domain name permutation engine for detecting typo squatting, phishing and corporate espionage
* [typofinder](https://github.com/nccgroup/typofinder)
	* Typofinder for domain typo discovery




-------------
#### <a name="email"></a>Email Gathering/Reconnaissance
* **Articles/Writeups**
	* [OSINT Through Sender Policy Framework Records](https://community.rapid7.com/community/infosec/blog/2015/02/23/osint-through-sender-policy-framework-spf-records)
* Tools
	* [SimplyEmail](https://github.com/killswitch-GUI/SimplyEmail)
		* What is the simple email recon tool? This tool was based off the work of theHarvester and kind of a port of the functionality. This was just an expansion of what was used to build theHarvester and will incorporate his work but allow users to easily build Modules for the Framework. Which I felt was desperately needed after building my first module for theHarvester.
	* [Email Reconnaissance and Phishing Template Generation Made Simple](https://cybersyndicates.com/2016/05/email-reconnaissance-phishing-template-generation-made-simple/)
	* [theHarvester](https://github.com/laramies/theHarvester)
		* theHarvester is a tool for gathering e-mail accounts, subdomain names, virtual hosts, open ports/ banners, and employee names from different public sources (search engines, pgp key servers).
	* [discover.sh](https://github.com/leebaird/discover)
		* For use with Kali Linux. Custom bash scripts used to automate various pentesting tasks.





-------------
#### <a name="search"></a>Fancy Search Engines
* [Entity Cube](http://entitycube.research.microsoft.com/) 
	* EntityCube is a research prototype for exploring object-level search technologies, which automatically summarizes the Web for entities (such as people, locations and organizations) with a modest web presence.
* [Silobreaker](http://www.silobreaker.com/)
	* Enterprise Semantic Search Engine, allows virtualisation of data, analytics and exploration of key data.
* [iSeek](http://www.iseek.com/#/web)
	* Another handy search engine that break results down into easy to manage categories.
* [Carrot2](http://search.carrot2.org/stable/search)
	*  Carrot2 organizes your search results into topics. With an instant overview of what's available, you will quickly find what you're looking for. 
* [Sqoop](http://sqoop.com/)
	* OSINT search engine of public documents(handy)
* [GlobalFileSearch](https://ftplike.com)
		* An FTP Search Engine that may come in handy.


-------------
#### <a name="meta"></a>General Meta Data
* [Just-Metadata](https://github.com/ChrisTruncer/Just-Metadata)
	* Just-Metadata is a tool that can be used to gather intelligence information passively about a large number of IP addresses, and attempt to extrapolate relationships that might not otherwise be seen. Just-Metadata has "gather" modules which are used to gather metadata about IPs loaded into the framework across multiple resources on the internet. Just-Metadata also has "analysis" modules. These are used to analyze the data loaded Just-Metadata and perform various operations that can identify potential relationships between the loaded systems.
* [MetaGooFil](https://code.google.com/p/metagoofil/)	
	* Description: Metagoofil is an information gathering tool designed for extracting metadata of public documents (pdf,doc,xls,ppt,docx,pptx,xlsx) belonging to a target company. The tool will perform a search in Google to identify and download the documents to local disk and then will extract the metadata with different libraries like Hachoir, PdfMiner and others. With the results it will generate a report with usernames, software versions and servers or machine names that will help Penetration testers in the information gathering phase.
* [Metashield Analyzer](https://metashieldanalyzer.elevenpaths.com/)
	* Description: Metadata documents can help a malicious user to obtain information that is beyond our control in an enterprise environment. Metashield Analyzer is an online service that allows easily check if your office documents contain metadata.
* [PowerMeta](https://github.com/dafthack/PowerMeta)
	* PowerMeta searches for publicly available files hosted on various websites for a particular domain by using specially crafted Google, and Bing searches. It then allows for the download of those files from the target domain. After retrieving the files, the metadata associated with them can be analyzed by PowerMeta. Some interesting things commonly found in metadata are usernames, domains, software titles, and computer names.






-------------
#### <a name="scrape"></a> General Data Scrapers
* [XRAY](https://github.com/evilsocket/xray)
	* XRay is a tool for recon, mapping and OSINT gathering from public networks.
* [NameCheck](https://www.namecheck.com)
	* Search usernames across multiple services/domain registries
* [TheHarvester](From: https://code.google.com/p/theharvester/)
	* Description: The objective of this program is to gather emails, subdomains, hosts, employee names, open ports and banners from different public sources like search engines, PGP key servers and SHODAN computer database. This tool is intended to help Penetration testers in the early stages of the penetration test in order to understand the customer footprint on the Internet. It is also useful for anyone that wants to know what an attacker can see about their organization. 
* [OSINT OPSEC Tool](https://github.com/hyprwired/osint-opsec-tool)
	* Description: The OSINT OPSEC Tool monitors multiple 21st Century OSINT sources real-time for keywords, then analyses the results, generates alerts, and maps trends of the data, finding all sorts of info people probably don't want others to see... 


-------------
#### <a name="gh"></a>Google Hacking
* [Google Hacking for Penetration Testers](https://www.blackhat.com/presentations/bh-europe-05/BH_EU_05-Long.pdf)
* [ExpoitDB archive of the google hacking database](http://www.exploit-db.com/google-dorks/)
* [Google Hacking Database](http://www.hackersforcharity.org/ghdb/)
	* We call them 'googledorks': Inept or foolish people as revealed by Google. Whatever you call these fools, you've found the center of the Google Hacking Universe! 
* [Google Hacking - Search Diggity tool](http://www.bishopfox.com/resources/tools/google-hacking-diggity/attack-tools/)
	* SearchDiggity 3.1 is the primary attack tool of the Google Hacking Diggity Project. It is Bishop Fox’s MS Windows GUI application that serves as a front-end to the most recent versions of our Diggity tools: GoogleDiggity, BingDiggity, Bing LinkFromDomainDiggity, CodeSearchDiggity, DLPDiggity, FlashDiggity, MalwareDiggity, PortScanDiggity, SHODANDiggity, BingBinaryMalwareSearch, and NotInMyBackYard Diggity.
* [GoogD0rker](https://github.com/ZephrFish/GoogD0rker)
	* GoogD0rker is a tool for firing off google dorks against a target domain, it is purely for OSINT against a specific target domain. Designed for OSX originally however googD0rker txt now works on all nix platforms.





-----------
### <a name="nin"></a>Network Information Search Engines
* [Whoisology](https://whoisology.com/)
	* Whoisology is a domain name ownership archive with literally billions of searchable and cross referenced domain name whois records. 





------------------------
##### <a name="site"></a>Site Specific
* AWS
	* [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)
		* AWSBucketDump is a tool to quickly enumerate AWS S3 buckets to look for loot. It's similar to a subdomain bruteforcer but is made specifically for S3 buckets and also has some extra features that allow you to grep for delicious files as well as download interesting files if you're not afraid to quickly fill up your hard drive.
* LinkedIn
	* [InSpy](https://github.com/gojhonny/InSpy)
		* A LinkedIn enumeration tool
	* [linkedin](https://github.com/eracle/linkedin)
		* Linkedin Scraper using Selenium Web Driver, Firefox 45, Ubuntu and Scrapy
	* [LinkedInt: A LinkedIn scraper for reconnaissance during adversary simulation](https://github.com/mdsecactivebreach/LinkedInt)
	* [LinkedIn Gatherer](https://github.com/DisK0nn3cT/linkedin-gatherer)
	* [socilab](http://socilab.com/#home)
		* This site allows users to visualize and analyze their LinkedIn network using methods derived from social-scientific research. Full sample output is shown here. The site is free and open-source. Have fun!
* Twitter
	* [OneMillionTweetMap](http://onemilliontweetmap.com/)
		* This page maps the last geolocalized tweets delivered by the twitter stream API. ... YES - IN REAL-TIME - and we keep "only" the last one million tweets.
	* [tweets_analyzer](https://github.com/x0rz/tweets_analyzer)
		* Tweets metadata scraper & activity analyzer
	* [Tweet Archivist](https://www.tweetarchivist.com/)
	* [tweets_analyzer](https://github.com/x0rz/tweets_analyzer)
		* Tweets metadata scraper & activity analyzer
	* [Tinfoleak](http://vicenteaguileradiaz.com/tools/)
		* tinfoleak is a simple Python script that allow to obtain: basic information about a Twitter user (name, picture, location, followers, etc.); devices and operating systems used by the Twitter user; applications and social networks used by the Twitter user; place and geolocation coordinates to generate a tracking map of locations visited; show user tweets in Google Earth!; download all pics from a Twitter user; hashtags used by the Twitter user and when are used (date and time); user mentions by the the Twitter user and when are occurred (date and time); topics used by the Twitter user
* Github
	* [Github dorks - finding vulns](http://blog.conviso.com.br/2013/06/github-hacking-for-fun-and-sensitive.html)











---------------
### <a name="social"></a>Social Media Search/Enumeration
* [CheckUsernames](http://checkusernames.com/)
	* Check the use of your brand or username on 160 Social Networks
* [NameCHK](https://namechk.com/)
	* Check to see if your desired username or vanity url is still available at dozens of popular Social Networking and Social Bookmarking websites.
* [Scythe](https://github.com/ChrisJohnRiley/Scythe)
	* The ability to test a range of email addresses across a range of sites (e.g. social media, blogging platforms, etc...) to find where those targets have active accounts. This can be useful in a social engineering test where you have email accounts for a company and want to list where these users have used their work email for 3rd party web based services.
* [Social Mention](http://www.socialmention.com/)
	* Social Mention is a social media search engine that searches user-generated content such as blogs, comments, bookmarks, events, news, videos, and more
* [Whos Talkin](http://www.whostalkin.com/)
	* social media search tool that allows users to search for conversations surrounding the topics that they care about most.

	





