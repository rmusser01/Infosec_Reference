### <a name="honey"></a> Honeypots
--------------------------

https://github.com/4sp1r3/honeytrap
	* [sshesame](https://github.com/jaksi/sshesame)
		* A fake SSH server that lets everyone in and logs their activity

* **General**
	* **101**
		* [Honeypot Computing - Wikipedia](https://en.wikipedia.org/wiki/Honeypot_%28computing%29)
		* [The Honeynet Project](https://www.honeynet.org/about)
			* The Honeynet Project is a leading international 501c3 non-profit security research organization, dedicated to investigating the latest attacks and developing open source security tools to improve Internet security. With Chapters around the world, our volunteers have contributed to fight against malware (such as Confickr), discovering new attacks and creating security tools used by businesses and government agencies all over the world. The organization continues to be on the cutting edge of security research by working to analyze the latest attacks and educating the public about threats to information systems across the world.
		* [Honeypots - ShadowServer](https://www.shadowserver.org/wiki/pmwiki.php/Information/Honeypots)
		* **Types of Honeypots**
			* **Zero Interaction(Think Passive)**
			* **Low Interaction(Think canned, limited responses to incoming data**
			* **Medium/High Interaction(Think Emulating Graphical Services/Providing Continual Content)**
			* **HoneyData - Strings, shares/drives, etc.**
	* **Articles/Papers/Talks/Writeups**
		* [Deploying Dionaea on a Raspberry Pi using MHN](https://github.com/threatstream/mhn/wiki/Deploying-Dionaea-on-a-Raspberry-Pi)
		* [Experimenting with Honeypots Using The Modern Honey Network](https://zeltser.com/modern-honey-network-experiments/)
		* [Building a Honeypot to Research Cyber-Attack Techniques](https://www.sussex.ac.uk/webteam/gateway/file.php?name=bell-proj.pdf&site=20)
		* [Lessons Learn from attacks on Kippo honeypots](https://isc.sans.edu/diary/Lessons+Learn+from+attacks+on+Kippo+honeypots/18935)
		* [An in-depth analysis of SSH attacks on Amazon EC2](https://blog.secdim.com/in-depth-analysis-of-ssh-attacks-on-amazon-ec2/)
			* The research study investigates Secure Shell (SSH) attacks on Amazon EC2 cloud instances across different AWS zones by means of deploying Smart Honeypot (SH). It provides an in-depth analysis of SSH attacks, SSH intruders profile, and attempts to identify their tactics and purposes.
		* [Analysis of Attacks Using a Honeypot - Verlag Berlin Heidelberg 2011]()
			* Abstract. A Honeypot is a software based security device, deployed to attract hackers by displaying services and open ports which are potentially vulnerable. While the attackers are diverted, t heir activities can then be monitored and an a- lysed to identify current a ttack methods and trends. A low - interaction Honeypot called Dion aea was chosen for this project because it can simulate services while preventing an attacker from gaining full control. Results were collected over the six week period of the experiment. The logged information of the o b- served attacks was analysed and compared with current vulnerabilities, the loc a- tions where the attacks were originating from and the time of day at the orig i- nating site. A profile of individual attackers can then be built to ga in an insight into the current attack trends in order to improve network defences.
		* [POSTER: Dragging Attackers to Honeypots for Effective Analysis of Cyber Threats](http://www.aims-conference.org/2014/POSTER-Dragging_Attackers_to_Honeypots_for_Effective_Analysis_of_Cyber_Threats.pdf)
		* [Setting Honeytraps with Modsecurity - Adding fake hidden form fields](http://blog.spiderlabs.com/2014/06/setting-honeytraps-with-modsecurity-adding-fake-hidden-form-fields.html)
		* [Honeypots for Active Defense - A Practical Guide to Deploying Honeynets Within the Enterprise - Greg Foss](http://www.irongeek.com/i.php?page=videos/centralohioinfosec2015/tech201-honeypots-for-active-defense-a-practical-guide-to-deploying-honeynets-within-the-enterprise-greg-foss)
			* InfoSec analysts are all somewhat familiar with honeypots. When they are given the proper attention, care and feeding, they produce invaluable information. This intelligence has been primarily used by security researchers and organizations with advanced defensive capabilities to study their adversaries and learn from their actions. But what about the rest of us? Honeypots are a lot of work to configure, maintain, and monitor -- how can an organization that is not focused on research gain valuable intelligence using honeypots and actively defend their network using the data obtained? The answer is honeypots for active defense. There are currently many open source security tool distributions that come pre-loaded with honeypots among other useful tools, however the honeypot software is often not deployed in an effective manner. This session will discuss techniques to deploy honeypots in ways that will not overburden the security team with massive logs to sift through and focuses on correlating active threat data observed in the honeypot with the production environment. When deploying honeypots effectively, this can give security analysts one additional mechanism to tip them off to nefarious activity within their network.
		* [Global Honeypot Trends - Elliot Brink](https://www.youtube.com/watch?v=rjd-r4WA0PU)
			* Many of my computer systems are constantly compromised, attacked, hacked, 24/7. How do I know this? I've been allowing it. This presentation will cover over one year of research running several vulnerable systems (or honeypots) in multiple countries including the USA, mainland China, Russia and others. We'll be taking a look at: a brief introduction to honeypots, common attacker trends (both sophisticated and script kiddie), brief malware analysis and the statistical analysis of attackers based on GeoIP. Are there differences in attacks based on where a computer system is located? Let's investigate this together! Beginners to the topic of honeypots fear not, the basics will be covered.
		* [Security Onions and Honey Potz - Ethan Dodge - BSidesSLC2015](https://www.youtube.com/watch?v=1Jbm1zwiGTM)
* **Miscellaneous**
* **Tools**
	* **General**
		* [Introduction to T-Pot - The all in one honeypot - northsec.tech](https://northsec.tech/introduction-to-t-pot-the-all-in-one-honeypot/)
			* [T-Pot ISO Creator](https://github.com/dtag-dev-sec/tpotce)
				* T-Pot Universal Installer and ISO Creator
		* [Modern Honey Network(MHN)](https://threatstream.github.io/mhn/)
			* From the secure deployment to the aggregation of thousands of events MHN provides enteprise grade management of the most current open source honeypot software. MHN is completely free open source software which supports external and internal honeypot deployments at a large and distributed scale. MHN uses the HPFeeds standard and low-interaction honeypots to keep effectiveness and security at enterprise grade levels. MHN provides full REST API out of the box and we are making CEF and STIX support available now for direct SIEM integration through our Commercial platform Optic. 
			* [Honeypot Farming: Setup Modern Honey Network](https://medium.com/@theroxyd/honeypot-farming-setup-mhn-f07d241fcac6)
		* [Beeswarm](http://www.beeswarm-ids.org/)
			* Beeswarm is a honeypot project which provides easy configuration, deployment and managment of honeypots. Beeswarm operates by deploying fake end-user systems (clients) and services (honeypots). Beeswarm uses these systems to provides IoC (Indication of Compromise) by observing the difference between expected and actual traffic. 
			* [Github](https://github.com/honeynet/beeswarm)
		* [Honeywall Project](https://projects.honeynet.org/honeywall/)
			* The goal of this page is to provide you the latest documentation, source code, distribution, and information for the Honeynet Project's Honeywall CDROM. The Honeywall CDROM is a bootable CD that installs onto a hard drive and comes with all the tools and functionality for you to implement data capture, control and analysis. 
		* [dionea](http://dionaea.carnivore.it/)
			* dionaea intention is to trap malware exploiting vulnerabilities exposed by services offerd to a network, the ultimate goal is gaining a copy of the malware. 
		* [Glastopf Project](http://glastopf.org/)
			* Glastopf is a Honeypot which emulates thousands of vulnerabilities to gather data from attacks targeting web applications. The principle behind it is very simple: Reply the correct response to the attacker exploiting the web application. The project has been kicked off by Lukas Rist in 2009 and the results we are got during this time are very promising and are an incentive to put even more effort in the development of this unique tool. Read the tool description for further information. We are working together with different people, organizations and institutions to get the best from the collected data. Find out more about collaborating with the project. 
		* [Amun](http://sourceforge.net/projects/amunhoney/)
			* Amun is a low-interaction honeypot, like Nepenthes or Omnivora, designed to capture autonomous spreading malware in an automated fashion. Amun is written in Python and therefore allows easy integration of new features.
			* [Amun Honeypot - Github](https://github.com/zeroq/amun)
			* [Amun Honeypot Paper](https://ub-madoc.bib.uni-mannheim.de/2595/1/amunhoneypot2.pdf)
		* [Portspoof](https://drk1wi.github.io/portspoof/)
			*  The Portspoof program primary goal is to enhance your systems security through a set of new camouflage techniques. As a result of applying them your attackers' port scan result will become entirely mangled and to very significant extent meaningless. 
		* Opens all ports, hosts seemingly legitimate services on each.
		* [Honeytrap](https://github.com/honeytrap/honeytrap)
			* Honeytrap is an extensible and opensource system for running, monitoring and managing honeypots.
	* **HoneyTokens**
		* [SPACECRAB](https://bitbucket.org/asecurityteam/spacecrab)
			* Bootstraps an AWS account with everything you need to generate, mangage, and distribute and alert on AWS honey tokens. Made with breakfast roti by the Atlassian security team.
		* [DCEPT](https://github.com/secureworks/dcept)
			* A tool for deploying and detecting use of Active Directory honeytokens 
	* **Java Apps**
		* [Honeyagent](https://bitbucket.org/fkie_cd_dare/honeyagent)
			* HoneyAgent is a Java agent library that creates a Sandbox for Java applications and applets. Therefore, it uses the JVMTI as well as the JNI to intercept class loading and function calls. During runtime HoneyAgent traces function calls from the analysed application. It is displayed which class calles which function with which parameters. Reflected function calls are translated to the original function names for simpler reading.
	* **Low-Interaction**
		* [Static Low-interaction Honeypots](http://www.frameloss.org/2014/07/12/static-low-interaction-honeypots/)
	* **Service Simulators**
		* [iNetSim](http://www.inetsim.org/)
			* INetSim is a software suite for simulating common internet services in a lab environment, e.g. for analyzing the network behaviour of unknown malware samples. 
	* **Single Purpose Emulation**
		* [PHP-ShockPot](https://github.com/leonjza/PHP-ShockPot)
			* PHP-ShockPot is a small honeypot aimed at showing you the interesting attempts made trying to exploit your host using the now famous "Shellshock" (also known as bashbug) bug.
		* [HoneyBadger](https://bitbucket.org/LaNMaSteR53/honeybadger)
			* A framework for targeted geolocation.
		* [elastichoney](https://github.com/jordan-wright/elastichoney)0
			* Elastichoney is a simple elasticsearch honeypot designed to catch attackers exploiting RCE vulnerabilities in elasticsearch.
	* **SSH**
		* [PSHITT](https://github.com/regit/pshitt)
			* pshitt (for Passwords of SSH Intruders Transferred to Text) is a lightweight fake SSH server designed to collect authentication data sent by intruders. It basically collects username and password used by SSH bruteforce software and writes the extracted data to a file in JSON format. pshitt is written in Python and use paramiko to implement the SSH layer.
		* [Kippo](https://github.com/desaster/kippo)
			* Kippo is a medium interaction SSH honeypot designed to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.
	* **Search Engine**
		* [Google Hack Honeypot GHH](http://ghh.sourceforge.net/)
			*  Google Hack Honeypot is the reaction to a new type of malicious web traffic: search engine hackers. GHH is a “Google Hack” honeypot. It is designed to provide reconaissance against attackers that use search engines as a hacking tool against your resources. GHH implements honeypot theory to provide additional security to your web presence.  Google has developed a powerful tool. The search engine that Google has implemented allows for searching on an immense amount of information. The Google index has swelled past 8 billion pages [February 2005] and continues to grow daily. Mirroring the growth of the Google index, the spread of web-based applications such as message boards and remote administrative tools has resulted in an increase in the number of misconfigured and vulnerable web apps available on the Internet.  These insecure tools, when combined with the power of a search engine and index which Google provides, results in a convenient attack vector for malicious users. GHH is a tool to combat this threat. 
	* **Tarpits**
		* [Web Labyrinth](https://github.com/mayhemiclabs/weblabyrinth)
			* A simple tool that creates a maze of bogus web pages to  confuse web scanners. It's main goal is to delay and occupy malicious  scanners that scan websites in order for incident handlers to detected  and respond to them before damage is done.
	* **USB**
		* [Ghost USB honeypot](https://github.com/honeynet/ghost-usb-honeypot)
			* Ghost is a honeypot for malware that spreads via USB storage devices. It detects infections with such malware without the need of any further information. If you would like to see a video introduction to the project, have a look at this Youtube video](https://www.youtube.com/watch?v=9G9oo3b9qR4)
			* [Ghost USB Honeypot - Installing/Running](http://highaltitudehacks.com/2013/06/15/ghost-usb-honeypot-part-2-installing-and-running-the-honeypot/)
	* **Web**
		* [Thug - Python low-interaction honeyclient](https://buffer.github.io/thug/)
			* Thug is a Python low-interaction honeyclient aimed at mimicing the behavior of a web browser in order to detect and emulate malicious contents.
		* [Wordpot](https://github.com/gbrindisi/wordpot)
			* Wordpot is a Wordpress honeypot which detects probes for plugins, themes, timthumb and other common files used to fingerprint a wordpress installation.
		* [phpmyadmin_honeypot](https://github.com/gfoss/phpmyadmin_honeypot)
			* Probably one of the smallest and simplest web honeypots out there...
		* [Web Bug Server](http://sourceforge.net/p/adhd/wiki/Web%20Bug%20Server/)
			* Easily embed a web bug inside word processing documents. These bugs are hidden to the casual observer by using things like linked style sheets and 1 pixel images.
		* [honeyLambda](https://github.com/0x4D31/honeyLambda)
			* a simple, serverless application designed to create and monitor URL {honey}tokens, on top of AWS Lambda and Amazon API Gateway
	* **Windows-based**
		* [Omnivora](http://sourceforge.net/projects/omnivora/)
			* Omnivora is a low-interaction honeypot for systems running Windows operating systems and is implemented using Borland Delphi. It is primarily designed to collect autonomous spreading malware.
	* **Wireless**
		* [romanHunter](http://sourceforge.net/projects/romanhunter/)
			* romanHunter (router man Hunter) is a wireless honeypot or closer to a sinkhole that will bait a cracker, capture the MAC address, reset the WIFI password (effectively destroying their connection) and wait for the next authorized connection.  The password changes happen on a round robin basis from entries in the password file (pw_list.txt).
* **Integration with Other Tools**
	* **Splunk**
		* [Tango Honeypot Intelligence](https://github.com/aplura/Tango)
			* Honeypot Intelligence with Splunk
* **Miscellaneous**
	* [Hflow2](https://projects.honeynet.org/hflow)
		* Data Analysis System