##Honeypots





TOC

Cull
Honeypots/nets
Tools
Write-ups




###Cull

http://www.cuckoosandbox.org/

https://www.shadowserver.org/wiki/pmwiki.php/Information/Honeypots

http://highaltitudehacks.com/2013/06/15/ghost-usb-honeypot-part-2-installing-and-running-the-honeypot/

https://en.wikipedia.org/wiki/Honeypot_%28computing%29

[Static Low-interaction Honeypots](http://www.frameloss.org/2014/07/12/static-low-interaction-honeypots/)



[elastichoney](https://github.com/jordan-wright/elastichoney)0
* Elastichoney is a simple elasticsearch honeypot designed to catch attackers exploiting RCE vulnerabilities in elasticsearch.





###Honeypots/nets
[Modern Honey Network(MHN)](https://threatstream.github.io/mhn/)
* From the secure deployment to the aggregation of thousands of events MHN provides enteprise grade management of the most current open source honeypot software. MHN is completely free open source software which supports external and internal honeypot deployments at a large and distributed scale. MHN uses the HPFeeds standard and low-interaction honeypots to keep effectiveness and security at enterprise grade levels. MHN provides full REST API out of the box and we are making CEF and STIX support available now for direct SIEM integration through our Commercial platform Optic. 

Beeswarm](http://www.beeswarm-ids.org/)
* Beeswarm is a honeypot project which provides easy configuration, deployment and managment of honeypots. Beeswarm operates by deploying fake end-user systems (clients) and services (honeypots). Beeswarm uses these systems to provides IoC (Indication of Compromise) by observing the difference between expected and actual traffic. 
* [Github](https://github.com/honeynet/beeswarm)

[Honeywall Project](https://projects.honeynet.org/honeywall/)
* The goal of this page is to provide you the latest documentation, source code, distribution, and information for the Honeynet Project's Honeywall CDROM. The Honeywall CDROM is a bootable CD that installs onto a hard drive and comes with all the tools and functionality for you to implement data capture, control and analysis. 

[PSHITT](https://github.com/regit/pshitt)
* pshitt (for Passwords of SSH Intruders Transferred to Text) is a lightweight fake SSH server designed to collect authentication data sent by intruders. It basically collects username and password used by SSH bruteforce software and writes the extracted data to a file in JSON format. pshitt is written in Python and use paramiko to implement the SSH layer.

[Omnivora](http://sourceforge.net/projects/omnivora/)
* Omnivora is a low-interaction honeypot for systems running Windows operating systems and is implemented using Borland Delphi. It is primarily designed to collect autonomous spreading malware.

[dionea](http://dionaea.carnivore.it/)
* dionaea intention is to trap malware exploiting vulnerabilities exposed by services offerd to a network, the ultimate goal is gaining a copy of the malware. 

[Kippo](https://github.com/desaster/kippo)
* Kippo is a medium interaction SSH honeypot designed to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.

[Glastopf Project](http://glastopf.org/)
* Glastopf is a Honeypot which emulates thousands of vulnerabilities to gather data from attacks targeting web applications. The principle behind it is very simple: Reply the correct response to the attacker exploiting the web application. The project has been kicked off by Lukas Rist in 2009 and the results we are got during this time are very promising and are an incentive to put even more effort in the development of this unique tool. Read the tool description for further information. We are working together with different people, organizations and institutions to get the best from the collected data. Find out more about collaborating with the project. 

[Amun](http://sourceforge.net/projects/amunhoney/)
* Amun is a low-interaction honeypot, like Nepenthes or Omnivora, designed to capture autonomous spreading malware in an automated fashion. Amun is written in Python and therefore allows easy integration of new features.

[PHP-ShockPot](https://github.com/leonjza/PHP-ShockPot)
* PHP-ShockPot is a small honeypot aimed at showing you the interesting attempts made trying to exploit your host using the now famous "Shellshock" (also known as bashbug) bug.

[Google Hack Honeypot GHH](http://ghh.sourceforge.net/)
*  Google Hack Honeypot is the reaction to a new type of malicious web traffic: search engine hackers. GHH is a “Google Hack” honeypot. It is designed to provide reconaissance against attackers that use search engines as a hacking tool against your resources. GHH implements honeypot theory to provide additional security to your web presence.  Google has developed a powerful tool. The search engine that Google has implemented allows for searching on an immense amount of information. The Google index has swelled past 8 billion pages [February 2005] and continues to grow daily. Mirroring the growth of the Google index, the spread of web-based applications such as message boards and remote administrative tools has resulted in an increase in the number of misconfigured and vulnerable web apps available on the Internet.  These insecure tools, when combined with the power of a search engine and index which Google provides, results in a convenient attack vector for malicious users. GHH is a tool to combat this threat. 

[iNetSim](http://www.inetsim.org/)
* INetSim is a software suite for simulating common internet services in a lab environment, e.g. for analyzing the network behaviour of unknown malware samples. 

[Thug - Python low-interaction honeyclient](https://buffer.github.io/thug/)
* Thug is a Python low-interaction honeyclient aimed at mimicing the behavior of a web browser in order to detect and emulate malicious contents. 



###Writeups


[ Deploying Dionaea on a Raspberry Pi using MHN](https://github.com/threatstream/mhn/wiki/Deploying-Dionaea-on-a-Raspberry-Pi)

[ Experimenting with Honeypots Using The Modern Honey Network](https://zeltser.com/modern-honey-network-experiments/)

[Building a Honeypot to Research Cyber-Attack Techniques](https://www.sussex.ac.uk/webteam/gateway/file.php?name=bell-proj.pdf&site=20)

[Lessons Learn from attacks on Kippo honeypots](https://isc.sans.edu/diary/Lessons+Learn+from+attacks+on+Kippo+honeypots/18935)

[An in-depth analysis of SSH attacks on Amazon EC2](https://blog.secdim.com/in-depth-analysis-of-ssh-attacks-on-amazon-ec2/)
* The research study investigates Secure Shell (SSH) attacks on Amazon EC2 cloud instances across different AWS zones by means of deploying Smart Honeypot (SH). It provides an in-depth analysis of SSH attacks, SSH intruders profile, and attempts to identify their tactics and purposes.


###Papers
[Analysis of Attacks Using a Honeypot - Verlag Berlin Heidelberg 2011]
* Abstract. A Honeypot is a software based security device, deployed to attract hackers by displaying services and open ports which are potentially vulnerable. While the attackers are diverted, t heir activities can then be monitored and an a- lysed to identify current a ttack methods and trends. A low - interaction Honeypot called Dion aea was chosen for this project because it can simulate services while preventing an attacker from gaining full control. Results were collected over the six week period of the experiment. The logged information of the o b- served attacks was analysed and compared with current vulnerabilities, the loc a- tions where the attacks were originating from and the time of day at the orig i- nating site. A profile of individual attackers can then be built to ga in an insight into the current attack trends in order to improve network defences.

[POSTER: Dragging Attackers to Honeypots for Effective Analysis of Cyber Threats](http://www.aims-conference.org/2014/POSTER-Dragging_Attackers_to_Honeypots_for_Effective_Analysis_of_Cyber_Threats.pdf)
