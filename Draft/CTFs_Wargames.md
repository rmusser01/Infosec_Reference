# CTFs & Wargames

-------------------------
## Table of Contents
- [General](#general)
- [101](#101)
- [Beginner Focused CTFs](#beginner)
- [Challenge Archives](#archives)
- [One-Off Challenges](#one-off)
- [Challenge Sites](#sites)
- [Educational Stuff](#educational)
- [Handy Tools](#tools)
- [Making Your Own CTF](#own)
- [Vulnerable VMs](#vulnerable)
- [Wargames](#wargames)
- [Writeups](#writeups)





https://github.com/stripe-ctf/stripe-ctf-2.0/
https://www.counterhackchallenges.com/
https://labs.nettitude.com/blog/derbycon-2018-ctf-write-up/
http://ctfhacker.com/reverse/2018/09/16/flareon-2018-wasabi.html

----------------------------------------
### <a name="general">General</a>
* **General**
	* [ctf-time](https://ctftime.org/)
* **101**<a name="101"></a>
	* [How to play your first OpenCTF](http://www.openctf.com/html/firstctf.html)
	* [Capture The Flag (CTF): What Is It for a Newbie?](https://www.alienvault.com/blogs/security-essentials/capture-the-flag-ctf-what-is-it-for-a-newbie)
	* [Advice for my first CTF? - Reddit Thread](https://www.reddit.com/r/hacking/comments/24py5h/advice_for_my_first_ctf/)
* **Beginner Focused CTFs**<a name="beginner"></a>
	* PicoCTF
	* CSAW
* **Challenge Archives**<a name="archives"></a>
	* [Archive of recent CTFs](http://repo.shell-storm.org/CTF/)
* **Challenges (one-offs)**<a name="one-off"></a>
	* [Forensics Contest](http://forensicscontest.com/)
	* [List of themed Hacker challenges](http://counterhack.net/Counter_Hack/Challenges.html)
	* [Sans Community Forensics Challenges](https://www.digital-forensics.sans.org/community/challenges)
	* [Greenhorn](https://github.com/trailofbits/greenhorn)
		* Greenhorn is a Windows Pwnable released during CSAW Quals 2014. It's meant to be an introduction to modern Windows binary exploitation.
* **Challenge Sites**<a name="sites"></a>
	* [HacktheBox.eu](https://www.hackthebox.eu/)
	* [Wechall](http://wechall.net/)
		* An amazing site. Tracks, lists, scores, various challenge sites. If you’re looking for a challenge or two, and not a wargame, this is the site you want to hit up first.
	* [XSS Challenge Wiki](https://github.com/cure53/xss-challenge-wiki/wiki)
		* A wiki that contains various xss challenges.
	* [Halls of Valhalla](http://halls-of-valhalla.org/beta/challenges)
	* [EnigmaGroup](http://www.enigmagroup.org/)
	* [cmdchallenge](https://github.com/jarv/cmdchallenge)
		* This repo holds the challenges for cmdchallenge.co - command-line challenges - can add your own/modify existing challenges
	* [Canyouhackit](http://canyouhack.it/)
		* Can You Hack It is a Hacking Challenge site designed to not only allow you to test and improve your skills in a wide variety of categories but to socialise both on the forums and on our IRC channel with other security enthusiasts. 
	* [Tasteless](http://chall.tasteless.se/)
	* [Hack This](https://www.hackthis.co.uk/)
	* [XSS Challenge Wiki](https://github.com/cure53/xss-challenge-wiki/wiki)
		* [List without spoilers:](https://github.com/cure53/xss-challenge-wiki/wiki/Older-Challenges-and-Write-Ups)
* **Educational**<a name="educational"></a>
	* [Suggestions on Running a CTF](https://github.com/pwning/docs/blob/master/suggestions-for-running-a-ctf.markdown)
		* This document describes some of the design decisions and technical details involved in running a CTF competition. It attempts to summarize some opinions held by the CTF community and list some specific pitfalls to avoid when designing problems.
	* [The Many Maxims of Maximally Effective CTFs](http://captf.com/maxims.html)
	* [CTF Field Guide - TrailofBits](https://trailofbits.github.io/ctf/)
	* [Golden Flag CTF Awards](http://golden-flags.com/)
* **Handy Tools**<a name="tools"></a>
	* [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html)
		* pngcheck verifies the integrity of PNG, JNG and MNG files (by checking the internal 32-bit CRCs [checksums] and decompressing the image data); it can optionally dump almost all of the chunk-level information in the image in human-readable form. For example, it can be used to print the basic statistics about an image (dimensions, bit depth, etc.); to list the color and transparency info in its palette (assuming it has one); or to extract the embedded text annotations. This is a command-line program with batch capabilities.
	* [pwntools](https://github.com/Gallopsled/pwntools)
	* [CTF Scripts and PyInstaller (.py > .exe) ](http://www.primalsecurity.net/ctf-scripts-and-pyinstaller-py-exe/)
	* [RSACtfTool](https://github.com/Ganapati/RsaCtfTool)
		* RSA tool for ctf - uncipher data from weak public key and try to recover private key Automatic selection of best attack for the given public key
* **Making Your Own CTF**<a name="make"></a>
	* [AppJailLauncher](https://github.com/trailofbits/AppJailLauncher)
		* CTF Challenge Framework for Windows 8 and above 
	* [CTFd](https://github.com/isislab/CTFd)
		* CTFd is a CTF in a can. Easily modifiable and has everything you need to run a jeopardy style CTF.
	* [FBCTF](https://github.com/facebook/fbctf)
		* The Facebook CTF is a platform to host Jeopardy and “King of the Hill” style Capture the Flag competitions.
	* [hack-the-arch](https://github.com/mcpa-stlouis/hack-the-arch)
		* This is a scoring server built using Ruby on Rails by the Military Cyber Professionals Association (MCPA). It is free to use and extend under the MIT license (see LICENSE file). The goal of this project is to provide a standard generic scoring server that provides an easy way to add and modify problems and track statistics of a Cyber Capture the Flag event. While it's not recommended, this server can be hosted with your challenges but we do recommend sand-boxing your challenges so they do not affect the scoring server.
	* [iCTF Framwork](https://github.com/ucsb-seclab/ictf-framework)
		* This is the framework that the UC Santa Barbara Seclab uses to host the iCTF, and that can be used to create your own CTFs at http://ictf.cs.ucsb.edu/framework. The framework creates several VMs: one for the organizers and one for every team. 
	* [NightShade](https://github.com/UnrealAkama/NightShade)
		* NightShade is a simple security capture the flag framework that is designed to make running your own contest as easy as possible.
	* [Mellivora](https://github.com/Nakiami/mellivora)
		* Mellivora is a CTF engine written in PHP
	* [picoCTF-Platform-2](https://github.com/picoCTF/picoCTF-Platform-2)
		* The picoCTF Platform 2 is the infrastructure on which picoCTF runs. The platform is designed to be easily adapted to other CTF or programming competitions. picoCTF Platform 2 targets Ubuntu 14.04 LTS but should work on just about any "standard" Linux distribution. It would probably even work on Windows. MongoDB must be installed; all default configurations should work.
	* [py_chall_factory](https://github.com/pdautry/py_chall_factory)
		*  Small framework to create/manage/package jeopardy CTF challenges
	* [Root the Box](https://github.com/moloch--/RootTheBox)
		* Root the Box is a real-time scoring engine for a computer wargames where hackers can practice and learn. The application can be easily modified for any hacker CTF game. Root the Box attempts to engage novice and experienced hackers alike by combining a fun game-like environment, with realistic challenges that convey knowledge applicable to real-world penetration testing. Just as in traditional CTF games, each team attacks targets of varying difficulty and sophistication, attempting to collect flags. However in Root the Box, teams can also create "Botnets" by uploading a small bot program to target machines. Teams are periodically rewarded with (in-game) money for each bot in their botnet; the larger the botnet the larger the reward.
	* [scorebot](https://github.com/legitbs/scorebot)
	* [SecGen](https://github.com/SecGen/SecGen)
		* SecGen creates vulnerable virtual machines so students can learn security penetration testing techniques.
	* [Flawed Fortress](https://github.com/rgajendran/ctf_marker)
		* Flawed Fortress is a front end platform for hosting Capture the Flag Event (CTF), it is programmed with PHP, JQuery, JavaScript and phpMyAdmin. Currently, It is designed to import SecGen CTF challenges using `marker.xml` file (which is generated in the project folder when creating a CTF Challenge)
	* [Remediate the Flag](https://github.com/sk4ddy/remediatetheflag)
		* RTF is an open source Practical Application Security Training platform that hosts application security focused exercises.
		* Candidates manually find, exploit, and manually remediate the code of a vulnerable application running in a disposable development environment accessed using a web browser. 100% hands-on training, no multiple choice questions involved.
* **Vulnerable Virtual Machines**<a name="vulnerable"></a>
	* [Vulnhub](https://www.Vulnhub.com)
	* [The Hacker Games](http://www.scriptjunkie.us/2012/04/the-hacker-games/)
		* VM Setup to practice VM breakouts/defense. Hack the VM before it hacks you!
		* [VM Download](http://www.scriptjunkie.us/files/TheHackerGames.zip)
	* [VulnInjector](https://github.com/g0tmi1k/VulnInjector)
		* Generates a 'vulnerable' machine using the end users own setup files & product keys. 
* **Wargames**<a name="wargames"></a>
	* [Ringzer0 team CTF](http://ringzer0team.com/)
		* Description: RingZer0 Team's online CTF offers you tons of challenges designed to test and improve your hacking skills thru hacking challenge. Register and get a flag for every challenges. 
	* [pwn0 Wargame](https://pwn0.com/)
		* “pwn0 is a network where (almost) anything goes. Just sign up, connect to the VPN, and start hacking. pwn0 on freenode “
	* [Microcorruption](https://microcorruption.com/login)
		* Awesome wargame.
	* [OverTheWire Wargames](http://overthewire.org/wargames/)
		* OverTheWire provides several wargames publicly/freely available. All very good quality. Highly recommended.
	* [Smash the Stack Wargames](http://smashthestack.org/)
		* Smash the stack hosts several public wargames of very good quality for free use. Highly recommended.
	* [WTHack OnlineCTF](https://onlinectf.com)
	* [IO](http://io.netgarage.org/)
	* [Pwnable.kr](http://pwnable.kr/)
	* [pwnable.tw](http://pwnable.tw/)
	* [Gracker](http://gracker.org)
	* [ROP Wargames](https://game.rop.sh/)
	* [Penetration Test 'test lab'](https://lab.pentestit.ru/)
	* [Defcon DFIR CTF 2018 Open to the Public - HackingExposed Computer Forensics](http://www.hecfblog.com/2018/08/daily-blog-451-defcon-dfir-ctf-2018.html?m=1)
	* [DFRWS IoT Forensic Challenge (2018 - 2019)](http://dfrws.org/dfrws-forensic-challenge)
* **Writeups**<a name="writeups"></a>
	* [CTF Writeups](https://github.com/ctfs/write-ups)
	* [CTF write-ups 2015](https://github.com/ctfs/write-ups-2015)
	* [CTF write-ups 2017](https://github.com/ctfs/write-ups-2017)
	* [Pwning (sometimes) with style Dragons’ notes on CTFs](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf)
	* [My CTF-Web-Challenges(orange)](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/README.md)






