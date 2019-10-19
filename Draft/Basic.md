# Basic Security Principles/Information

----------------------------------
## Table of Contents
- [101](#101)
- [How to Suck at InfoSec](#suck)
- [Getting Started with InfoSec](#getstart)
- [Being the First Security Person](#fps)
- [Careers in Information Security](#careers)
	- [Educational](#ced)
- [Cognitive Bias](#cbias)
- [Critical Thinking](#critthink)
- [Common Vulnerability Scoring System](#cvss)
- [Fundamental Papers](#fund)
- [Helping Others](#helpo)
- [Asking Better Questions](#bq)
- [Learning](#learning)
- [Normalization of Deviance](#nom)
- [Problem Solving](#ps)
- [Regular Expressions](#rex)
- [Research](#research)
- [Fun](#Fun)


* To Do:
	* Add 'Day 0' Stuff - First member of the security team


-------------------------
### General Information
* **101**<a name="101"></a>
	* [Learning the Ropes 101: Introduction - zsec.uk](https://blog.zsec.uk/101-intro/)
	* [InfoSec Newbie List by Mubix](https://gist.github.com/mubix/5737a066c8845d25721ec4bf3139fd31)
	* [infosec_getting_started](https://github.com/gradiuscypher/infosec_getting_started)
		* A collection of resources/documentation/links/etc to help people learn about Infosec and break into the field.
	* [One week of bugs - danluu.com](http://danluu.com/everything-is-broken/)
	* [I could do that in a weekend! - danluu.com](https://danluu.com/sounds-easy/)
	* [Zero-One-Infinity Rule - catb.org](http://www.catb.org/jargon/html/Z/Zero-One-Infinity-Rule.html)
	* [Every TED Talk Ever, In One Brutal Parody - FastCompany](https://www.fastcompany.com/3060820/every-ted-talk-ever-in-one-brutal-parody)
	* [Improving Infosec (or any Community/Industry) in One Simple but Mindful Step - Matt Graeber](https://medium.com/@mattifestation/improving-infosec-or-any-community-industry-in-one-simple-but-mindful-step-651e18296f9)
	* [40 Key Computer Science Concepts Explained In Layman’s Terms - carlcheo.com](http://carlcheo.com/compsci)
	* [Software Engineering Body of Knowledge (SWEBOK) - IEEE](https://www.computer.org/education/bodies-of-knowledge/software-engineering)
	* [Infra Living Standard — whatwg.org](https://infra.spec.whatwg.org/)
		* Last Updated 30 August 2019; The Infra Standard aims to define the fundamental concepts upon which standards are built.
	* [The Most Important Productivity Lesson I Ever Learned - Daniel Messler](https://danielmiessler.com/blog/the-most-important-productivity-lesson-i-ever-learned/)
* **101 Principles**
	* [Types of Authentication](http://www.gfi.com/blog/security-101-authentication-part-2/)
	* [Access control best practices](https://srlabs.de/acs/)
	* [Information Theory - Wikipedia](https://en.wikipedia.org/wiki/Information_theory)
	* [Encoding vs. Encryption vs. Hashing vs. Obfuscation - Daniel Messler](https://danielmiessler.com/study/encoding-encryption-hashing-obfuscation/)
* **How to Suck at InfoSec**<a name="suck"></a>
	* [How to Suck at Information Security – A Cheat Sheet](https://zeltser.com/suck-at-security-cheat-sheet/)
	* [How not to Infosec - Dan Tentler](https://www.youtube.com/watch?v=S5O47gemMNQ)
* **Getting Started with InfoSec**<a name="getstart"></a>
	* [Breaking Into Information Security A Modern Guide - 0xsha](https://0xsha.io/posts/breaking-into-information-security-a-modern-guide)
	* [Passwords in a file - erratasec](https://blog.erratasec.com/2019/01/passwords-in-file.html)
* **Being the First Security Person**<a name="fps"></a>
	* [Startup security: Starting a security program at a startup - Evan Johnson(AppSecCali 2019)](https://www.youtube.com/watch?v=6iNpqTZrwjE&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=20&t=0s)
		* There's no blueprint for how to be successful at a small startup. Startups are quirky, ambiguous, and full of challenges and broken processes. Startups also have a high risk tolerance and rarely introduce security from the beginning. This talk will discuss different approaches to introducing security at a company, how to be successful as a security professional at a startup, and how to integrate your security team with the rest of the company.
* **Careers in Information Security**<a name="careers"></a>
	* **Educational/Informational**<a name="ced"></a>
		* [Navigating Career Choices in InfoSec - Fernando Montenegro - BSides Detroit2017](https://www.youtube.com/watch?v=yM2xCjrQSY4)
			* Making career choices can be intimidating and stressful. Perhaps this presentation can help. The tidal forces affecting technology impact our careers as well. If we're not actively managing them, we're leaving decisions to chance (or to others), and may not like the outcomes. This presentation describes a framework I've used over the past few years to evaluate both ongoing job satisfaction as well as new opportunities as they appear. I'm happy with the outcomes I've obtained with it, and have used this same framework when providing advice to others, and it has been well received. Hopefully it can help others as well.
		* [Infosec Tools of the Trade: Getting Your Hands Dirty](http://www.irongeek.com/i.php?page=videos/bsidesnashville2017/bsides-nashville-2017-green00-infosec-tools-of-the-trade-getting-your-hands-dirty-jason-smith-and-tara-wink)
			* In this presentation we'll will be going over introductions to the various focuses in information security and demoing the most common tools that are used in operational security, both offense and defense. You'll leave with an idea on how to freely obtain and use these tools so that you can have what you need for that first interview: experience and a passion for security. This is a green talk for people who don't have a clue on what offensive and defensive people do operationally, from a tool perspective.
		* [So You Want To Be A H6x0r Getting Started in Cybersecurity Doug White and Russ Beauchemin ](https://www.youtube.com/watch?v=rRJKghTTics)
		* [Breaking Into Information Security A Modern Guide - 0xSha](https://0xsha.io/posts/breaking-into-information-security-a-modern-guide)
	* **Interview Preparation**
		* See 'Career.md'
	* **Relevant Standards**
		* [NICE Cybersecurity Workforce Framework](https://www.nist.gov/itl/applied-cybersecurity/national-initiative-cybersecurity-education-nice/nice-cybersecurity)
			* The NICE Framework, NIST Special Publication 800-181, establishes taxonomy and common lexicon that is to be used to describe all cybersecurity work and workers irrespective of where or for whom the work is performed. The NICE Framework is intended to be applied in the public, private, and academic sectors. (USA Focused)
	* **Data Scientist**
		* [What Data Scientists Really Do, According to 35 Data Scientists - HBR](https://hbr.org/2018/08/what-data-scientists-really-do-according-to-35-data-scientists?mc_cid=f8f788d39e&mc_eid=f956a0c5ca)
	* **Penetration Tester**
		* **Articles & Writeups**
			* [How to become a pentester - Corelan](https://www.corelan.be/index.php/2015/10/13/how-to-become-a-pentester/)
			* [Attacking Big Business](https://www.cyberis.co.uk/blog/attacking-big-business)	
			* [10 common mistakes aspiring/new pentesters make - PentesterLab](https://blog.pentesterlab.com/10-common-mistakes-aspiring-new-pentesters-make-b74a81e58934)
			* [So You Want To Be a Pentester? - Jack Halon](https://jhalon.github.io/becoming-a-pentester/)
			* [And THIS is Why Penetration Testing Sucks - Ronin Chang](https://www.linkedin.com/pulse/why-penetration-testing-sucks-ronin-chang/)
			* [So You Want To Be a Pentester? - Jack Halon](https://jhalon.github.io/becoming-a-pentester/)
			* [World's Worst Penetration Test Report - rant](https://it.toolbox.com/blogs/chiefmonkey/the-worlds-worst-penetration-test-report-by-scumbagpentester-012814)
			* [Make It Count: Progressing through Pentesting - Bálint Varga-Perke -Silent Signal](https://silentsignal.hu/docs/Make_It_Count_-_Progressing_through_Pentesting_Balint_Varga-Perke_Silent_Signal.pdf)
		* **Talks & Presentations**
			* [So you think you want to be a penetration tester - Defcon24](https://www.youtube.com/watch?v=be7bvZkgFmY)
				* So, you think you want to be a penetration tester, or you already are and don't understand what the difference between you and all the other "so called" penetration testers out there. Think you know the difference between a Red Team, Penetration Test and a Vulnerability assessment? Know how to write a report your clients will actually read and understand? Can you leverage the strengths of your team mates to get through tough roadblocks, migrate, pivot, pwn and pillage? No? well this talk is probably for you then! We will go through the fascinating, intense and often crazily boring on-site assessment process. Talk about planning and performing Red Teams, how they are different, and why they can be super effective and have some fun along the way. I'll tell you stories that will melt your face, brain and everything in between. Give you the answers to all of your questions you never knew you had, and probably make you question your life choices. By the end of this session you will be ready to take your next steps into the job you've always wanted, or know deep inside that you should probably look for something else. There will be no judgment or shame, only information, laughter and fun.
		* [Hold my Red Bull Undergraduate Red Teaming Jonathan Gaines](https://www.youtube.com/watch?v=9vgpqRzuvLk)
* **Cognitive Bias**<a name="cbias"></a>
	* [List of cognitive biases - Wikipedia](https://en.wikipedia.org/wiki/List_of_cognitive_biases)
	* [58 cognitive biases that screw up everything we do - Business Insider](https://www.businessinsider.com/cognitive-biases-2015-10)
* **Critical Thinking**<a name="critthink"></a>
	* [How to Apply Critical Thinking Using Paul-Elder Framework - designorate](https://www.designorate.com/critical-thinking-paul-elder-framework/)
	* [Paul-Elder Critical Thinking Framework - University of Louisville](https://louisville.edu/ideastoaction/about/criticalthinking/framework)
* **Common Vulnerability Scoring System(CVSS)**<a name="cvss"></a>
	* [Common Vulnerability Scoring System version 3.1: User Guide - first.org](https://www.first.org/cvss/user-guide)
	* [Common Vulnerability Scoring System version 3.1: Specification Document - first.org](https://www.first.org/cvss/specification-document)
* **Fundamental Papers**<a name="fund"></a>
	* [END-TO-END ARGUMENTS IN SYSTEM DESIGN - J.H. Saltzer, D.P. Reed and D.D. Clark](http://web.mit.edu/saltzer/www/publications/endtoend/endtoend.pdf)
		* This paper presents a design principle that helps guide placement of functions among the modules of a distributed computer system. The principle, called the end-to-end argument, suggests that functions placed at low levels of a system may be redundant or of little value when compared with the cost of providing them at that low level. Examples discussed in the paper include bit error recovery, security using encryption, duplicate message suppression, recovery from system crashes, and delivery acknowledgement. Low level mechanisms to support these functions are justified only as performance enhancements.
	* [Ceremony Design and Analysis - Carl Ellison](https://eprint.iacr.org/2007/399.pdf)
		* Abstract. The concept of ceremony is introduced as an extension of the concept of network protocol, with human nodes alongside computer nodes and with communication links that include UI, human-to-human communication and transfers of physical objects that carry data. What is out-of-band to a protocol is in-band to a ceremony, and therefore subject to design and analysis using variants of the same mature techniques used for the design and analysis of protocols. Ceremonies include all protocols, as well as all applications with a user interface, all workflow and all provisioning scenarios. A secure ceremony is secure against both normal attacks and social engineering. However, some secure protocols imply ceremonies that cannot be made secure.
	* [How Complex Systems Fail (Being a Short Treatise on the Nature of Failure; How Failure is Evaluated; How Failure is Attributed to Proximate Cause; and the Resulting New Understanding of Patient Safety) Richard I. Cook, MD](https://web.mit.edu/2.75/resources/random/How%20Complex%20Systems%20Fail.pdf)
	* [No Silver Bullet - fmiljang.co.uk](http://www.fmjlang.co.uk/blog/NoSilverBullet.html)
	* [A Mathematical Theory of Communication - Claude E. Shannon](http://www.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf)
	* [The Diamond Model of Intrusion Analysis - Sergio Caltagirone, Andrew Pendergast, Christopher Betz](https://apps.dtic.mil/dtic/tr/fulltext/u2/a586960.pdf)
* **General**<a name="general"></a>
	* [Mozilla Enterprise Information Security](https://infosec.mozilla.org/)
	* [Rating Infosec Relevant Masters Programs - netsecfocus](https://netsecfocus.com/training/development/certifications/2017/03/08/rating_infosec_masters.html)
	* [Salted Hash Ep 34: Red Team vs. Vulnerability Assessments - CSO Online](https://www.csoonline.com/article/3286604/security/salted-hash-ep-34-red-team-vs-vulnerability-assessments.html#tk.twt_cso)
		* Words matter. This week on Salted Hash, we talk to Phil Grimes about the differences between full Red Team engagements and vulnerability assessments
* **General Good Stuff**
	* [Words Have Meanings - Dan Tentler - CircleCityCon 2017]
	* [(Deliberate) practice makes perfect: how to become an expert in anything - Aytekin Tank](https://medium.com/swlh/deliberate-practice-makes-perfect-how-to-become-an-expert-in-anything-ec30e0c1314e)
	* [Information Security Mental Models - Chris Sanders](https://chrissanders.org/2019/05/infosec-mental-models/)
* **Helping Others**<a name="helpo"></a>
	* [Internet Safety for Teens, Kids, and Students - cooltechzone.com](https://cooltechzone.com/internet-safety-guide)
	* [STOP. THINK. CONNECT. ™ Toolkit - DHS](https://www.dhs.gov/stopthinkconnect-toolkit)
	* [What I Learned Trying To Secure Congressional Campaigns - idlewords](https://idlewords.com/2019/05/what_i_learned_trying_to_secure_congressional_campaigns.htm)
* **History**
	* [CyberInsecurity: The Cost of Monopoly - How the Dominance of Microsoft's Products Poses a Risk to Security - Daniel Geer, Charles P. Pfleeger, Bruce Schneier, John S. Quarterman, Perry Metzger, Rebecca Bace, and Peter Gutmann](https://www.schneier.com/essays/archives/2003/09/cyberinsecurity_the.html)
* **How to Ask Better Questions**<a name="bq"></a>
	* [How To Ask Questions The Smart Way - Eric Raymond](http://www.catb.org/esr/faqs/smart-questions.html)
	* [Socratic questioning - Wikipedia](https://en.wikipedia.org/wiki/Socratic_questioning)
	* [The Six Types Of Socratic Questions - umich.edu](http://www.umich.edu/~elements/probsolv/strategy/cthinking.htm)
	* [Ask Good Questions: Deep Dive - Yousef Kazerooni](https://medium.com/@YousefKazerooni/ask-good-questions-deep-dive-dacd8dddc247)
	* [Relearning the Art of Asking Questions - HBR](https://hbr.org/2015/03/relearning-the-art-of-asking-questions)
	* [How To Ask Questions The Smart Way - wiki.c2.com](http://wiki.c2.com/?HowToAskQuestionsTheSmartWay)
* **Learning:**<a name="learning"></a>
	* **101**
		* [Effective learning: Twenty rules of formulating knowledge - SuperMemo](http://super-memory.com/articles/20rules.htm)
		* [Learning How to Learn: Powerful mental tools to help you master tough subjects - Coursera](https://www.coursera.org/learn/learning-how-to-learn)
	* **Excel**
		* [You Suck at Excel with Joel Spolsky(2015)](https://www.youtube.com/watch?v=0nbkaYsR94c&feature=youtu.be)
			* The way you are using Excel causes errors, creates incomprehensible spaghetti spreadsheets, and makes me want to stab out my own eyes. Enough of the =VLOOKUPs with the C3:$F$38. You don't even know what that means.
	* [Notes](https://trello.com/b/HGITnpih/you-suck-at-excel)
	* **The Command Line**
		* [explainshell.com](https://github.com/idank/explainshell)
			* explainshell is a tool (with a web interface) capable of parsing man pages, extracting options and explain a given command-line by matching each argument to the relevant help text in the man page.
		* [A little collection of cool unix terminal/console/curses tools](https://kkovacs.eu/cool-but-obscure-unix-tools)
		* [Structured Text Tools](https://github.com/dbohdan/structured-text-tools)
			* The following is a list of text-based file formats and command line tools for manipulating each.
		* [Keyboard shortcuts in Windows - support.ms](https://support.microsoft.com/en-us/help/12445/windows-keyboard-shortcuts)
	* **New Skills**
		* [The Paradox of Choice: Learning new skills in InfoSec without getting overwhelmed - AzeriaLabs](https://azeria-labs.com/paradox-of-choice/)
* **Normalization of Deviance**<a name="nom"></a>
	* [The normalization of deviance in healthcare delivery - John Hanja](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC2821100/)
		* Many serious medical errors result from violations of recognized standards of practice. Over time, even egregious violations of standards of practice may become “normalized” in healthcare delivery systems. This article describes what leads to this normalization and explains why flagrant practice deviations can persist for years, despite the importance of the standards at issue. This article also provides recommendations to aid healthcare organizations in identifying and managing unsafe practice deviations before they become normalized and pose genuine risks to patient safety, quality care, and employee morale.
* **Problem Solving**<a name="ps"></a>
	* [Software Problem Solving Cheat Sheet - Florian Roth](https://www.nextron-systems.com/wp-content/uploads/2018/06/Software-Problem-Solving-Cheat-Sheet.pdf)
	* [The XY Problem](http://xyproblem.info/)
		* The XY problem is asking about your attempted solution rather than your actual problem. This leads to enormous amounts of wasted time and energy, both on the part of people asking for help, and on the part of those providing help.
	* [The AZ Problem](http://azproblem.info/)
		* This website introduces the AZ Problem: a generalization of the XY Problem. To wit, if we agree that the XY Problem is a problem, than the AZ Problem is a metaproblem. And while the XY Problem is often technical, the AZ Problem is procedural. The AZ Problem is when business requirements are misunderstood or decontextualized. These requirements end up being the root cause of brittle, ill-suited, or frivolous features. An AZ Problem will often give rise to several XY Problems.
* **Regular Expressions**<a name="rex"></a>
	* [Regular Expressions | A Complete Beginners Tutorial - Atmanand Nagpure](https://blog.usejournal.com/regular-expressions-a-complete-beginners-tutorial-c7327b9fd8eb)
* **Research**<a name="research"></a>
	* [Research Debt - Chris Olah, Shan Carter](https://distill.pub/2017/research-debt/)
	* [Ten Simple Rules for Doing Your Best Research, According to Hamming](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC2041981/)
* **Risk**
* **Securing yourself**
	* [Operation Luigi: How I hacked my friend without her noticing](https://www.youtube.com/watch?v=ZlNkIFipKZ4&feature=youtu.be)
	    * My friend gave me permission to "hack all her stuff" and this is my story. It's about what I tried, what worked, my many flubs, and how easy it is to compromise Non Paranoid People TM.
	    * [Blogpost](https://mango.pdf.zone/operation-luigi-how-i-hacked-my-friend-without-her-noticing)
* **Skill-Testing/Question Prep**
	* [test-your-admin-skills](https://github.com/trimstray/test-your-sysadmin-skills)
		*  A collection of \*nix Sysadmin Test Questions with Answers for Interview/Exam (2018 Edition).
* **Task Automation**
	* [WALKOFF](https://github.com/nsacyber/WALKOFF)
		* WALKOFF is a flexible, easy to use, automation framework allowing users to integrate their capabilities and devices to cut through the repetitive, tedious tasks slowing them down,
* **Testing**
	* [When to Test and How to Test It - Bruce Potter - Derbycon7](https://www.youtube.com/watch?v=Ej97WyEMRkI)
		* “I think we need a penetration test” This is one of the most misunderstood phrases in the security community. It can mean anything from “Someone should run a vulnerability scan against a box” to “I’d like nation-state capable actors to tell me everything that wrong with my enterprise” and everything in between. Security testing is a complex subject and it can be hard to understand what the best type of testing is for a given situation. This talk will examine the breadth of software security testing. From early phase unit and abuse testing to late phase penetration testing, this talk will provide details on the different tests that can be performed, what to expect from the testing, and how to select the right tests for your situation. Test coverage, work effort, attack simulation, and reporting results will be discussed. Also, this talk will provide a process for detailed product assessments, i.e.: if you’ve got a specific product you’re trying to break, how do you approach assessing the product in a way that maximizes your chance of breaking in as well as maximizing the coverage you will get from your testing activity.
* **The Web**
	* [Web Architecture 101 - Jonathan Fulton](https://engineering.videoblocks.com/web-architecture-101-a3224e126947?gi=d79a0aa34949)
* **Tools you should probably know exist**
	* [Introduction To Metasploit – The Basics](http://www.elithecomputerguy.com/2013/02/08/introduction-to-metasploit-the-basics/) 
	* [Shodan](http://www.shodanhq.com/help)
* **Fun**
	* [Welcome to Infosec (Choose your own Adventure) - primarytyler](https://docs.google.com/presentation/d/1_PjLGP28AH3HXbkwRkzGFeVPBmbBhp05mg7T6YofzRA/mobilepresent#slide=id.p)
	* [Choose Your Own Red Team Adventure - Tim Malcomvetter](https://medium.com/@malcomvetter/choose-your-own-red-team-adventure-f87d6a3b0b76)
