# Basic Security Principles/Information

----------------------------------
## Table of Contents
- [101](#101)
- [Classes/Types of Vulnerabilities](#classes)
- [How to suck at infosec](#suck)
- [Getting started with infosec](#getstart)
- [Being the First Security Person/Starting a Security Program](#fps) 
- [Scaling a Security Program](#scalingsec)
- [Building a Security Team](#buildteam)
- [Red Team, Blue Team, Purple Team, Green Team](#team)
- [Cognitive Biases](#bias)
- [Mental Models](#mm)
- [Comedy](#comedy)
- [Command Line](#cli)
- [Critical Thinking](#crittihnk)
- [Common Vulnerability Scoring System](#cvss)
- [Data Breaches](#db)
- [Fundamental Papers](#fund)
- [General Good Stuff](#general)
- [Helping Others](#helpo)
- [History](#history)
- [How to ask better questions](#bq)
- [Information Processing](#ip)
- [Learning](#learning)
- [Networking](#networking)
- [Normalization of Deviance](#nom)
- [Problem Solving](#ps)
- [Regular Expressions](#rex)
- [Research](#research)
- [Risk](#risk)
- [Securing yourself](#secself)
- [System Design](#systemdesign)
- [Task Automation](#automation)
- [The Web](#web)
- [Zero Trust](#zerotrust)



* **To Do:**
	* Make things better


-------------------------
### General Information
* **101**<a name="101"></a>
	* **General**
		* [Security Engineering (3rd ed) - Ross Anderson](https://www.cl.cam.ac.uk/~rja14/book.html)
		* [10 Immutable Laws of Security Administration - Scott Culp(docs.ms)](https://docs.microsoft.com/en-us/previous-versions//cc722488(v=technet.10)?redirectedfrom=MSDN)
		* [Learning the Ropes 101: Introduction - zsec.uk](https://blog.zsec.uk/101-intro/)
		* [InfoSec Newbie List by Mubix](https://gist.github.com/mubix/5737a066c8845d25721ec4bf3139fd31)
		* [infosec_getting_started](https://github.com/gradiuscypher/infosec_getting_started)
			* A collection of resources/documentation/links/etc to help people learn about Infosec and break into the field.
		* [Brandolini's Law - Wikipedia](https://en.wikipedia.org/wiki/Brandolini%27s_law)
			* Brandolini's law, also known as the bullshit asymmetry principle, is an internet adage which emphasizes the difficulty of debunking bullshit: "The amount of energy needed to refute bullshit is an order of magnitude bigger than to produce it."
	* **Computer Science**
		* [40 Key Computer Science Concepts Explained In Layman’s Terms - carlcheo.com](http://carlcheo.com/compsci)
		* [Software Engineering Body of Knowledge (SWEBOK) - IEEE](https://www.computer.org/education/bodies-of-knowledge/software-engineering)
		* [Infra Living Standard — whatwg.org](https://infra.spec.whatwg.org/)
			* Last Updated 30 August 2019; The Infra Standard aims to define the fundamental concepts upon which standards are built.
	* **Mentality**
		* [One week of bugs - danluu.com](http://danluu.com/everything-is-broken/)
		* [I could do that in a weekend! - danluu.com](https://danluu.com/sounds-easy/)
		* [Zero-One-Infinity Rule - catb.org](http://www.catb.org/jargon/html/Z/Zero-One-Infinity-Rule.html)
		* [Improving Infosec (or any Community/Industry) in One Simple but Mindful Step - Matt Graeber](https://medium.com/@mattifestation/improving-infosec-or-any-community-industry-in-one-simple-but-mindful-step-651e18296f9)
		* [Tacit Knowledge](https://en.wikipedia.org/wiki/Tacit_knowledge)
			* Tacit knowledge or implicit knowledge (as opposed to formal, codified or explicit knowledge) is the kind of knowledge that is difficult to transfer to another person by means of writing it down or verbalizing it. For example, that London is in the United Kingdom is a piece of explicit knowledge that can be written down, transmitted, and understood by a recipient. However, the ability to speak a language, ride a bicycle, knead dough, play a musical instrument, or design and use complex equipment requires all sorts of knowledge which is not always known explicitly, even by expert practitioners, and which is difficult or impossible to explicitly transfer to other people.
	* **Things**
		* [Every TED Talk Ever, In One Brutal Parody - FastCompany](https://www.fastcompany.com/3060820/every-ted-talk-ever-in-one-brutal-parody)
		* [The Most Important Productivity Lesson I Ever Learned - Daniel Messler](https://danielmiessler.com/blog/the-most-important-productivity-lesson-i-ever-learned/)
		* [How to exit Vim](https://github.com/hakluke/how-to-exit-vim)
	* **Videos**
		* [Every Security Team is a Software Team Now - Dino Dai Zovi(Black Hat USA 2019 Keynote)](https://www.youtube.com/watch?list=PLH15HpR5qRsWrfkjwFSI256x1u2Zy49VI&v=8armE3Wz0jk)
			* As software is eating the world, every company is becoming a software company. This doesn’t mean that every company is shipping software products, it means that services and products in every field are becoming increasingly driven, powered, and differentiated by software. Let’s explore what that will do to how cybersecurity is practiced in enterprises of all types. Peter Drucker famously said that “Culture eats strategy for breakfast.” There have been two large cultural shifts in software engineering over the last 20 years that created the successful strategies behind how software is eating the world. First, there was Agile (2001). In response to the inefficiencies of classic “waterfall” software development, Agile focused on breaking down the barriers between software requirements, development, and testing by having software development teams own their roadmaps as well as their quality. Separate product management organizations evolved into product owners working directly with the software team. Similarly, separate quality assurance organizations evolved into a focus on building quality into the software development process. This should remind us of how we talk about needing to build security in, but most importantly, this change was effected by software teams themselves vs. forced onto them by a separate security organization. There is a lesson to be learned there. Next came DevOps (2009), which brought the agile mindset to server operations. Software teams now began to own their deployment and their uptime. Treating software teams as the end-user and customer has driven the replacement of traditional ops with the cloud and replacing the traditional stack with serverless models. Ops teams evolved into software teams that provide platforms, tools, and self-service infrastructure to internal teams. They provide value by increasing internal teams’ productivity while reducing costs to the entire organization through economies of scale and other efficiencies. When a cross-functional team owns their features, their quality, their deployment, and their uptime, they fully own their end-to-end value stream. Next, they will evolve to also own their own risks and fully own their end-to-end impact. There are two big shifts involved as teams begin to own their end-to-end impact: software teams need to own their own security now and security teams need to become full-stack software teams. Just as separate product management and quality assurance organizations diffused into cross-functional software teams, security must now do the same. At his re:Invent 2018 Keynote, Amazon’s CTO Werner Vogels proclaimed that “security is everyone’s job now, not just the security team’s.” But if security is every teams’ job, what is the security team’s job? Just like how classic ops teams became internal infrastructure software teams, security teams will become internal security software teams that deliver value to internal teams through self-service platforms and tools. Security teams that adopt this approach will reduce the risk to the organization the most while also minimizing impact to overall productivity. In this talk, we’ll explore how this is already being done across high-performing companies and how to foster this security transformation at yours.
		* [Real Software Engineering - Glenn Vanderburg(Software Art Thou)](https://www.youtube.com/watch?v=RhdlBHHimeM)
			* The idea is spreading that perhaps software development is simply incompatible with engineering; that software developers are not, and never will be, real engineers. Glenn Vanderburg, VP of Engineering at First, takes a fresh look at what that really should mean for this field. With an extra 45 years of experience about the task of programming, and a broad survey of the varied different engineering disciplines, can we envision a future for a field of “software engineering” that is worthy of the name?
		* [Real Software Engineering by Glenn Vanderburg(Lone Star Ruby Conference(2010)](https://www.youtube.com/watch?v=NP9AIUT9nos&feature=youtu.be)
			* Software engineering as it's taught in universities simply doesn't work. It doesn't produce software systems of high quality, and it doesn't produce them for low cost. Sometimes, even when practiced rigorously, it doesn't produce systems at all.  That's odd, because in every other field, the term "engineering" is reserved for methods that work.  What then, does real software engineering look like? How can we consistently deliver high-quality systems to our customers and employers in a timely fashion and for a reasonable cost? In this session, we'll discuss where software engineering went wrong, and build the case that disciplined Agile methods, far from being "anti-engineering" (as they are often described), actually represent the best of engineering principles applied to the task of software development.
		* [Software Security Field Guide for the Bewildered - zwischenzugs](https://zwischenzugs.com/2019/09/22/software-security-field-guide-for-the-bewildered/)
* **101 Principles**
	* [Akin's Laws of Spacecraft Design - David L. Akin](https://spacecraft.ssl.umd.edu/akins_laws.html)
	* [Types of Authentication](http://www.gfi.com/blog/security-101-authentication-part-2/)
	* [Access control best practices](https://srlabs.de/acs/)
	* [Information Theory - Wikipedia](https://en.wikipedia.org/wiki/Information_theory)
	* [Encoding vs. Encryption vs. Hashing vs. Obfuscation - Daniel Messler](https://danielmiessler.com/study/encoding-encryption-hashing-obfuscation/)
	* [Safety with Dignity Booklist - Sidney Dekker](http://sidneydekker.com/books/)
	* [10 Immutable Laws of Security (Microsoft TechNet) Non-original](https://www.wciapool.org/pdf/Tab_5_10_Immutable_LawsofSecurity.pdf)
	* [Ten Immutable Laws Of Security (Version 2.0) - docs.ms](https://docs.microsoft.com/en-us/archive/blogs/rhalbheer/ten-immutable-laws-of-security-version-2-0)
	* [You Can’t Do Everything: The Importance of Prioritization in Security - RecordedFuture](https://www.recordedfuture.com/vulnerability-threat-prioritization/)
* **Classes/Types of Vulnerabilities**<a name="classes"></a>
	* [MITRE Common Attack Pattern Enumeration and Classification(CAPEC)](https://capec.mitre.org)
	* [Race Condition Exploits - Prabhaker Mateti](https://web1.cs.wright.edu/~pmateti/InternetSecurity/Lectures/RaceConditions/index.html)
* **How to Suck at InfoSec**<a name="suck"></a>
	* [How to Suck at Information Security – A Cheat Sheet](https://zeltser.com/suck-at-security-cheat-sheet/)
	* [How not to Infosec - Dan Tentler](https://www.youtube.com/watch?v=S5O47gemMNQ)
* **Getting Started with InfoSec**<a name="getstart"></a>
	* [infosec_newbie.md - mubix](https://gist.github.com/mubix/5737a066c8845d25721ec4bf3139fd31)
		* List of links on getting started in InfoSec/Starting a career.
	* [Breaking Into Information Security A Modern Guide - 0xsha](https://0xsha.io/posts/breaking-into-information-security-a-modern-guide)
	* [Passwords in a file - erratasec](https://blog.erratasec.com/2019/01/passwords-in-file.html)
* **Being the First Security Person/Starting a Security Program/Growing it**<a name="fps"></a>
	* **101**
		* Asset Inventory
		* Baseline Hardening
		* Developer Training/Secure Coding Training
		* File Integrity Monitoring
		* Firewall
		* Logging
		* Mobile Device Management
		* Monitoring
		* Patch Management
		* Policies
		* User Security Awareness Training
		* Vendor Management
		* Vulnerability Management
	* **Articles/Blogposts/Writeups**
		* [Starting Up Security - Ryan McGeehan](https://scrty.io/)
			* A collection of information security essays and links to help growing teams manage risks.
		* [A comprehensive guide to security for startups - David Cowan](https://www.bvp.com/atlas/security-for-startups)
		* [How Early-Stage Startups Can Enlist The Right Amount of Security As They Grow - firstround.com](https://firstround.com/review/how-early-stage-startups-can-enlist-the-right-amount-of-security-as-they-grow/)
		* [Starting Up Security - Ryan McGeehan](https://medium.com/starting-up-security/starting-up-security-87839ab21bae)
		* [Killing “Chicken Little”: Measure and eliminate risk through forecasting. - Ryan McGeehan](https://medium.com/starting-up-security/killing-chicken-little-measure-and-eliminate-risk-through-forecasting-ecdf4c7e9575)
		* [OWASP Security Champions Playbook](https://wiki.owasp.org/index.php/Security_Champions_Playbook)
		* [A bug goes skateboarding on Boehm’s Curve - Ulf Eriksson(2013)](https://reqtest.com/general/a-bug-goes-skateboarding-on-boehms-curve/)
	* **Talks/Presentations/Videos**
		* [Pushing left like a boss - Tanya Janca(DevSecCon Singapore2018)](https://www.youtube.com/watch?v=8kqtrX6C10c&feature=youtu.be)
			* With incident response and penetration testing currently receiving most of our application security dollars, it would appear that industry has decided to treat the symptom instead of the disease. “Pushing left” refers to starting security earlier in the SDLC; addressing the problem throughout the process. From scanning your code with a vulnerability scanner to red team exercises, developer education programs and bug bounties, this talk will show you how to ‘push left’, like a boss.
		* [Starting Strength for AppSec - Fredrick Lee(OWASP AppSec Cali2019)](https://www.youtube.com/watch?v=kGt3pVDloy0&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=5)
			* [Slides](https://static.sched.com/hosted_files/appseccalifornia2019/17/AppSecCali2019-StartingStrengthForAppSec.pdf)
		* [Startup security: Starting a security program at a startup - Evan Johnson(OWASP AppSecCali 2019)](https://www.youtube.com/watch?v=6iNpqTZrwjE&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=19)
			* There's no blueprint for how to be successful at a small startup. Startups are quirky, ambiguous, and full of challenges and broken processes. Startups also have a high risk tolerance and rarely introduce security from the beginning. This talk will discuss different approaches to introducing security at a company, how to be successful as a security professional at a startup, and how to integrate your security team with the rest of the company.
		* [Twubhubbook: Like an Appsec Program, but for Startups - Brent Johnson, Neil Matatall(OWASP AppSec CA 2017)](https://www.youtube.com/watch?v=JEE7wXHa1kY&feature=youtu.be)
			* Simulated walk through of two 'security' contractors being brought on to establish security within a 'startup'. Good talk.
		* [We Come Bearing Gifts: Enabling Product Security with Culture and Cloud - Astha Singhal, Patrick Thomas(OWASP AppSec Cali2018)](https://www.youtube.com/watch?v=L1WaMzN4dhY&feature=youtu.be)
			* This talk explores that counter-intuitive premise, and shows how it is not just possible but *necessary* to discard many traditional security behaviors in order to support modern high-velocity, cloud-centric engineering teams. For the product security team at Netflix, this is the logical implication of a cultural commitment to enabling the organization. Attendees will learn how to replace heavy-handed gating with an automation-first approach, and build powerful security capabilities on top of cloud deployment primitives. Specific examples including provable application identity, immutable and continuous deployment, and secret bootstrapping illustrate how this approach balances security impact with engineering enablement.
		* [starting an AppSec Program: An Honest Retrospective - John Melton](https://www.youtube.com/watch?v=ETkHISgEh3g&feature=youtu.be)
			* This talk will cover the lessons learned from a 2-year journey starting an appsec program at a small-medium sized company that previously had no security program. This will be an honest look at what worked, what didn't work, as well as a follow-up analysis. There will be plenty of stories, common sense perspective, as well as discussion around goal-setting and execution. This will be the talk I wish I had two years ago when I was starting this adventure.
		* [Startup security: Starting a security program at a startup - Evan Johnson(AppSecCali 2019)](https://www.youtube.com/watch?v=6iNpqTZrwjE&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=20&t=0s)
			* There's no blueprint for how to be successful at a small startup. Startups are quirky, ambiguous, and full of challenges and broken processes. Startups also have a high risk tolerance and rarely introduce security from the beginning. This talk will discuss different approaches to introducing security at a company, how to be successful as a security professional at a startup, and how to integrate your security team with the rest of the company.
		* [Jumpstarting Your Appsec Program - Julia Knecht & Jacob Lords(BSidesSLC 2020)](https://www.youtube.com/watch?v=Wgob-wbQ26w&list=PLqVzh0_XpLfSJ2Okt38acDdO_xu2zKYmK&index=17&t=0s)
		* [Building a Modern Security Engineering Organization - Zane Lackey(OWASP AppSec California2015](https://www.youtube.com/watch?v=aJ-RGaCiDSM)
			* Continuous deployment and the DevOps philosophy have forever changed the ways in which businesses operate. This talk with discuss how security adapts effectively to these changes, specifically covering: Practical advice for building and scaling modern AppSec and NetSec programs; Lessons learned for organizations seeking to launch a bug bounty program; How to run realistic attack simulations and learn the signals of compromise in your environment
		* [Where do I start The first 365 days of building a security program - Hudson Bush(ShellCon2018)](https://www.youtube.com/watch?v=uO7ybTOb5OE&list=PL7D3STHEa66TbZwq9w3S2qWzoJeNo3YYN&index=15)
			* Scenario: You've been put in charge of InfoSec for a business with no existing security posture and the executive team thinks that Antivirus and Firewall is a sufficient InfoSec budget. They expect results in one year. If you're thinking '`Oh $(*7, I have to do what?'`, this talk is for you. At the end of this talk you will have a roadmap for the first year of implementing a security program, with some understanding of what those who have come before you have done. I hope to explain my mistakes so that you don't have to make mine; you can make your own.
		* [Working with Developers for Fun and Progress - Leif Dreizler(OWASP AppSec Cali2019)](https://www.youtube.com/watch?v=ltXYbIacHr8&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=17)
			* Forging a strong relationship with developers is essential part of creating an impactful AppSec program. Without it, your team will have little idea what's going on and will have trouble getting bugs fixed and features shipped. Segment has built strong ties to developers using our competition-based training featuring Burp Suite and OWASP Juice Shop, partnership during implementation of tooling, and contributions to the existing codebase. This presentation is chock full of practical examples and references that attendees can bring back to their organization.
* **Scaling a Security Program**<a name="scalingsec"></a>
	* **101**
		* [How to 10X Your Company’s Security (Without a Series D) - Clint Gibler(BSidesSF2020)](https://www.youtube.com/watch?v=tWA_EBNsQH8&feature=emb_title)
			* [Slides](https://docs.google.com/presentation/d/1lfEvXtw5RTj3JmXwSQDXy8or87_BHrFbo1ZtQQlHbq0/mobilepresent?slide=id.g6555b225cd_0_1069)
			* I’ll summarize and distill the insights, unique tips and tricks, and actionable lessons learned from a vast number of DevSecOps/modern AppSec talks and blog posts, saving attendees 100s of hours. I’ll show where we’ve been, where we’re going, and provide a lengthy bibliography for further review.
	* **Articles/Blogposts/Writeups**
		* [Scaling Appsec at Netflix - Astha Singhal](https://medium.com/@NetflixTechBlog/scaling-appsec-at-netflix-6a13d7ab6043)
		* [Building analysts from the ground up - Jack Crook](https://findingbad.blogspot.com/2016/09/building-analysts-from-ground-up.html)
	* **Talks/Presentations/Videos**
		* [DevSecOps State of the Union - Clint Gibler(BSidesSF 2019)](https://www.youtube.com/watch?v=AusPKzwNnMg)
			* Many companies have shared their lessons learned in scaling their security efforts, leading to hundreds of blog posts and conference talks. Sharing knowledge is fantastic, but when you're a busy AppSec engineer or manager struggling to keep up with day-to-day requirements, it can be difficult to stay on top of or even be aware of relevant research. This talk will summarize and distill the unique tips and tricks, lessons learned, and tools discussed in a vast number of blog posts and conference talks over the past few years and combine it with knowledge gained from in-person discussions with AppSec engineers at a number of companies with mature security teams. Topics covered will include: Principles, mindsets, and methodologies of highly effective AppSec teams, Best practices in developing security champions and building a positive security culture, High value engineering projects that can prevent classes of bugs, How and where to integrate security automation into the CI/CD process in a high signal, low noise way, Open source tools that help with one or more of the above. Attendees will leave this talk with an understanding of the current state of the art in DevSecOps, links to tools they can use, resources where they can dive into specific topics of interest, and most importantly an actionable path forward for taking their security program to the next level.
		* [Efforts in Scaling Application Security Programs - Eric Fay(ShellCon2018)](https://www.youtube.com/watch?v=YNHqDGL0goo&list=PL7D3STHEa66TbZwq9w3S2qWzoJeNo3YYN&index=10)
			* With organizational success comes the exciting period of ever-increasing scale and scope. This talk will cover some of the past and current efforts that Eric personally took on while creating and scaling the application security program at Hulu. A retrospective look will be taken at the focus points, tradeoffs and decisions made by the application security team while keeping up with the growth and continued success of Hulu.
		* [Scale your security with DevSecOps: 4 valuable mindsets and principles - Clint Gibler(2019)](https://techbeacon.com/devops/how-scale-security-devsecops-4-valuable-mindsets-principles)
		* [A​ Pragmatic Approach for Internal Security Partnerships - Scott Behrens, Esha Kanekar(OWASP AppSecCali 2019)](https://www.youtube.com/watch?v=HIdexRqjpWc&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=22)
			* Why do we have such a hard time getting engineering teams to care about vulnerabilities? How is it that we are fixing lots of vulnerabilities, yet are still falling ever further behind on the actual risks? These questions both have the same answer, but getting to it requires empathy, trust, courage, and a giant step back from our day-to-day approach to security. In this talk we will share our experiences about creating proactive partnerships with engineering and product teams. From the ways we have seen this fail to recent success stories, we will illustrate specific practices that help developers and security teams focus and align on a shared view of risk, rather than a laundry list of vulnerabilities: the leverage that comes from enabling rather than gating, automating for visibility and action to manage scale, threat modeling across organizations rather than individual applications, and the particulars of how we get big security features onto busy product teams' roadmaps.
		* [Efforts in Scaling Application Security Programs - Eric Fay(ShellCon2018)](https://www.youtube.com/watch?v=YNHqDGL0goo&list=PL7D3STHEa66TbZwq9w3S2qWzoJeNo3YYN&index=10)
			* With organizational success comes the exciting period of ever-increasing scale and scope. This talk will cover some of the past and current efforts that Eric personally took on while creating and scaling the application security program at Hulu. A retrospective look will be taken at the focus points, tradeoffs and decisions made by the application security team while keeping up with the growth and continued success of Hulu.
		* [Year[0]: AppSec at a Startup - Leif Dreizler(LASCON2019)](https://www.youtube.com/watch?v=ImJqBX0OXew&app=desktop)
			* Have you wanted to be on the application security team at a startup, but were worried about having an employer that can’t figure out how to monetize its user base, being compensated in potentially worthless stock options, or discovering your company’s business model is based on selling a $400 juicer and expensive juice packets that could actually be squeezed by hand? If so, then this talk is for you! From the safety of the audience you’ll hear about the first year of an appsec program at a tech startup. We’ll cover how to win over the hearts and minds of your developers, useful tooling/automation, and other topics to rapidly improve the security of a growing SaaS startup.
		* [(in)Secure Development - Why some product teams are great and others … aren’t... - Koen Hendrix(AppSecCali 2019)](https://www.youtube.com/watch?v=-bZM_48Ghv0&t=0s&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=25)
			* In this presentation, Koen will share his experiences with Product Teams at Riot Games and how those teams do or do not take security into consideration. Every product team is unique; but they all behave in similar security patterns, and care about security in predictable ways. Using metrics of our Bug Bounty program and security review process, we’ll dissect the impact that team culture and process have on the security posture of a product. The framework that we’ve created allows you to quickly see what makes a good team good, and how other teams can improve. Taking into account how agile organisations want to operate, we will look at some tools you can introduce into your product teams to help raise the security bar.
		* [The Call is Coming From Inside the House: Lessons in Securing Internal Apps - Hongyi Hu(OWASP AppSec Cali 2019)](https://www.youtube.com/watch?v=c9A8v5hiqoA&t=0s&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=28)
			* Come hear a dramatic and humorous tale of internal appsec and the technical and management lessons we learned along the way. Even if your focus is on securing external apps, this talk will be relevant for you. You’ll hear about what worked well for us and what didn’t, including: Finding a useful mental model to organize your roadmap; Starting with the basics: authn/z, TLS, etc.; Rolling out Content Security Policy; Using SameSite cookies as a powerful entry point regulation mechanism; Leveraging WAFs for useful detection and response; Using internal apps as a training ground for new security engineers
		* [Jumpstarting Your Appsec Program - Julia Knecht & Jacob Lords(BSidesSLC 2020)](https://www.youtube.com/watch?v=Wgob-wbQ26w&list=PLqVzh0_XpLfSJ2Okt38acDdO_xu2zKYmK&index=17&t=0s)
* **Building a Security Team**<a name="buildteam"></a>
	* [How to Build a Security Team and Program - Coleen Coolidge(BSidesSF2017)](https://www.youtube.com/watch?v=b0r5vc_eCoU&feature=youtu.be)
* **Red Team, Blue Team, Purple Team, Green Team**<a name='team'></a>
	* See [RedTeam Page](./RT.md)
	* [The Difference Between Red, Blue, and Purple Teams - Daniel Miessler](https://danielmiessler.com/study/red-blue-purple-teams/)
	* [Red Teams - Ryan McGeehan(2015)](https://medium.com/starting-up-security/red-teams-6faa8d95f602)
	* **Purple Teaming**
		* [Purple Teaming: The Pen-Test Grows Up - Bryce Galbraith](https://www.sans.org/webcasts/purple-teaming-pen-test-grows-111630)
			* This webcast will cover: Why your annual pen-test is a recipe for disaster, and what you can do about it.; Why many Red and Blue Teams are ineffective despite their efforts, and how to turn this around.; Several real-world TTPs that adversaries utilize (including demos) to completely dominate organizations, shockingly fast.; How to begin to perform adversary emulation and Purple Teaming.; Several helpful tools and resources you can begin to explore immediately...; As Einstein wisely stated, Insanity is doing the same thing over and over again and expecting different results. There is a better way...
		* [Purple Team Exposed](https://www.youtube.com/watch?v=Mkh5cSnunrI&list=PL7D3STHEa66TbZwq9w3S2qWzoJeNo3YYN&index=13)
			* Are you looking to rapidly improve your security posture or train a new member of your security organization? Are you a Blue Team member looking to cross train with Red Team or vice versa? Purple Teaming could be the answer to your problems. You may have already heard about Purple Teaming through a spare think piece online, casual mentions or even rage tweets, but few know what makes a Purple Team. In this talk I will cover how to build your own Purple Team function from the ground up using applied gap analysis, creating meaningful test cases, modifying tools, cross-training possibilities, and automation frameworks. We'll walk through the methodology together so you leave with the tools and experience you need to do it yourself. If implemented, this can give you a better knowledge of your security baseline, improvements in defenses, opportunities for internal training and mentorship, and an increased dialogue between Red and Blue.
	* **Having a Pentest Performed**
		* [Red Team Assessment and Penetration Testing - Manga Sridhar Akella](https://www.yash.com/blog/red-team-assessment-and-penetration-testing/)
		* [Pen Tests and Red Teams are NOT the same - Carole Theriault](https://tbgsecurity.com/pen-tests-and-red-teams-are-not-the-same/)
		* [Putting your security assessment budget on a leash while avoiding the Pentest Puppy Mill - John Strand, Paul Asadoorian(2013)](https://www.sans.org/webcasts/putting-security-assessment-budget-leash-avoiding-pentest-puppy-mill-96927)
			* The goal of a penetration test should be to elevate your security, not line the pocket of the pentester. In this webcast, Paul and John discuss ways to structure your pentest so that you aren't paying for shells from a Pentest Puppy Mill, but instead paying for reproducible results that will provide a baseline for future testing.
	* **Measuring Results of a Red Team/Pentest**
		* [Measuring a red team or penetration test. - Ryan McGeehan](https://medium.com/starting-up-security/measuring-a-red-team-or-penetration-test-44ea373e5089)
		* [A Red Team Maturity Model - redteams.fyi](https://redteams.fyi/)
* **Cognitive Bias**<a name="cbias"></a>
	* [List of cognitive biases - Wikipedia](https://en.wikipedia.org/wiki/List_of_cognitive_biases)
	* [58 cognitive biases that screw up everything we do - Business Insider](https://www.businessinsider.com/cognitive-biases-2015-10)
	* [Mental Models: The Best Way to Make Intelligent Decisions (109 Models Explained) - Farnam Street](https://fs.blog/mental-models/)
	* [Spotlight effect - Wikipedia](https://en.wikipedia.org/wiki/Spotlight_effect)
	* [Curse of knowledge - Wikipedia](https://en.wikipedia.org/wiki/Curse_of_knowledge)
		* The curse of knowledge is a cognitive bias that occurs when an individual, communicating with other individuals, unknowingly assumes that the others have the background to understand. This bias is also called by some authors the curse of expertise, although that term is also used to refer to various other phenomena.
* **Mental Models**<a name="mm"></a>
	* [The Map Is Not the Territory - Farnam Street](https://fs.blog/2015/11/map-and-territory/)
		* The map of reality is not reality. Even the best maps are imperfect. That’s because they are reductions of what they represent. If a map were to represent the territory with perfect fidelity, it would no longer be a reduction and thus would no longer be useful to us. A map can also be a snapshot of a point in time, representing something that no longer exists. This is important to keep in mind as we think through problems and make better decisions.
	* [Coastline paradox - Wikipedia](https://en.wikipedia.org/wiki/Coastline_paradox)
		* The coastline paradox is the counterintuitive observation that the coastline of a landmass does not have a well-defined length. This results from the fractal curve-like properties of coastlines, i.e., the fact that a coastline typically has a fractal dimension (which in fact makes the notion of length inapplicable).
	* [Information Security Mental Models - Chris Sanders](https://chrissanders.org/2019/05/infosec-mental-models/)
* **Comedy**<a name="comedy"></a>
	* [The Website is Down #1: Sales Guy vs. Web Dude](https://www.youtube.com/watch?v=uRGljemfwUE)
	* [BOFH Index](https://bearbin.net/bofh)
		* This is a collection of links to most of the BOFH stories from 2000 to 2016 (For BOFH episodes from before 2000, please see the [Official Archive)](https://web.archive.org/web/20160106082840/http://bofh.ntk.net/BOFH/index.php).
	* [Microservices](https://www.youtube.com/watch?v=y8OnoxKotPQ&app=desktop)
		* Satire or documentary.
* **Command Line**<a name="cli"><</a>
	* **Linux/MacOS**
		* **Articles/Resources**
			* **Bash**
				* [Bash Guide for Beginners - tldp.org](http://tldp.org/LDP/Bash-Beginners-Guide/html/Bash-Beginners-Guide.html)
					* The Bash Guide for Beginners gets you started with Bash scripting and bridges the gap between the Bash HOWTO and the Advanced Bash Scripting Guide. Everybody who wants to make life easier on themselves, power users and sysadmins alike, can benefit from reading this practical course. The guide contains lots of examples and exercises at the end of each chapter, demonstrating the theory and helping you practice. Bash is available on a wide variety of UNIX, Linux, MS Windows and other systems.
				* [The BashGuide](https://mywiki.wooledge.org/BashGuide)
					* This guide aims to aid people interested in learning to work with BASH. It aspires to teach good practice techniques for using BASH, and writing simple scripts. This guide is targeted at beginning users. It assumes no advanced knowledge -- just the ability to login to a Unix-like system and open a command-line (terminal) interface. It will help if you know how to use a text editor; we will not be covering editors, nor do we endorse any particular editor choice. Familiarity with the fundamental Unix tool set, or with other programming languages or programming concepts, is not required, but those who have such knowledge may understand some of the examples more quickly.
				* [Bash Pitfalls - wooledge.org](https://mywiki.wooledge.org/BashPitfalls)
			* **`*`grep**
				* [learn_gnugrep_ripgrep](https://github.com/learnbyexample/learn_gnugrep_ripgrep)
					* Example based guide to mastering GNU grep and ripgrep
			* **SSH**
				* [Secure Shell - Wikipedia](https://en.wikipedia.org/wiki/Secure_Shell)
					* Secure Shell (SSH) is a cryptographic network protocol for operating network services securely over an unsecured network. Typical applications include remote command-line, login, and remote command execution, but any network service can be secured with SSH.
				* [OpenSSH](https://www.openssh.com/)
				* [SSH -debian.org](https://wiki.debian.org/SSH)
			* **tmux & screen**
				* **tmux**
					* [tmux](https://github.com/tmux/tmux)
						* tmux is a terminal multiplexer: it enables a number of terminals to be created, accessed, and controlled from a single screen. tmux may be detached from a screen and continue running in the background, then later reattached.
					* [Getting Started - tmux](https://github.com/tmux/tmux/wiki/Getting-Started)
					* [tmux manpage](http://man.openbsd.org/OpenBSD-current/man1/tmux.1)
					* [A Quick and Easy Guide to tmux - Ham Vocke](https://www.hamvocke.com/blog/a-quick-and-easy-guide-to-tmux/)
					* [tmux plugin manager](https://github.com/tmux-plugins/tpm)
						* Installs and loads tmux plugins.
					* [Introduction to tmux - ippsec](https://www.youtube.com/watch?v=Lqehvpe_djs)
					* [.tmux - oh my tmux!](https://github.com/gpakosz/.tmux)
						* Self-contained, pretty and versatile .tmux.conf configuration file.
				* **Screen**
					* [GNU Screen - gnu.org](https://www.gnu.org/software/screen/)
						* Screen is a full-screen window manager that multiplexes a physical terminal between several processes, typically interactive shells. Each virtual terminal provides the functions of the DEC VT100 terminal and, in addition, several control functions from the ANSI X3.64 (ISO 6429) and ISO 2022 standards (e.g., insert/delete line and support for multiple character sets). There is a scrollback history buffer for each virtual terminal and a copy-and-paste mechanism that allows the user to move text regions between windows. When screen is called, it creates a single window with a shell in it (or the specified command) and then gets out of your way so that you can use the program as you normally would. Then, at any time, you can create new (full-screen) windows with other programs in them (including more shells), kill the current window, view a list of the active windows, turn output logging on and off, copy text between windows, view the scrollback history, switch between windows, etc. All windows run their programs completely independent of each other. Programs continue to run when their window is currently not visible and even when the whole screen session is detached from the users terminal.
					* [Screen User’s Manual - gnu.org](https://www.gnu.org/software/screen/manual/html_node/index.html)
			* **General**
				* [Bandit - OvertheWire](https://overthewire.org/wargames/bandit/)
					* "The Bandit wargame is aimed at absolute beginners. It will teach the basics needed to be able to play other wargames."; It's also an effective way to learn the basics of linux and how to use the linux cli.
				* [The art of the command line](https://github.com/jlevy/the-art-of-command-line)
					* Master the command line, in one page
				* [Stupid Unix Tricks - Jeffrey Paul](https://sneak.berlin/20191011/stupid-unix-tricks/)
				* [Why Learn AWK? - Jonathan Palardy](https://blog.jpalardy.com/posts/why-learn-awk/)
				* [Applying Your Linux Skills to macOS: Terminal BASH and Common Commands - Jason Eckert](https://www.comptia.org/blog/applying-your-linux-skills-to-macos-terminal-bash-and-common-commands)
				* [Linux Command Line](https://github.com/learnbyexample/Linux_command_line)
					* Introduction to Linux commands and Shell scripting
				* [Linux Productivity Tools](https://code.ornl.gov/km0/lisa19)
					* Highly recommend.
				* [Don Libes' Expect: A Surprisingly Underappreciated Unix Automation Tool - Robert Elder](https://blog.robertelder.org/don-libes-expect-unix-automation-tool/)
				* [mastering-zsh](https://github.com/rothgar/mastering-zsh)
			* **Videos**
				* [Linux Command Line Dojo with Hal Pomeranz(BHIS 2020)](https://www.youtube.com/watch?v=-jNkjuWMFrk)
					* In this webcast, we have our friend Hal Pomeranz sharing his massive knowledge on Linux. If you’re new to Linux, or if you know it and just want to hear from Hal’s years of using and teaching all things Linux, then this is the webcast for you. 
					* [Part 2](https://www.youtube.com/watch?v=dtyX7XO-GSg&list=RDCMUCJ2U9Dq9NckqHMbcUupgF0A&index=2)
			* **Tools**
				* [explainshell.com](https://github.com/idank/explainshell)
					* explainshell is a tool (with a web interface) capable of parsing man pages, extracting options and explain a given command-line by matching each argument to the relevant help text in the man page.
				* [A little collection of cool unix terminal/console/curses tools](https://kkovacs.eu/cool-but-obscure-unix-tools)
				* [Pexpect](https://github.com/pexpect/pexpect)
					* Pexpect is a Pure Python Expect-like module
				* [Chepy](https://github.com/securisec/chepy)
					* Chepy is a python lib/cli equivalent of the awesome CyberChef tool.
	* **Windows**
		* **Articles/Resources**		
			* [Keyboard shortcuts in Windows - support.ms](https://support.microsoft.com/en-us/help/12445/windows-keyboard-shortcuts)
		* **Tools**
			* [Chocolatey](https://chocolatey.org/)
				* "The Package Manager for Windows."
* **Critical Thinking**<a name="critthink"></a>
	* [How to Apply Critical Thinking Using Paul-Elder Framework - designorate](https://www.designorate.com/critical-thinking-paul-elder-framework/)
	* [Paul-Elder Critical Thinking Framework - University of Louisville](https://louisville.edu/ideastoaction/about/criticalthinking/framework)
* **Common Vulnerability Scoring System(CVSS)**<a name="cvss"></a>
	* [Common Vulnerability Scoring System version 3.1: User Guide - first.org](https://www.first.org/cvss/user-guide)
	* [Common Vulnerability Scoring System version 3.1: Specification Document - first.org](https://www.first.org/cvss/specification-document)
* **Data Breaches**
	* [SecurityBreach](https://github.com/ericalexanderorg/SecurityBreach)
		* Crowdsourced catalog of security breaches.
* **Fundamental Papers**<a name="fund"></a>
	* [END-TO-END ARGUMENTS IN SYSTEM DESIGN - J.H. Saltzer, D.P. Reed and D.D. Clark](http://web.mit.edu/saltzer/www/publications/endtoend/endtoend.pdf)
		* This paper presents a design principle that helps guide placement of functions among the modules of a distributed computer system. The principle, called the end-to-end argument, suggests that functions placed at low levels of a system may be redundant or of little value when compared with the cost of providing them at that low level. Examples discussed in the paper include bit error recovery, security using encryption, duplicate message suppression, recovery from system crashes, and delivery acknowledgement. Low level mechanisms to support these functions are justified only as performance enhancements.
	* [Ceremony Design and Analysis - Carl Ellison](https://eprint.iacr.org/2007/399.pdf)
		* Abstract. The concept of ceremony is introduced as an extension of the concept of network protocol, with human nodes alongside computer nodes and with communication links that include UI, human-to-human communication and transfers of physical objects that carry data. What is out-of-band to a protocol is in-band to a ceremony, and therefore subject to design and analysis using variants of the same mature techniques used for the design and analysis of protocols. Ceremonies include all protocols, as well as all applications with a user interface, all workflow and all provisioning scenarios. A secure ceremony is secure against both normal attacks and social engineering. However, some secure protocols imply ceremonies that cannot be made secure.
	* [How Complex Systems Fail (Being a Short Treatise on the Nature of Failure; How Failure is Evaluated; How Failure is Attributed to Proximate Cause; and the Resulting New Understanding of Patient Safety) Richard I. Cook, MD](https://web.mit.edu/2.75/resources/random/How%20Complex%20Systems%20Fail.pdf)
	* [No Silver Bullet - fmiljang.co.uk](http://www.fmjlang.co.uk/blog/NoSilverBullet.html)
	* [A Mathematical Theory of Communication - Claude E. Shannon](http://www.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf)
	* [The Diamond Model of Intrusion Analysis - Sergio Caltagirone, Andrew Pendergast, Christopher Betz](https://apps.dtic.mil/dtic/tr/fulltext/u2/a586960.pdf)
	* **Beyond Corp**
		* [BeyondCorp](https://cloud.google.com/beyondcorp/)
		* [How Google Adopted BeyondCorp](https://security.googleblog.com/2019/06/how-google-adopted-beyondcorp.html)
			* [Part 2](https://security.googleblog.com/2019/08/how-google-adopted-beyondcorp-part-2.html)
			* [Part 3](https://security.googleblog.com/2019/09/how-google-adopted-beyondcorp-part-3.html)
			* [Part 4](https://security.googleblog.com/2019/10/how-google-adopted-beyondcorp-part-4.html)
		* [BeyondCorp: A New Approach to Enterprise Security - Rory Ward, Betsy Beyer](https://research.google/pubs/pub43231/)
			* Virtually every company today uses firewalls to enforce perimeter security. However, this security model is problematic because, when that perimeter is breached, an attacker has relatively easy access to a company’s privileged intranet. As companies adopt mobile and cloud technologies, the perimeter is becoming increasingly difficult to enforce. Google is taking a different approach to network security. We are removing the requirement for a privileged intranet and moving our corporate applications to the Internet.
* **General**<a name="general"></a>
	* [Mozilla Enterprise Information Security](https://infosec.mozilla.org/)
	* [Rating Infosec Relevant Masters Programs - netsecfocus](https://netsecfocus.com/training/development/certifications/2017/03/08/rating_infosec_masters.html)
	* [Salted Hash Ep 34: Red Team vs. Vulnerability Assessments - CSO Online](https://www.csoonline.com/article/3286604/security/salted-hash-ep-34-red-team-vs-vulnerability-assessments.html#tk.twt_cso)
		* Words matter. This week on Salted Hash, we talk to Phil Grimes about the differences between full Red Team engagements and vulnerability assessments
* **General Good Stuff**
	* [C2 Wiki - Security](http://wiki.c2.com/?CategorySecurity)
	* [Not Even Close, The State of Computer Security w/ slides - James Mickens](https://www.youtube.com/watch?v=tF24WHumvIc)
	* [Words Have Meanings - Dan Tentler - CircleCityCon 2017]
	* [(Deliberate) practice makes perfect: how to become an expert in anything - Aytekin Tank](https://medium.com/swlh/deliberate-practice-makes-perfect-how-to-become-an-expert-in-anything-ec30e0c1314e)
	* [Information Security Mental Models - Chris Sanders](https://chrissanders.org/2019/05/infosec-mental-models/)
	* [The Submarine (Article)- Paul Graham](http://paulgraham.com/submarine.html)
	* [Satya Nadella ‘Reads’/‘Games’ Hacker News - KicksCondor](https://www.kickscondor.com/satya-nadella-'reads''games'-hacker-news/)
	* [Unintendedconsequenc.es](https://unintendedconsequenc.es)
	* [Art as a Methodology for Security Research - Leigh-Anne Galloway](https://leigh-annegalloway.com/art-as-a-methodology-for-security-research/)
	* [The Natural Life Cycle of Mailing Lists - Kat Nagel](http://users.rider.edu/~suler/psycyber/lifelist.html)
* **Helping Others**<a name="helpo"></a>
	* [Internet Safety for Teens, Kids, and Students - cooltechzone.com](https://cooltechzone.com/internet-safety-guide)
	* [STOP. THINK. CONNECT. ™ Toolkit - DHS](https://www.dhs.gov/stopthinkconnect-toolkit)
	* [What I Learned Trying To Secure Congressional Campaigns - idlewords](https://idlewords.com/2019/05/what_i_learned_trying_to_secure_congressional_campaigns.htm)
* **History** <a name="history"></a>
	* [Collections: The Siege of Gondor, Part II: These Beacons are Liiiiiiit - Bret Devereaux](https://acoup.blog/2019/05/17/collections-the-siege-of-gondor-part-ii-these-beacons-are-liiiiiiit/)
		* Defense in depth aint new
	* [CyberInsecurity: The Cost of Monopoly - How the Dominance of Microsoft's Products Poses a Risk to Security - Daniel Geer, Charles P. Pfleeger, Bruce Schneier, John S. Quarterman, Perry Metzger, Rebecca Bace, and Peter Gutmann](https://www.schneier.com/essays/archives/2003/09/cyberinsecurity_the.html)
	* [Ford Pinto - Engineering.com](https://www.engineering.com/Library/ArticlesPage/tabid/85/ArticleID/166/Ford-Pinto.aspx)
	* [A Case Study of Toyota Unintended Acceleration and Software Safety - Phil Koopman](https://users.ece.cmu.edu/~koopman/pubs/koopman14_toyota_ua_slides.pdf)
	* [The Hacker Crackdown - Wikipedia](https://en.wikipedia.org/wiki/The_Hacker_Crackdown)
		* The book discusses watershed events in the hacker subculture in the early 1990s. The most notable topic covered is Operation Sundevil and the events surrounding the 1987–1990 war on the Legion of Doom network: the raid on Steve Jackson Games, the trial of "Knight Lightning" (one of the original journalists of Phrack), and the subsequent formation of the Electronic Frontier Foundation. The book also profiles the likes of "Emmanuel Goldstein" (publisher of 2600: The Hacker Quarterly), the former assistant attorney general of Arizona Gail Thackeray, FLETC instructor Carlton Fitzpatrick, Mitch Kapor, and John Perry Barlow.
	* [The Hacker Crackdown: Law and Disorder on the Electronic Frontier by Bruce Sterling - Project Gutenberg](https://www.gutenberg.org/ebooks/101)
* **How to Ask Better Questions**<a name="bq"></a>
	* [How To Ask Questions The Smart Way - Eric Raymond](http://www.catb.org/esr/faqs/smart-questions.html)
	* [Socratic questioning - Wikipedia](https://en.wikipedia.org/wiki/Socratic_questioning)
	* [The Six Types Of Socratic Questions - umich.edu](http://www.umich.edu/~elements/probsolv/strategy/cthinking.htm)
	* [Ask Good Questions: Deep Dive - Yousef Kazerooni](https://medium.com/@YousefKazerooni/ask-good-questions-deep-dive-dacd8dddc247)
	* [Relearning the Art of Asking Questions - HBR](https://hbr.org/2015/03/relearning-the-art-of-asking-questions)
	* [How To Ask Questions The Smart Way - wiki.c2.com](http://wiki.c2.com/?HowToAskQuestionsTheSmartWay)
* **Information Processing**<a name="ip"></a>
	* [Drinking from the Fire Hose: Making Smarter Decisions Without Drowning in Information - Book](https://paradoxesinc.com/portfolio/5104/)
	* [How to make sense of any mess - Abby Covert](https://www.youtube.com/watch?v=r10Sod44rME)
* **Learning:**<a name="learning"></a>
	* **101**
		* [Effective learning: Twenty rules of formulating knowledge - SuperMemo](http://super-memory.com/articles/20rules.htm)
		* [Learning How to Learn: Powerful mental tools to help you master tough subjects - Coursera](https://www.coursera.org/learn/learning-how-to-learn)
		* [Double-loop Learning - Wikipedia](https://en.wikipedia.org/wiki/Double-loop_learning)
			* Double-loop learning entails the modification of goals or decision-making rules in the light of experience. The first loop uses the goals or decision-making rules, the second loop enables their modification, hence "double-loop". Double-loop learning recognises that the way a problem is defined and solved can be a source of the problem. This type of learning can be useful in organizational learning since it can drive creativity and innovation, going beyond adapting to change to anticipating or being ahead of change.
		* [The Motivation Secret: How to Maintain Intense Motivation as a Hacker (or Anything) - Luke Stephens](https://medium.com/@hakluke/the-motivation-secret-how-to-maintain-intense-motivation-as-a-hacker-43d8876cc86c)
		* [Deliberate Practice: What It Is and How to Use It - James Clear](https://jamesclear.com/deliberate-practice-theory)
		* [Continuous Skills Improvement For Everyone - Matt Scheurer(OISF19)](https://www.youtube.com/watch?time_continue=1&v=Se-qPMIfLRI&feature=emb_title)
		* [The Importance Of Deep Work & The 30-Hour Method For Learning A New Skill - Azeria](https://azeria-labs.com/the-importance-of-deep-work-the-30-hour-method-for-learning-a-new-skill/)
		* [The idea of a difficulty curve is all wrong - David Strachan](http://www.davetech.co.uk/difficultycurves)
		* [How to Read a Book, v5.0 - Paul N. Edwards University of Michigan](http://pne.people.si.umich.edu/PDF/howtoread.pdf)
		* [How to Read a Book - Wikipedia](https://en.wikipedia.org/wiki/How_to_Read_a_Book)
	* **Excel**
		* [You Suck at Excel with Joel Spolsky(2015)](https://www.youtube.com/watch?v=0nbkaYsR94c&feature=youtu.be)
			* The way you are using Excel causes errors, creates incomprehensible spaghetti spreadsheets, and makes me want to stab out my own eyes. Enough of the =VLOOKUPs with the C3:$F$38. You don't even know what that means.
			* [Notes](https://trello.com/b/HGITnpih/you-suck-at-excel)
	* **Agnostic Tools**	
		* [Structured Text Tools](https://github.com/dbohdan/structured-text-tools)
			* The following is a list of text-based file formats and command line tools for manipulating each.
	* **Videos**
		* [jumpcutter](https://github.com/carykh/jumpcutter)
			* Automatically edits vidx. [Explanation here](https://www.youtube.com/watch?v=DQ8orIurGxw)
		* [Auto-Editor](https://github.com/WyattBlue/auto-editor)
			* Auto-Editor is a video editing tool that can automatically edit raw source video into a entertaining and polished video. It works by analyzing the video's audio to detect when a section needs to be cut, kept in, or zoomed in, then auto-editor runs a subprocess called ffmpeg to create the new video.
		* [cut-the-crap](https://github.com/jappeace/cut-the-crap)
			* Cut the crap is an automatic video editing program for streamers. It can cut out uninteresting parts by detecting silences. This was inspired by jumpcutter, where this program can get better quality results by using an (optional) dedicated microphone track. This prevents cutting of quieter consonants for example. Using ffmpeg more efficiently also produces faster results and is less error prone.
	* **Learning New Things**
		* [The Paradox of Choice: Learning new skills in InfoSec without getting overwhelmed - AzeriaLabs](https://azeria-labs.com/paradox-of-choice/)
* **Metrics**<a name="metrics"></a>
	* [Be Careful What You Measure - Mark Graham Brown](https://corporater.com/en/the-chicken-kpi-be-careful-of-what-you-measure/)
	* [How to Use Metrics - George K. Campbell(2006)](https://www.csoonline.com/article/2120344/how-to-use-metrics.html)
	* [Security metric techniques: How to answer the 'so what?' - Bill Brenner](https://www.csoonline.com/article/2125789/security-metric-techniques--how-to-answer-the--so-what--.html)
	* [Security Value Made Visible: How American Water's Bruce Larson uses a simple metric to build bridges with business partners and justify security spending at the same time - Scott Berinato](https://www.csoonline.com/article/2120656/security-value-made-visible.html)
	* [A key performance indicator for infosec organizations: Using probabilistic risk KPIs to direct complex risk engineering efforts - Ryan McGeehan(2019)](https://medium.com/starting-up-security/a-key-performance-indicator-for-infosec-organizations-7f654b7cd256)
* **Networking**<a name="networking"></a>
	* [The Bits and Bytes of Computer Networking - Google/Coursera](https://www.coursera.org/learn/computer-networking)
		* This course is designed to provide a full overview of computer networking. We’ll cover everything from the fundamentals of modern networking technologies and protocols to an overview of the cloud to practical applications and network troubleshooting. By the end of this course, you’ll be able to: describe computer networks in terms of a five-layer model; understand all of the standard protocols involved with TCP/IP communications; grasp powerful network troubleshooting tools and techniques; learn network services like DNS and DHCP that help make computer networks run; understand cloud computing, everything as a service, and cloud storage
	* [Linux Network Administration - gnulinux.guru](https://gnulinux.guru/?Networking)
		* One(really long) page reference
	* [IPv4/v6 Subnet Mask cheatsheet - kthx.at](https://kthx.at/subnetmask/)
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
* **Risk**<a name="risk"></a>
	* **FAIR**
		* [Factor analysis of information risk - Wikipedia](https://en.wikipedia.org/wiki/Factor_analysis_of_information_risk)
			* Factor Analysis of Information Risk (FAIR) is a taxonomy of the factors that contribute to risk and how they affect each other. It is primarily concerned with establishing accurate probabilities for the frequency and magnitude of data loss events. It is not a methodology for performing an enterprise (or individual) risk assessment.
* **Securing yourself**<a name="secself"></a>
	* [Operation Luigi: How I hacked my friend without her noticing](https://www.youtube.com/watch?v=ZlNkIFipKZ4&feature=youtu.be)
	    * My friend gave me permission to "hack all her stuff" and this is my story. It's about what I tried, what worked, my many flubs, and how easy it is to compromise Non Paranoid People TM.
	    * [Blogpost](https://mango.pdf.zone/operation-luigi-how-i-hacked-my-friend-without-her-noticing)
* **Software Testing**<a name="softwaretesting"></a>
	* [When to Test and How to Test It - Bruce Potter - Derbycon7](https://www.youtube.com/watch?v=Ej97WyEMRkI)
		* “I think we need a penetration test” This is one of the most misunderstood phrases in the security community. It can mean anything from “Someone should run a vulnerability scan against a box” to “I’d like nation-state capable actors to tell me everything that wrong with my enterprise” and everything in between. Security testing is a complex subject and it can be hard to understand what the best type of testing is for a given situation. This talk will examine the breadth of software security testing. From early phase unit and abuse testing to late phase penetration testing, this talk will provide details on the different tests that can be performed, what to expect from the testing, and how to select the right tests for your situation. Test coverage, work effort, attack simulation, and reporting results will be discussed. Also, this talk will provide a process for detailed product assessments, i.e.: if you’ve got a specific product you’re trying to break, how do you approach assessing the product in a way that maximizes your chance of breaking in as well as maximizing the coverage you will get from your testing activity.
* **System Design**<a name="systemdesign"></a>
	* [The System Design Primer](https://github.com/donnemartin/system-design-primer)
		* Learning how to design scalable systems will help you become a better engineer. System design is a broad topic. There is a vast amount of resources scattered throughout the web on system design principles. This repo is an organized collection of resources to help you learn how to build systems at scale.
* **Task Automation**<a name="automation"></a>
	* [WALKOFF](https://github.com/nsacyber/WALKOFF)
		* WALKOFF is a flexible, easy to use, automation framework allowing users to integrate their capabilities and devices to cut through the repetitive, tedious tasks slowing them down,
	* [StackStorm](https://stackstorm.com/)
* **Vendor Security**<a name="vensec"></a>
	* [UC Berkely Vendor Security Assessment Program](https://security.berkeley.edu/services/vendor-security-assessment-program/details-vendor-security-assessment-program)
	* [VSAQ: Vendor Security Assessment Questionnaire](https://github.com/google/vsaq)
		* VSAQ is an interactive questionnaire application. Its initial purpose was to support security reviews by facilitating not only the collection of information, but also the redisplay of collected data in templated form. At Google, questionnaires like the ones in this repository are used to assess the security programs of third parties. But the templates provided can be used for a variety of purposes, including doing a self-assessment of your own security program, or simply becoming familiar with issues affecting the security of web applications.
* **The Web**<a name='web'></a>
	* [Web Architecture 101 - Jonathan Fulton](https://engineering.videoblocks.com/web-architecture-101-a3224e126947?gi=d79a0aa34949)
	* [The Tangled Web - Michal Zalewski(book)](https://lcamtuf.coredump.cx/tangled/)
		* "The Tangled Web is my second book, a lovingly crafted guide to the world of browser security. It enters an overcrowded market, but there are two reasons why you may want to care. First of all, where other books simply dispense old and tired advice on remediating common vulnerabilities, The Tangled Web offers a detailed and thoroughly enjoyable account of both the "how" and the "why" of the modern web. In doing so, it enables you to deal with the seedy underbelly of contemporary, incredibly complex web apps. The other reason is that it is based on years of original research - including, of course, my Browser Security Handbook (2008). I think it is simply unmatched when it comes to the breadth and the quality of the material presented. It outlines dozens of obscure but remarkably important security policies, governing everything from content rendering to frame navigation - and affecting your applications in more ways than you may expect."
	* **Tools**
		* [Firefox Developer Tools - MDN](https://developer.mozilla.org/en-US/docs/Tools)
			* Firefox Developer Tools is a set of web developer tools built into Firefox. You can use them to examine, edit, and debug HTML, CSS, and JavaScript. This section contains detailed guides to all of the tools as well as information on how to debug Firefox for Android, how to extend DevTools, and how to debug the browser as a whole.
		* [Chrome DevTools - developers.google](https://developers.google.com/web/tools/chrome-devtools)
		* [Discover DevTools](https://www.codeschool.com/courses/discover-devtools)
			* Learn how Chrome DevTools can sharpen your dev process and discover the tools that can optimize your workflow and make life easier.
* **Zero Trust**<a name="zerotrust"></a>
	* **Articles/Blogposts/Writeups**
		* [Exploring The Zero Trust Model - securethelogs.com](https://securethelogs.com/2019/06/25/exploring-the-zero-trust-model/)
		* [Awesome Zero trust](https://github.com/pomerium/awesome-zero-trust/blob/master/README.md)
	* **Talks/Presentations/Videos**
* **Tools you should probably know exist**
	* [Introduction To Metasploit – The Basics](http://www.elithecomputerguy.com/2013/02/08/introduction-to-metasploit-the-basics/) 
	* [Shodan](http://www.shodanhq.com/help)
	* [agrep - tool](https://linux.die.net/man/1/agrep)
		* print lines approximately matching a pattern
* **Fun**
	* [Welcome to Infosec (Choose your own Adventure) - primarytyler](https://docs.google.com/presentation/d/1_PjLGP28AH3HXbkwRkzGFeVPBmbBhp05mg7T6YofzRA/mobilepresent#slide=id.p)
	* [Choose Your Own Red Team Adventure - Tim Malcomvetter](https://medium.com/@malcomvetter/choose-your-own-red-team-adventure-f87d6a3b0b76)
