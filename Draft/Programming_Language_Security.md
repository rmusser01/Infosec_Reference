# Programming Language Courses/References/Security (AppSec)

## Table of Contents
- [General](#general)
- [Secure Development Patterns/Practices/Resources](#securedev)
    - [Application Logging & Monitoring](#logmon)
    - [AppSec Stuff](#appsec)
    - [Code-Repo Related](#crepo)
    - [Code Review](#code-review)
    - [Secure/Software/Systems Development Life Cycle(SDLC/SDL)](#sdlc)
    - [Software Testing](#stest)
    - [Supply-Chain Management](#supply)
    - [Threat Modeling](#threatm)
    - [Specific Vulnerabilitiy Mitigation/Prevention](#specvuln)
      - [Comparison Operations](#compops)
      - [Cryptographic Issues](#crypto)
      - [Input Validation](#inputval)
      - [Race Conditions/ToCToU Bugs](#toctou)
      - [Account Enumeration](#ace)
      - [Secure File Upload](#sfu)
      - [SQL Injection](#sqli)
- [Source Code Analysis](#sca)
    - [Non-Specific](#nonspec)
    - [Specific Languages](#spec)
    - [Infrastructure-as-Code Scanners & Linters](#iaac)
- [Application Security Pipeline](#appsecpipeline)
    - [Continous Integration](#ci)
    - [Continous Deployment](#cd)
    - [CI/CD Scanning Tooling/Approaches](#cdscan)
    - [(DIY) Building an AppSec Pipeline](#cddiy)
    - [Static Analysis Approaches & Tooling](#static)
    - [Dynamic Analysis - Continuous Scanning](#dynscan)
    - [Dependency Management](#depmgmt)
    - [Metrics](#metrics)
    - [Automated Response](#auto)
- [Programming](#programming)
  - [APIs](#apis)
  - [Assembly x86/x64/ARM](#asm)
  - [Android (Kotlin/Android Java)](#android)
  - [Bash](#bash)
  - [C/C++](#c)
  - [C#](#c#)
  - [Go](#go)
  - [Java](#java)
  - [Javascript](#javascript)
  - [Lisp](#lisp)
  - [Lua](#lua)
  - [Perl](#perl)
  - [Powershell](#power)
  - [PHP](#php)
  - [Python](#python)
  - [Ruby](#ruby)
  - [Rust](#rust)
  - [SQL](#sql)
  - [Swift](#swift)
  - [UEFI Programming](#uefi)

## General <a name="general"></a>
* The content here is just stuff I've come across or think would be useful to someone in infosec. It is not to be taken as anything beyond a suggestion about stuff.
* **Articles/Blogposts/Writeups**
	* [How To Write Unmaintainable Code - Roedy Green](https://github.com/Droogans/unmaintainable-code)
	* [A Taxonomy of Tech Debt - Bill Clark(Riot Games)](https://technology.riotgames.com/news/taxonomy-tech-debt)
	* [Software Engineering Body of Knowledge - Wikipedia](https://en.wikipedia.org/wiki/Software_Engineering_Body_of_Knowledge)
* **Talks/Presentations/Videos**
	* [What We Actually Know About Software Development, and Why We Believe It’s True - Greg Wilson(2010)](https://vimeo.com/9270320)
	* [Old Is the New New • Kevlin Henney(GOTO2018)](https://www.youtube.com/watch?v=AbgsfeGvg3E)
		* [Slides](https://gotochgo.com/2018/sessions/371/slides)
		*  Everything is changing. Everything is new. Frameworks, platforms and trends are displaced on a weekly basis. Skills are churning.  And yet... Beneath this seemingly turbulent flow there is a slow current, strong and steady, changing relatively little over the decades. Concepts with a long history appear in new forms and fads and technologies. Principles are revisited. Ideas once lost to the mainstream are found again.  In this keynote we revisit the present through the past, looking at the enduring principles that shape programming languages, architecture, development practice and development process, the ideas that cycle round, each time becoming perhaps a little better defined, a little more mature, and look to see what else might be on the horizon.
	* [Practical tips for defending web  applications in the age of agile/DevOps - Zane Lackey](https://www.youtube.com/watch?v=Hmu21p9ybWs)
		* [Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Lackey-Practical%20Tips-for-Defending-Web-Applications-in-the-Age-of-DevOps.pdf)
	* [How to 10X Your Company’s Security (Without a Series D) - Clint Gibler(BSidesSF2020)](https://www.youtube.com/watch?v=tWA_EBNsQH8&feature=emb_title)
		* [Slides](https://docs.google.com/presentation/d/1lfEvXtw5RTj3JmXwSQDXy8or87_BHrFbo1ZtQQlHbq0/mobilepresent?slide=id.g6555b225cd_0_1069)
		* I’ll summarize and distill the insights, unique tips and tricks, and actionable lessons learned from a vast number of DevSecOps/modern AppSec talks and blog posts, saving attendees 100s of hours. I’ll show where we’ve been, where we’re going, and provide a lengthy bibliography for further review.
* **Educational**
	* [App Ideas - Stuff to build out ot improve your programming skills](https://github.com/tastejs/awesome-app-ideas)
	* [How to be a Programmer: Community Version](https://github.com/braydie/HowToBeAProgrammer)
		* To be a good programmer is difficult and noble. The hardest part of making real a collective vision of a software project is dealing with one's coworkers and customers. Writing computer programs is important and takes great intelligence and skill. But it is really child's play compared to everything else that a good programmer must do to make a software system that succeeds for both the customer and myriad colleagues for whom he or she is partially responsible. In this essay I attempt to summarize as concisely as possible those things that I wish someone had explained to me when I was twenty-one.
	* [Learn_X_in_Y_Minutes](http://learnxinyminutes.com/)
	* [Hyperpolyglot](http://hyperpolyglot.org/)
	* [Android's billion-dollar mistake(s) - Jean-Michel Fayard ](https://web.archive.org/web/20190930114632/https://dev.to/jmfayard/android-s-billion-dollar-mistake-327b)
	* [Security Training for Engineers - PagerDuty](https://sudo.pagerduty.com/for_engineers/)
* **Dev Environment**
	* [gitignore](https://github.com/github/gitignore)
		* This is GitHub’s collection of .gitignore file templates. We use this list to populate the .gitignore template choosers available in the GitHub.com interface when creating new repositories and files.
* **Bugs**
	* [A bug goes skateboarding on Boehm’s Curve - Ulf Eriksson(2013)](https://reqtest.com/general/a-bug-goes-skateboarding-on-boehms-curve/)


## Secure Development Patterns/Practices/Resources <a name="securedev"></a>
* **General**
	* **Articles/Papers/Talks/Writeups**
		* [Counterfeit Object-oriented Programming](http://syssec.rub.de/media/emma/veroeffentlichungen/2015/03/28/COOP-Oakland15.pdf)
		* [OWASP Developer Guide Reboot](https://github.com/OWASP/DevGuide)
		* [Microsoft Software Development Lifecycle Process Guidance](https://msdn.microsoft.com/en-us/library/windows/desktop/cc307406.aspx)
		* [Security Guide for Developers](https://github.com/FallibleInc/security-guide-for-developers)
		* [Who Fixes That Bug? - Part One: Them! - Ryan McGeehan](https://medium.com/starting-up-security/who-fixes-that-bug-d44f9a7939f2)
			* [Part 2](https://medium.com/starting-up-security/who-fixes-that-bug-f17d48443e21)
	* **Talks/Presentations/Videos**
* **Application Logging & Monitoring** <a name="logmon"></a>
* **AppSec Stuff** <a name="appsec"></a>
	* **Articles/Blogposts/Writeups**
		* [Application Security in a DevOps Environment - Lyft](https://eng.lyft.com/application-security-in-a-devops-environment-53092f8a6048)
		* [Designing Security for Billions - Facebook](https://newsroom.fb.com/news/2019/01/designing-security-for-billions/)
		* [Abuser Stories: A Sneak Peak For Scrum Teams - Abhay Bhargav(2018)](https://www.we45.com/blog/abuser-stories-a-sneak-peak-for-scrum-teams)
		* [Pushing Left, Like a Boss: Table of Contents - Tanya Janca(2018)](https://medium.com/bugbountywriteup/pushing-left-like-a-boss-table-of-contents-42fd063a75bb)
			* "The following is a table of contents for my modern-day book, based off of a talk I wrote in 2016 entitled “Pushing Left, Like a Boss”. It serves as a foundational lesson on what “Application Security” is, and how to get started. I hope you find the series helpful."
		* [What I Learned Watching All 44 AppSec Cali 2019 Talks - Clint Gibler](https://tldrsec.com/blog/appsec-cali-2019/)
	* **Talks/Presentations/Videos**
		* [The AppSec Starter Kit - Timothy De Block(BSides Detroit 2017)](https://www.youtube.com/watch?v=KMz8lWNAUmg)
			* Security teams are starting to get more involved in the development life cycle. What tools are going to be introduced to the SDLC? What strategy is the security team going to use? This talk will provide an introduction to the tools and strategies security teams are using to improve security in the SDLC. We will walk through dynamic and static analyzers. Their strengths and weaknesses. The Open Web Applications Security Project (OWASP). It’s vast resources for learning more about security. We will look at OWASP Pipeline. How it can help with automating security in a DevOps environment. Learn about the names providing excellent appsec content. This talk is for developers who want to know about security and the tools being integrated into the development life cycle.
		* [AppSec: From the OWASP Top Ten(s) to the OWASP ASVS - Jim Manico(GOTO Chicago 2019)](https://www.youtube.com/watch?v=nvzMN5Z8DJI&feature=youtu.be&list=PLEx5khR4g7PLIxNHQ5Ze0Mz6sAXA8vSPE)
			* This talk will review the OWASP Top Ten 2017 and the OWASP Top Ten Proactive Controls 2018 and compare them to a more comprehensive standard: the OWASP Application Security Verification Standard (ASVS) v4.0. OWASP's ASVS contains over 180 requirements that can provide a basis for defining what secure software really is. The OWASP ASVS can be used to help test technical security controls of web and API applications. It can also be used to provide developers with a list of requirements for secure development with much more nuance and detail than a top ten list! You cannot base a security program off a Top Ten list. You can base an Application Security program off of the OWASP ASVS.
		* [Modeling and Discovering Vulnerabilities with Code Property Graphs - Fabian Yamaguchi, Nico Golde, Daniel Arp, Konrad Rieck(2014)](https://ieeexplore.ieee.org/ielx7/6954656/6956545/06956589.pdf?tp=&arnumber=6956589&isnumber=6956545)
			* The vast majority of security breaches encountered today are a direct result of insecure code. Consequently, the protection of computer systems critically depends on the rigorous identification of vulnerabilities in software, a tedious and errorprone process requiring significant expertise. Unfortunately, a single flaw suffices to undermine the security of a system and thus the sheer amount of code to audit plays into the attacker’s cards. In this paper, we present a method to effectively mine large amounts of source code for vulnerabilities. To this end, we introduce a novel representation of source code called a code property graph that merges concepts of classic program analysis, namely abstract syntax trees, control flow graphs and program dependence graphs, into a joint data structure. This comprehensive representation enables us to elegantly model templates for common vulnerabilities with graph traversals that, for instance, can identify buffer overflows, integer overflows, format string vulnerabilities, or memory disclosures. We implement our approach using a popular graph database and demonstrate its efficacy by identifying 18 previously unknown vulnerabilities in the source code of the Linux kernel.
		* [Pushing Left Like A Boss - Tanya Janca](https://www.youtube.com/watch?v=Q5Nt8VhXg-0)
			* With incident response and penetration testing currently receiving most of our application security dollars, it would appear that industry has decided to treat the symptom instead of the disease. 'Pushing left' refers to starting security earlier in the SDLC; addressing the problem throughout the process, and specifically during the development phase. From scanning your code with a vulnerability scanner to red team exercises, developer education programs and bug bounties, this talk will show you how to 'push left', like a boss. This talk is aimed at developers, operations, dev-ops, people who are new to application security, managers, or anyone who works in any other field of security than AppSec.
* **Code-Repo Related** <a name="crepo"></a>
	* **Articles/Blogposts/Writeups**
		* [Why Google Stores Billions of Lines of Code in a Single Repository - Rachel Potvin, Josh Levenberg(2016)](https://cacm.acm.org/magazines/2016/7/204032-why-google-stores-billions-of-lines-of-code-in-a-single-repository/fulltext)
	* **Repo Software**
		* [Concurrent Versions System (CVS)](https://www.nongnu.org/cvs/)
		* [Subversion (SVN)](https://subversion.apache.org/)
			* Subversion is an open source version control system. Founded in 2000 by CollabNet, Inc., the Subversion project and software have seen incredible success over the past decade. Subversion has enjoyed and continues to enjoy widespread adoption in both the open source arena and the corporate world.
		* [Git](https://git-scm.com/)
			* Git is a free and open source distributed version control system designed to handle everything from small to very large projects with speed and efficiency.
			* See also: Gitea, Gogs, Gitolite, Gitlab
	* **Code Search**
		* [Sourcegraph](https://about.sourcegraph.com/)
* **Code Review** <a name="code-review"></a>
	* **101**
		* [Code Reviews: Just Do It - Jeff Atwood](https://blog.codinghorror.com/code-reviews-just-do-it/)
		* [On Code Reviews - Nick Shrock(2018)](https://medium.com/@schrockn/on-code-reviews-b1c7c94d868c)
		* [How to do a code review - Google](https://google.github.io/eng-practices/review/reviewer/)
		* [How I review code - cyle(Tumblr Engineering 2018)](https://engineering.tumblr.com/post/170040992289/how-i-review-code)
		* [8 Tips for Great Code Reviews - Kelley Sutton(2018)](https://kellysutton.com/2018/10/08/8-tips-for-great-code-reviews.html)
		* [Code Review Guidelines for Humans - Philipp Hauer(2019](https://phauer.com/2018/code-review-guidelines/)
		* [Effective Code Reviews Without the Pain - Robert Bogue(2006)](https://www.developer.com/tech/article.php/3579756/Effective-Code-Reviews-Without-the-Pain.htm)
		* [Code Review: Create The Culture, Learn The Best Practices - Gabor Zold](https://codingsans.com/blog/code-review)
		* [Code Review Best Practices - Palantir](https://medium.com/palantir/code-review-best-practices-19e02780015f)
	* **Avoiding Code-Fatigue**
		* [Ship Small Diffs - Dan McKinley(2017)](https://blog.skyliner.io/ship-small-diffs-741308bec0d1)
		* [Stacked Pull Requests: Keeping GitHub Diffs Small](https://graysonkoonce.com/stacked-pull-requests-keeping-github-diffs-small/)
		* Avoiding Code Review Fatigue
	* **Culture**
		* [Designing Awesome Code Reviews - Brian Lee(2017)](https://medium.com/unpacking-trunk-club/designing-awesome-code-reviews-5a0d9cd867e3)
		* [Why I changed the way I think about Code Quality - John Cobb](https://medium.freecodecamp.org/why-i-changed-the-way-i-think-about-code-quality-88c5d8d57e68)
		* [Pull Requests: How to Get and Give Good Feedback - Kickstarter(2015)](https://kickstarter.engineering/pull-requests-how-to-get-and-give-good-feedback-f573469f0c44)
		* [Towards Productive Technical Discussions - @catehstn(2018)](https://cate.blog/2018/07/03/towards-productive-technical-discussions/)
		* [Unlearning Toxic Behaviors in a Code Review Culture - Sandya Sankarram(2018)](https://www.youtube.com/watch?v=QIUwGa-MttQ)
			* [Slides](https://speakerdeck.com/sandyaaaa/unlearning-toxic-behaviors-in-a-code-review-culture)
			* [Blogpost](https://medium.com/@sandya.sankarram/unlearning-toxic-behaviors-in-a-code-review-culture-b7c295452a3c)
		* [Code Review Etiquette - Jeff Wainwright(2017)](https://css-tricks.com/code-review-etiquette/)
		* [A zen manifesto for effective code reviews - Jean-Charles Fabre(2019)](https://www.freecodecamp.org/news/a-zen-manifesto-for-effective-code-reviews-e30b5c95204a/)
		* [On Empathy & Pull Requests - Slack Engineering(2016)](https://slack.engineering/on-empathy-pull-requests-979e4257d158#.imqf1v6wn)
		* [The Art of Humanizing Pull Requests - Ankita Kulkarni(2018)](https://blog.usejournal.com/the-art-of-humanizing-pull-requests-prs-b520588eb345)
			* What are PR’s, how to effectively create a PR, how to give feedback on PR’s and how to respond to feedback
		* [Building an Inclusive Code Review Culture - Julianna Lamb(2020)](https://blog.plaid.com/building-an-inclusive-code-review-culture/)
		* [Comments during Code Reviews - Otaru Babatunde](https://medium.com/@otarutunde/comments-during-code-reviews-2cb7791e1ac7)
		* [Creating a Code Review Culture, Part 1: Organizations and Authors - John Turner](https://engineering.squarespace.com/blog/2019/code-review-culture-part-1)
			* [Part2](https://engineering.squarespace.com/blog/2019/code-review-culture-part-2)
	* **Examples of**
		* [Code Reviews at Google are lightweight and fast - Michaela Greiler](https://www.michaelagreiler.com/code-reviews-at-google/)
		* [How Code Reviews work at Microsoft - Michaela Greiler](https://www.michaelagreiler.com/code-reviews-at-microsoft-how-to-code-review-at-a-large-software-company/)
	* **Other**
		* [Feedback Ladders: How We Encode Code Reviews at Netlify](https://www.netlify.com/blog/2020/03/05/feedback-ladders-how-we-encode-code-reviews-at-netlify/)
		* [Code Review Review is the Manager's Job - John Barton(2018)](https://hecate.co/blog/code-review-review-is-the-managers-job)
		* [Helping Developers Help Themselves: Automatic Decomposition of Code Review Changes - blog.acolyer.org](https://blog.acolyer.org/2015/06/26/helping-developers-help-themselves-automatic-decomposition-of-code-review-changes/)
	* **How-To**
		* [Auditing Source Code - TrailofBits CTF Field Guide](https://trailofbits.github.io/ctf/vulnerabilities/source.html)
		* [How to Do Code Reviews Like a Human (Part One) - Michael Lynch](https://mtlynch.io/human-code-reviews-1/)
			* [Part 2](https://mtlynch.io/human-code-reviews-2/)
	* **Published Audits**
		* [Trail of Bits Publically Published Code Audits/Security Reviews](https://github.com/trailofbits/publications/tree/master/reviews)
	* **Talks/Presentations/Videos**
		* [Code Reviews: Honesty, Kindness, Inspiration: Pick Three - Jacob Stoebel RubyConf 2017](http://confreaks.tv/videos/rubyconf2017-code-reviews-honesty-kindness-inspiration-pick-three)
			* The attitude among many developers seems to be that code reviews can be either honest or nice but not both. I see this as a false dichotomy; while code reviews should be both honest and kind, they should be focused on inspiring creators to go back to their work, excited to make it better. This talk will introduce the Liz Lerman Critical Response process, a framework for giving feedback on anything creative. You'll leave this talk with tips on how to improve your code reviews by putting the creator in the driver's seat and inspiring everyone on the team to make the product even better.
		* [Goldilocks and the Three Code Reviews - Vaidehi Joshi RedDot Ruby Conf 2017](https://confreaks.tv/videos/reddotrubyconf2017-goldilocks-and-the-three-code-reviews)
			* Once upon a time, Goldilocks had a couple extra minutes to spare before morning standup. She logged into Github and saw that there were three pull requests waiting for her to review. We’ve probably all heard that peer code reviews can do wonders to a codebase. But not all type of code reviews are effective. Some of them seem to go on and on forever, while others pick at syntax and formatting but miss bugs. This talk explores what makes a strong code review and what makes a painful one. Join Goldilocks as she seeks to find a code review process that’s neither too long nor too short, but just right!
		* [Implementing a Strong Code-Review Culture - Derek Prior Railsconf 2015](https://www.youtube.com/watch?v=PJjmw9TRB7s)
			* Code reviews are not about catching bugs. Modern code reviews are about socialization, learning, and teaching. How can you get the most out of a peer's code review and how can you review code without being seen as overly critical? Reviewing code and writing easily-reviewed features are skills that will make you a better developer and a better teammate. You will leave this talk with the tools to implement a successful code-review culture. You'll learn how to get more from the reviews you're already getting and how to have more impact with the reviews you leave.
		* [Michaela Greiler on Code Reviews - SE Radio 2020](https://www.se-radio.net/2020/02/episode-400-michaela-greiler-on-code-reviews/)
			 * Michaela Greiler discusses the importance of code reviews and how to conduct them. Felienne spoke with Greiler about the practice of code reviews, how to get better at them, what tools can be used to support them, as well as how to behave in the roles of both reviewer and code author.
	* **Training**
		* [Seth & Ken’s Excellent Adventures in Secure Code Review - mydevsecops.io](https://www.mydevsecops.io/post/seth-ken-s-excellent-adventures-in-secure-code-review)
		* [Seth & Ken's Excellent Adventures in Secure Code Review - BSidesSF2020 Workshop](https://github.com/zactly/handouts/blob/master/conferences/bsidessf_2020/Hands%20On%20Secure%20Code%20Review.pdf)
	* **Papers**
		* [An experiment to assess the cost-benefits of code inspections in large scale software development (Porter, Siy, Toman & Votta, 1997)](https://ieeexplore.ieee.org/document/601071http://laser.cs.umass.edu/courses/cs521-621.Fall10/documents/PorterSiyetal.pdf)
			* We conducted a long term experiment to compare the costs and benefits of several different software inspection methods. These methods were applied by professional developers to a commercial software product they were creating. Because the laboratory for this experiment was a live development effort, we took special care to minimize cost and risk to the project, while maximizing our ability to gather useful data. The article has several goals: (1) to describe the experiment's design and show how we used simulation techniques to optimize it; (2) to present our results and discuss their implications for both software practitioners and researchers; and (3) to discuss several new questions raised by our findings. For each inspection, we randomly assigned three independent variables: (1) the number of reviewers on each inspection team (1, 2, or 4); (2) the number of teams inspecting the code unit (1 or 2); and (3) the requirement that defects be repaired between the first and second team's inspections. The reviewers for each inspection were randomly selected without replacement from a pool of 11 experienced software developers. The dependent variables for each inspection included inspection interval (elapsed time), total effort, and the defect detection rate. Our results showed that these treatments did not significantly influence the defect detection effectiveness, but that certain combinations of changes dramatically increased the inspection interval.
		* [Anywhere, anytime code inspections: using the Web to remove inspection bottlenecks in large-scale software development (Perpich, Perry, Porter, Votta & Wade, 1997)](https://dl.acm.org/citation.cfm?id=253234)
			* We present and justify a solution using an intranet web that is both timely in its dissemination of information and effective in its coordination of distributed inspectors. First, exploiting a naturally occurring experiment (reported here), we conclude that the asynchronous collection of inspection results is at least as effective as the synchronous collection of those results. Second, exploiting the information dissemination qualities and the on-demand nature of information retrieval of the web, and the platform independence of browsers, we built an inexpensive tool that integrates seamlessly into the current development process. By seamless we mean an identical paper flow that results in an almost identical inspection process. The acceptance of the inspection tool has been excellent. The cost savings just from the reduction in paper work
		* [Design and Code Inspections to Reduce Errors in Program Development (Fagan, 2002)](https://ieeexplore.ieee.org/document/5388086)
			* We can summarize the discussion of design and code inspections and process control in developing programs as follows: 1. Describe the program development process in terms of operations, and define exit criteria which must be satisfied for completion of each operation. 2. Separate the objectives of the inspection process operations to keep the inspection team focused on one objective at a time: Operation Overview Preparation Inspection Rework Follow-up Objective Communications/education Education Find errors Fix errors Ensure all fixes are applied correctly 3. Classify errors by type, and rank frequency of occurrence of types. Identify which types to spend most time looking for in the inspection. 4. Describe how to look for presence of error types. 5. Analyze inspection results and use for constant process improvement (until process averages are reached and then use for process control).
		* [Characteristics of Useful Code Reviews: An Empirical Study at Microsoft (Bosu, Greiler, Bird, 2015)](https://www.microsoft.com/en-us/research/publication/characteristics-of-useful-code-reviews-an-empirical-study-at-microsoft/)
			* Over the past decade, both open source and commercial software projects have adopted contemporary peer code review practices as a quality control mechanism. Prior research has shown that developers spend a large amount of time and effort performing code reviews. Therefore, identifying factors that lead to useful code reviews can benefit projects by increasing code review effectiveness and quality. In a three-stage mixed research study, we qualitatively investigated what aspects of code reviews make them useful to developers, used our findings to build and verify a classification model that can distinguish between useful and not useful code review feedback, and finally we used this classifier to classify review comments enabling us to empirically investigate factors that lead to more effective code review feedback. In total, we analyzed 1.5 millions review comments from five Microsoft projects and uncovered many factors that affect the usefulness of review feedback. For example, we found that the proportion of useful comments made by a reviewer increases dramatically in the first year that he or she is at Microsoft but tends to plateau afterwards. In contrast, we found that the more files that are in a change, the lower the proportion of comments in the code review that will be of value to the author of the change. Based on our findings, we provide recommendations for practitioners to improve effectiveness of code reviews.
		* [Helping Developers Help Themselves: Automatic Decomposition of Code Review Changes (Barnett et al. 2015)](https://ieeexplore.ieee.org/document/7194568)
			* Code Reviews, an important and popular mechanism for quality assurance, are often performed on a change set, a set of modified files that are meant to be committed to a source repository as an atomic action. Understanding a code review is more difficult when the change set consists of multiple, independent, code differences. We introduce CLUSTERCHANGES, an automatic technique for decomposing change sets and evaluate its effectiveness through both a quantitative analysis and a qualitative user study.
		* [Work Practices and Challenges in Pull-Based Development - Georgios Gousios ; Andy Zaidman ; Margaret-Anne Storey ; Arie van Deursen(2015)]
			* In the pull-based development model, the integrator has the crucial role of managing and integrating contributions. This work focuses on the role of the integrator and investigates working habits and challenges alike. We set up an exploratory qualitative study involving a large-scale survey of 749 integrators, to which we add quantitative data from the integrator's project. Our results provide insights into the factors they consider in their decision making process to accept or reject a contribution. Our key findings are that integrators struggle to maintain the quality of their projects and have difficulties with prioritizing contributions that are to be merged. Our insights have implications for practitioners who wish to use or improve their pull-based development process, as well as for researchers striving to understand the theoretical implications of the pull-based model in software development.
		* [Code Reviewing in the Trenches: Understanding Challenges, Best Practices, and Tool Needs (MacLeod, Greiler, Storey, Bird, Czerwonka, 2018)](https://ieeexplore.ieee.org/document/7950877)
			* Code review has been widely adopted by and adapted to open source and industrial projects. Code review practices have undergone extensive research, with most studies relying on trace data from tool reviews, sometimes augmented by surveys and interviews. Several recent industrial research studies, along with blog posts and white papers, have revealed additional insights on code reviewing “from the trenches.” Unfortunately, the lessons learned about code reviewing are widely dispersed and poorly summarized by the existing literature. In particular, practitioners wishing to adopt or reflect on an existing or new code review process might have difficulty determining what challenges to expect and which best practices to adopt for their development context. Building on the existing literature, this article adds insights from a recent large-scale study of Microsoft developers to summarize the challenges that code-change authors and reviewers face, suggest best code-reviewing practices, and discuss tradeoffs that practitioners should consider. This article is part of a theme issue on Process Improvement.
		* [Modern Code Review: A Case Study at Google(2018)](https://research.google/pubs/pub47025/)
			* Employing lightweight, tool-based code review of code changes (aka modern code review) has become the norm for a wide variety of open-source and industrial systems. In this paper, we make an exploratory investigation of modern code review at Google. Google introduced code review early on and evolved it over the years; our study sheds light on why Google introduced this practice and analyzes its current status, after the process has been refined through decades of code changes and millions of code reviews. By means of 12 interviews, a survey with 44 respondents, and the analysis of review logs for 9 million reviewed changes, we investigate motivations behind code review at Google, current practices, and developers’ satisfaction and challenges.
	* **Tools**
		* [Gerrit](https://www.gerritcodereview.com/)
		* [Phabricator](https://www.phacility.com/phabricator/)
* **Cryptography**
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
		* [Practical Crypto Review for Developers - David Dillard(BSides Tampa 2020)](https://www.irongeek.com/i.php?page=videos/bsidestampa2020/track-b-02-practical-crypto-review-for-developers-david-dillard)
			* Cryptography is hard. It's hard because there are often a number of mistakes a developer can make when writing cryptographic code, but there's no easy way for the developer to look at the ciphertext or use unit tests to know that he made any mistakes. As long as the data can be correctly decrypted the developer usually assumes everything is fine, when in fact there may be issues that a knowledgeable attacker could take advantage of to recover the plaintext data. The easiest way to find such issues is to review how the crypto was done, but what should someone look for in such a review? This presentation will cover both common and not so common mistakes made with crypto I've encountered when performing crypto reviews and that have otherwise been made public, e.g. in news articles, blogs posts or CVEs. It will give attendees a number of practical things they can look for in performing crypto reviews of their own software. Examples of topics that will be covered include random number generation, the use of salts, salt generation, key generation, key derivation, IV generation, nonce generation and why developers should prefer AEAD ciphers.
* **Design Patterns**
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
	* **Papers**
		* [The Death Star Design Pattern](https://kkovacs.eu/the-death-star-design-pattern)
		* [Loop Patterns](https://users.cs.duke.edu/~ola/patterns/plopd/loops.html#loop-and-a-half)
* **Documentation**
* **Methodology**
	* [OWASP security Knowledge Framework](https://owasp.org/www-project-security-knowledge-framework/)
		* SKF is an open source security knowledgebase including manageble projects with checklists and best practice code examples in multiple programming languages showing you how to prevent hackers gaining access and running exploits on your application.
* **Metrics/Measurements**
	* [OWASP Security Assurance Maturity Model (SAMM)](https://owasp.org/www-project-samm/)
		* Our mission is to provide an effective and measurable way for all types of organizations to analyze and improve their software security posture. We want to raise awareness and educate organizations on how to design, develop, and deploy secure software through our self-assessment model. SAMM supports the complete software lifecycle and is technology and process agnostic. We built SAMM to be evolutive and risk-driven in nature, as there is no single recipe that works for all organizations.
* **Password Storage/Hashing**
* **Secrets Management**
	* **Articles/Blogposts/Writeups**
		* [Infrastructure Secret Management Software Overview](https://gist.github.com/maxvt/bb49a6c7243163b8120625fc8ae3f3cd)
			* Currently, there is an explosion of tools that aim to manage secrets for automated, cloud native infrastructure management. Daniel Somerfield did some work classifying the various approaches, but (as far as I know) no one has made a recent effort to summarize the various tools. This is an attempt to give a quick overview of what can be found out there. The list is alphabetical. There will be tools that are missing, and some of the facts might be wrong--I welcome your corrections. For the purpose, I can be reached via @maxvt on Twitter, or just leave me a comment here.
	* **Talks/Presentations/Videos**
		* [Turtles All the Way Down: Storing Secrets in the Cloud and the Data Center - Daniel Somerfield(OWASP AppSecUSA 2015)](https://www.youtube.com/watch?v=OUSvv2maMYI&feature=youtu.be)
			* This talk will be a survey of the available tools, technologies, and strategies developers can utilize to improve how their secrets are managed throughout development, testing, and deployment. The talk will cover both data center and cloud-based deployments, paying special attention to open-source tools available for common enterprise platforms. Discussion will center around advantages and disadvantages of each option in order to help developers and operational teams find the solution or solutions most appropriate to their applications and organizations.
* **Secure Coding Documents**
	* [Secure Coding Standards - Android](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=111509535)
	* [Secure Coding Cheat Sheet - OWASP](https://www.owasp.org/index.php/Secure_Coding_Cheat_Sheet)
	* [Secure iOS application development](https://github.com/felixgr/secure-ios-app-dev)
		* This guide is a collection of the most common vulnerabilities found in iOS applications. The focus is on vulnerabilities in the applications’ code and only marginally covers general iOS system security, Darwin security, C/ObjC/C++ memory safety, or high-level application security. Nevertheless, hopefully the guide can serve as training material to iOS app developers that want to make sure that they ship a more secure app. Also, iOS security reviewers can use it as a reference during assessments.
	* [OWASP Secure Coding Practices-Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/migrated_content)
		* The Secure Coding Practices Quick Reference Guide is a technology agnostic set of general software security coding practices, in a comprehensive checklist format, that can be integrated into the development lifecycle. At only 17 pages long, it is easy to read and digest. The focus is on secure coding requirements, rather then on vulnerabilities and exploits. It includes an introduction to Software Security Principles and a glossary of key terms. It is designed to serve as a secure coding kick-start tool and easy reference, to help development teams quickly understand secure coding practices.
* **Secure/Software/Systems Development Life Cycle(SDLC/SDL)** <a name="sdlc"></a>
	* **101**
		* [Systems development life cycle - Wikipedia](https://en.wikipedia.org/wiki/Systems_development_life_cycle)
		* [Microsoft Security Development Lifecycle](https://www.microsoft.com/en-us/securityengineering/sdl)
		* [Microsoft SDL Practices](https://www.microsoft.com/en-us/securityengineering/sdl/practices)
		* [SDLC Overview - tutorialspoint](https://www.tutorialspoint.com/sdlc/sdlc_overview.htm)
		* [The SDLC: 7 phases, popular models, benefits & more - Dave Swersky(2019)](https://raygun.com/blog/software-development-life-cycle/)
	* **Articles/Blogposts/Writeups**
		* [Moving Fast and Securing Things: The SDL at Slack and goSDL - Max Feldman(2018)](https://slack.engineering/moving-fast-and-securing-things-540e6c5ae58a)
		* [The Security Development Lifecycle(free ebook) - Microsoft](https://docs.microsoft.com/en-us/archive/blogs/microsoft_press/free-ebook-the-security-development-lifecycle)
		* [OWASP Proactive Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls?refresh=123#tab=OWASP_Proactive_Controls_2016)
			* The OWASP Top Ten Proactive Controls 2016 is a list of security concepts that should be included in every software development project. They are ordered by order of importance, with control number 1 being the most important.
		* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
	* **Talks/Presentations/Videos**
		* [Moving Fast and Securing Things - Max Feldman(AppSecUSA 2017)](https://www.youtube.com/watch?v=feRypwVqcuQ)
			* In this presentation we will discuss both our Secure Development Lifecycle (SDL) process and tooling, as well as view metrics and provide analysis of how the process has worked thus far. We intend to open-source our tooling as a supplement to this presentation, and offer advice for others wishing to attempt similar implementations. We'll discuss our deployment of a flexible framework for security reviews, including a lightweight self-service assessment tool, a checklist generator, and most importantly a chat-based process that meets people where they are already working. We’ll show how it’s possible to encourage a security mindset among developers, while avoiding an adversarial relationship. By tracking data from multiple sources, we can also view the quantified success of such an approach and show how it can be applied in other organizations.
		* [Practical tips for defending web applications - Zane Lackey - devops Amsterdam 2017](https://www.youtube.com/watch?v=Mae2iXUA7a4)
			* [Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Lackey-Practical%20Tips-for-Defending-Web-Applications-in-the-Age-of-DevOps.pdf)
* **Software Testing** <a name="stest"></a>
	* **Articles/Blogposts/Writeups**
		* [A kernel unit-testing framework - Jonathan Corbet](https://lwn.net/Articles/780985/)
		* [How is the Linux kernel tested? - StackOverflow](https://stackoverflow.com/questions/3177338/how-is-the-linux-kernel-tested)
		* [Evolving Test Practices at Microsoft - docs.ms(2017)](https://docs.microsoft.com/en-us/azure/devops/learn/devops-at-microsoft/evolving-test-practices-microsoft)
	* **Talks/Presentations/Videos**
		* [When to Test and How to Test It - Bruce Potter - Derbycon7](https://www.youtube.com/watch?v=Ej97WyEMRkI)
			* “I think we need a penetration test” This is one of the most misunderstood phrases in the security community. It can mean anything from “Someone should run a vulnerability scan against a box” to “I’d like nation-state capable actors to tell me everything that wrong with my enterprise” and everything in between. Security testing is a complex subject and it can be hard to understand what the best type of testing is for a given situation. This talk will examine the breadth of software security testing. From early phase unit and abuse testing to late phase penetration testing, this talk will provide details on the different tests that can be performed, what to expect from the testing, and how to select the right tests for your situation. Test coverage, work effort, attack simulation, and reporting results will be discussed. Also, this talk will provide a process for detailed product assessments, i.e.: if you’ve got a specific product you’re trying to break, how do you approach assessing the product in a way that maximizes your chance of breaking in as well as maximizing the coverage you will get from your testing activity.
		* [Big picture software testing unit testing, Lean Startup, and everything in between PyCon 2017](https://www.youtube.com/watch?v=Vaq_e7qUA-4&feature=youtu.be&t=63s)
			* There are many ways you can test your software: unit testing, manual testing, end-to-end testing, and so forth. Take a step back and you'll discover even more form of testing, many of them very different in their goals: A/B testing, say, where you see which of two versions of your website results in more signups or ad clicks. How do these forms of testing differ, how do they relate to each other? How do you choose which kind of testing to pursue, given limited time and resources? How do you deal with strongly held yet opposite views arguing either that a particular kind of testing is essential or that it's a waste time? This talk will provide you with a model, a way to organize all forms of testing and understand what exactly they provide, and why. Once you understand the model you will be able to choose the right form of testing for *your* situation and goals.
		* [Robots with Pentest Recipes - Abhay Bhargav(OWASP AppSec Cali 2018)](https://www.youtube.com/watch?v=EC1X4bqAqCk)
			* Over the last few months, my team and I have leveraged the all-powerful Robot Framework to integrate various security testing tools, including OWASP ZAP, Nmap, Nessus. Robot Framework is a generic test automation framework for acceptance testing and acceptance test-driven development (ATDD). It provides a very extensible test-driven syntax that extend test libraries implemented in Python or Java. We have developed Open Source libraries for popular tools like OWASP ZAP, Nmap, Nessus and some recon tools, which can be invoked with existing libraries like Selenium, etc to perform completely automated, parameterized, security tests across the continuous delivery pipeline with easy-to-write, almost trivial test syntax like `run nmap scan` OR `start zap active scan` thereby making it easier for engineering teams to be able to create “recipes” of security tests that they want to run, integrate with functional test automation to run anything from a baseline scan to a complete parameterized security test of the application on various environments. In fact, we have used these libraries to run a “mostly automated pentest as a recipe” replete with recon, mapping, vulnerability discovery phases with evidences and reporting built-in.
* **Supply-Chain Management** <a name="supply"></a>
	* **Articles/Blogposts/Writeups**
		* [Want to take over the Java ecosystem? All you need is a MITM! - Jonathan Leitschuh(2019)](https://medium.com/bugbountywriteup/want-to-take-over-the-java-ecosystem-all-you-need-is-a-mitm-1fc329d898fb)
		* [How To Take Over The Computer Of any Java (or Clojure or Scala) Developer - max.computer(2014)](https://max.computer/blog/how-to-take-over-the-computer-of-any-java-or-clojure-or-scala-developer/)
	* **Talks/Presentations/Videos**	
		* [Securing the software supply chain together - Maya Kaczorowski(GitHub Satellite 2020)](https://www.youtube.com/watch?v=XwKTUji5HtY&feature=emb_title)
		* Writing secure code is hard in its own right, but understanding what vulnerabilities exist in your code— and how to keep up to date with the latest patches—is daunting for even the most sophisticated software teams. In this session, you'll learn how GitHub is making it easier to secure your software supply chain, and how to get started in protecting your code and its dependencies.
		* [The path to code provenance at uber - Matt Finifter, Debosmit Ray, Tony Ngo(2019)](https://www.youtube.com/watch?v=vb08Jkp1f-M)
			* We will share some specific examples and use cases from our Uber’s product security team that can be applied in other environments including: - deploying hooks for developers to sign commits (and enforcement of signatures before building container images); - making security a first-class citizen in our build pipelines to harden and sign builds (and integrations with our container orchestration framework to ensure that our build/image artifacts have been appropriately hardened and vetted to be run within our infrastructure); - improvements to our container runtime security, in order to efficiently detect and block any unauthorized code (including runtime anomaly detection and a process for remediation of newly-blacklisted packages); - deploying security policies around third-party dependencies (and how we hook into the SDLC in order to warn and enforce when something is out of policy compliance)
	* **Tools**
		* [in-toto](https://github.com/in-toto/in-toto)
			* in-toto provides a framework to protect the integrity of the software supply chain. It does so by verifying that each task in the chain is carried out as planned, by authorized personnel only, and that the product is not tampered with in transit.
		* [LibScout](https://github.com/reddr/LibScout)
			* LibScout is a light-weight and effective static analysis tool to detect third-party libraries in Android/Java apps. The detection is resilient against common bytecode obfuscation techniques such as identifier renaming or code-based obfuscations such as reflection-based API hiding or control-flow randomization. Further, LibScout is capable of pinpointing exact library versions including versions that contain severe bugs or security issues.
		* [third-party-lib-analyzer](https://github.com/jtmelton/third-party-lib-analyzer)
			* A tool for analyzing third party libraries and how they connect to user classes. TPLA constructs a graph database of all dependencies, user classes, and relationships between all classes. It also allows some built in queries to be executed with reports generated based on the results.
* **Threat Modeling** <a name="threatm"></a>
	* See [Threat Modeling](./threatmodel.md)
	* **Articles/Blogposts/Writeups**
		* [Abuser Stories: A Sneak Peak For Scrum Teams - Abhay Bhargav(2018)](https://www.we45.com/blog/abuser-stories-a-sneak-peak-for-scrum-teams)
		* [Agile Threat Modeling - Mathias Rohr(2020)](https://blog.secodis.com/2020/01/05/agile-threat-modeling/)
		* [Threat Model, like Sherlock! - Puru Naidu & Sudarshan Narayanan(2018)](https://www.we45.com/blog/threat-model-like-sherlock)
		* [Practical Security Stories and Security Tasks for Agile Development Environments](https://safecode.org/publication/SAFECode_Agile_Dev_Security0712.pdf)
		* [A Guide to Threat Modelling for Developers - Jim Gumbley](https://martinfowler.com/articles/agile-threat-modelling.html)
			* This article provides clear and simple steps to help teams that want to adopt threat modelling. Threat modelling is a risk-based approach to designing secure systems. It is based on identifying threats in order to develop mitigations to them.
		* [Tactical Threat Modeling - SAFECode(2017)](https://safecode.org/wp-content/uploads/2017/05/SAFECode_TM_Whitepaper.pdf)
		* [[Part 1] Experimenting with visualizations and code risk overview - DiabloHorn](https://diablohorn.com/2020/05/06/part-1-experimenting-visualizations-code-risk-overview/)
			* [Part 2](https://diablohorn.com/2020/05/10/part-2-interactive-and-transferrable-code-risk-visualization/)
	* **Talks/Presentations/Videos**
		* [Threat Model Every Story: Practical Continuous Threat Modeling Work for Your Tea - Izar Tarandach](https://www.youtube.com/watch?v=VbW-X0j35gw&t=0s&list=PLpr-xdpM8wG-bXotGh7OcWk9Xrc1b4pIJ&index=21)
			* The good old days of waterfall! You had "The One Design To Bind Them All" and once it got all agreed, the developers would happily implement it "per spec". But alas, we are not there anymore. Agile methodologies basically guarantee that the deployed system will change, and change fast, since inception. Design emerges as it develops. How do we cope with that in Threat Modeling? This talk explores the way Autodesk is moving to a team-based collaborative and continuous Threat Modeling methodology, and how the dialog has moved the dependency away from security SMEs and into the team. PyTM, an Open Source threat-modeling-as-code support system is also presented.
		* [User-Story Driven Threat Modeling - Robert Hurlbut](https://www.youtube.com/watch?v=oEfOKK895Q8)
			* [Slides](https://roberthurlbut.com/Resources/2019/CodeMash/Robert-Hurlbut-CodeMash2019-User-Story-Threat-Modeling-20190910.pdf)
			* Threat modeling is a way of thinking about what could go wrong and how to prevent it. When it comes to building software, some software shops either skip the important step of threat modeling in secure software design or, they have tried threat modeling before but haven't quite figured out how to connect the threat models to real world software development and its priorities. Threat modeling should be part of your secure software design process. In this session we will look at some of the latest advances in threat modeling integrated with Agile Development processes by using User Stories and Abuser Stories. This process is iterative and meant to keep step with Agile Development practices. By enumerating Threats against User Stories / Abuser Stories, you are not threat modeling an entire/massive system, but going granular by enumerating threats against relevant user stories. Finally, you will see how this process facilitates the creation of multiple segues into Security Test Cases and Mitigation Plans. You will see how this process works with an automated approach to security test cases.
		* [Threat Model Every Story: Practical Continuous Threat Modeling Work for Your Team - Izar Tarandach(OWASP AppSecCali 2019)](https://www.youtube.com/watch?v=VbW-X0j35gw)
			* The good old days of waterfall! You had "The One Design To Bind Them All" and once it got all agreed, the developers would happily implement it "per spec". But alas, we are not there anymore. Agile methodologies basically guarantee that the deployed system will change, and change fast, since inception. Design emerges as it develops. How do we cope with that in Threat Modeling? This talk explores the way Autodesk is moving to a team-based collaborative and continuous Threat Modeling methodology, and how the dialog has moved the dependency away from security SMEs and into the team. PyTM, an Open Source threat-modeling-as-code support system is also presented.
		* [Threat Model-as-Code - Abhay Bhargav(OWASP AppSecUSA 2018)](https://www.youtube.com/watch?v=fT2-JuvK428)
			* [Slides](https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1541171553.pdf)
			* Threat Modeling is critical for Product Engineering Team. Yet, even in the rare event that it’s performed, its performed without actionable outputs emerging from the exercise. It is relegated to the status of what a “Policy/Best Practice Document”, which it shouldn’t be. I believe that Threat Models are playbooks of Product Security Engineering. I feel that the best way to do threat modeling is to integrate it into the Software Development Lifecycle (SDL). In addition, I believe that Threat Models should produce actionable outputs that can be acted up on by various teams within the organization. To address this lacuna, I have developed “Automaton” - An Open Source “Threat Modeling as Code” framework, that allows product teams to capture User Stories, Abuser Stories, Threat Models and Security Test Cases in YAML Files (like Ansible). With the help of Test Automation Frameworks (in this case, Robot Framework) Automaton allows the product engineering team to not only capture Threat Models as code, but also trigger specific security test cases with tools like OWASP ZAP, BurpSuite, WFuzz, Sublist3r, Nmap and so on.
		* [Robots with Pentest Recipes - Abhay Bhargav(OWASP AppSec Cali 2018)](https://www.youtube.com/watch?v=EC1X4bqAqCk)
			* Over the last few months, my team and I have leveraged the all-powerful Robot Framework to integrate various security testing tools, including OWASP ZAP, Nmap, Nessus. Robot Framework is a generic test automation framework for acceptance testing and acceptance test-driven development (ATDD). It provides a very extensible test-driven syntax that extend test libraries implemented in Python or Java. We have developed Open Source libraries for popular tools like OWASP ZAP, Nmap, Nessus and some recon tools, which can be invoked with existing libraries like Selenium, etc to perform completely automated, parameterized, security tests across the continuous delivery pipeline with easy-to-write, almost trivial test syntax like `run nmap scan` OR `start zap active scan` thereby making it easier for engineering teams to be able to create “recipes” of security tests that they want to run, integrate with functional test automation to run anything from a baseline scan to a complete parameterized security test of the application on various environments. In fact, we have used these libraries to run a “mostly automated pentest as a recipe” replete with recon, mapping, vulnerability discovery phases with evidences and reporting built-in.
	* **Tools**
		* [ThreatPlaybook](https://we45.gitbook.io/threatplaybook/)
			* A (relatively) Unopinionated framework that faciliates Threat Modeling as Code married with Application Security Automation on a single Fabric
		* [Threatspec](https://github.com/threatspec/threatspec)
			* Threatspec is an open source project that aims to close the gap between development and security by bringing the threat modelling process further into the development process. This is achieved by having developers and security engineers write threat modeling annotations as comments inside source code, then dynamically generating reports and data-flow diagrams from the code. This allows engineers to capture the security context of the code they write, as they write it. In a world of everything-as-code, this can include infrastructure-as-code, CI/CD pipelines, and serverless etc. in addition to traditional application code.
		* [Continuous Threat Modeling - Autodesk](https://github.com/Autodesk/continuous-threat-modeling)
			* CTM is Autodesk's threat modeling methodology enabling development teams to perform threat modeling with minimal initial security knowledge and lesser dependency on security experts. It is an evolutionary, dynamic methodology that should mesh well with teams using Agile and evolving system architectures.
		* [pytm: A Pythonic framework for threat modeling](https://github.com/izar/pytm)
			* Define your system in Python using the elements and properties described in the pytm framework. Based on your definition, pytm can generate, a Data Flow Diagram (DFD), a Sequence Diagram and most important of all, threats to your system.
		* [goSDL](https://github.com/slackhq/goSDL)
			* goSDL is a web application tool that serves as a self-service entry point for following a Security Development Lifecycle checklist in a software development project. This tool collects relevant information about the feature, determines the risk rating, and generates the appropriate security requirements. The tool tailors the checklist to the developers’ specific needs, without providing unnecessary unrelated security requirements. Security experts can establish custom security guidance and requirements as checklist items for all developers. This checklist is used as a guide and reference for building secure software. This encourages a security mindset among developers when working on a project and can be used to easily track the completion of security goals for that project.
		* [Mozilla Rapid Risk Assessment](https://infosec.mozilla.org/guidelines/risk/rapid_risk_assessment)
			* A typical Rapid Risk Analysis/Assessment (RRA) takes about 30 minutes. It is not a security review, a full threat-model, a vulnerability assessment, or an audit. These types of activities may however follow an RRA if deemed appropriate or necessary. The main objective of the RRA is to understand the value and impact of a service to the reputation, finances, productivity of the project or business. It is based on the data processed, stored or simply accessible by services. Note that the RRA does not focus on enumerating and analyzing security controls. The RRA process is intended for analyzing and assessing services, not processes or individual controls.
* **Specific Vulnerabilitiy Mitigation/Prevention** <a name="specvuln"></a>
	* **Comparison Operations** <a name="compops"></a>
		* **Articles/Blogposts/Writeups**
			* [The Evil within the Comparison Functions - Andrey Karpov](https://www.viva64.com/en/b/0509/)
			* [Inverting Your Assumptions: A Guide To JIT Comparisons - Jasiel Spelman(2018)](https://www.zerodayinitiative.com/blog/2018/4/12/inverting-your-assumptions-a-guide-to-jit-comparisons)
	* **Cryptographic Issues** <a name="crypto"></a>
		* **Articles/Blogposts/Writeups**
			* [Top 10 Developer Crypto Mistakes - crazycontini(2017)](https://littlemaninmyhead.wordpress.com/2017/04/22/top-10-developer-crypto-mistakes)
	* **Input Validation** <a name="inputval"></a>
		* **Articles/Blogposts/Writeups**
			* [Validating input - David Wheeler(2003)](https://www.ibm.com/developerworks/library/l-sp2/index.html)
	* **Race Conditions/ToCToU Bugs** <a name="toctou"></a>
		* **Articles/Blogposts/Writeups**
			* [Exploiting and Protecting Against Race Conditions - Jack Cable(2017)](https://lightningsecurity.io/blog/race-conditions/)
	* **Account Enumeration** <a name="ace"></a>
		* **Articles/Blogposts/Writeups**
			* [Once upon a time an account enumeration - Cust0n](https://sidechannel.tempestsi.com/once-upon-a-time-there-was-an-account-enumeration-4cf8ca7cdc1)
			* "The aim of this blogpost is to illustrate how account enumeration can occur in web applications, from the classic example to some tricks we’ve learned over the years (and of course show how to avoid this)."
	* **Secure File Upload** <a name="sfu"></a>
		* **Articles/Blogposts/Writeups**
			* [8 Basic Rules to Implement Secure File Uploads - SANS](https://software-security.sans.org/blog/2009/12/28/8-basic-rules-to-implement-secure-file-uploads/)
	* **SQL Injection** <a name="sqli"></a>
		* **Articles/Blogposts/Writeups**
			* [Bobby Tables: A guide to preventing SQL injection](https://bobby-tables.com/)
			* [SQL Injection Prevention Cheat Sheet - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
			* [What ORMs have taught me: just learn SQL - wozniak.ca(2014)](https://wozniak.ca/blog/2014/08/03/What-ORMs-have-taught-me-just-learn-SQL/)
* [Six Stages of debugging](http://plasmasturm.org/log/6debug/)
	```
	1. That can’t happen.
	2. That doesn’t happen on my machine.
	3. That shouldn’t happen.
	4. Why does that happen?
	5. Oh, I see.
	6. How did that ever work?
	```

## Source Code Analysis <a name="sca"></a>
* **Articles/Blogposts/Writeups**
	* [What I learned from doing 1000 code reviews](https://hackernoon.com/what-i-learned-from-doing-1000-code-reviews-fe28d4d11c71)
	* [One Line of Code that Compromises Your Server - The dangers of a simplistic session secret](https://martinfowler.com/articles/session-secret.html)
	* [How to find 56 potential vulnerabilities in FreeBSD code in one evening](https://www.viva64.com/en/b/0496/)
* **General**
	* [Code-Audit-Challenges](https://github.com/CHYbeta/Code-Audit-Challenges)
	* [InsecureProgramming](https://github.com/gerasdf/InsecureProgramming)
		* Insecure Programming by Example - Teach yourself how buffer overflows, format strings, numeric bugs, and other binary security bugs work and how to exploit them
* **Presentations/Talks**
	* [Code Insecurity or Code in Security - Mano 'dash4rk' Paul - Derbycon2014](https://www.irongeek.com/i.php?page=videos/derbycon4/t205-code-insecurity-or-code-in-security-mano-dash4rk-paul)
		* Attendees of this talk will benefit from learning about what constitutes insecure code and the associated attacks that stem from such code. Applicable attacks ranging from injection to reversing will be demonstrated to reinforce contents of this talk. This way, the attendee would not only be taught about “What not to do?” but also, “Why this should not do, what they ought not to do?”. Finally, attendees will also be introduced to secure development processes such as protection needs elicitation, threat modeling, code review and analysis and secure deployment, to illustrate that while writing secure code is one important aspect of software security, there is more to securing applications, than what meets the eye. Come for a fun filled, interactive session and your chance to win one of the personalized and autographed copies of the speaker’s renowned book – The 7 qualities of highly secure software.
	* [Code Insecurity or Code in Security - Mano 'dash4rk' Paul](http://www.irongeek.com/i.php?page=videos/derbycon4/t205-code-insecurity-or-code-in-security-mano-dash4rk-paul)
		* Attendees of this talk will benefit from learning about what constitutes insecure code and the associated attacks that stem from such code. Applicable attacks ranging from injection to reversing will be demonstrated to reinforce contents of this talk. This way, the attendee would not only be taught about “What not to do?” but also, “Why this should not do, what they ought not to do?”. Finally, attendees will also be introduced to secure development processes such as protection needs elicitation, threat modeling, code review and analysis and secure deployment, to illustrate that while writing secure code is one important aspect of software security, there is more to securing applications, than what meets the eye. Come for a fun filled, interactive session and your chance to win one of the personalized and autographed copies of the speaker’s renowned book – The 7 qualities of highly secure software.
	* [Seth & Ken’s Excellent Adventures in Secure Code Review - thesecuredeveloper.com](https://www.thesecuredeveloper.com/post/seth-ken-s-excellent-adventures-in-secure-code-review)
* **Non-Specific** <a name="nonspec"></a>
	* **Tools**
		* **Analyzer**
			* [Semgrep](https://github.com/returntocorp/semgrep)
				* semgrep is a tool for easily detecting and preventing bugs and anti-patterns in your codebase. It combines the convenience of grep with the correctness of syntactical and semantic search. Developers, DevOps engineers, and security engineers use semgrep to write code with confidence.
			* [PMD](http://pmd.sourceforge.net/)
				* PMD is a source code analyzer. It finds common programming flaws like unused variables, empty catch blocks, unnecessary object creation, and so forth. It supports Java, JavaScript, PLSQL, Apache Velocity, XML, XSL. Additionally it includes CPD, the copy-paste-detector. CPD finds duplicated code in Java, C, C++, C#, PHP, Ruby, Fortran, JavaScript, PLSQL, Apache Velocity, Ruby, Scala, Objective C, Matlab, Python, Go.
			* [SourceTrail](https://www.sourcetrail.com/)
				* A cross-platform source explorer for C/C++ and Java
			* [Infer](https://github.com/facebook/infer)
				* [Infer](http://fbinfer.com/) is a static analysis tool for Java, Objective-C and C, written in OCaml.
			* [VCG](https://github.com/nccgroup/VCG)
				* VCG is an automated code security review tool that handles C/C++, Java, C#, VB and PL/SQL.
		* **IDE-Related**
			* [DevSkim](https://github.com/Microsoft/DevSkim)
				* DevSkim is a framework of IDE extensions and language analyzers that provide inline security analysis in the dev environment as the developer writes code. It has a flexible rule model that supports multiple programming languages. The goal is to notify the developer as they are introducing a security vulnerability in order to fix the issue at the point of introduction, and to help build awareness for the developer.
		* **Libraries**
			* [Semantic](https://github.com/github/semantic/)
				* `semantic` is a Haskell library and command line tool for parsing, analyzing, and comparing source code.
		* **Miscellaneous**
			* [cloc](https://github.com/AlDanial/cloc)
				* cloc counts blank lines, comment lines, and physical lines of source code in many programming languages.
	* **Grep-Based**
		* [Don't Underestimate Grep Based Code Scanning - Crazy Contini](https://littlemaninmyhead.wordpress.com/2019/08/04/dont-underestimate-grep-based-code-scanning/)
		* [Graudit](https://github.com/wireghoul/graudit)
			* Graudit is a simple script and signature sets that allows you to find potential  security flaws in source code using the GNU utility grep. It's comparable to  other static analysis applications like RATS, SWAAT and flaw-finder while  keeping the technical requirements to a minimum and being very flexible.
		* [CRASS](https://github.com/floyd-fuh/crass)
			* The "code review audit script scanner" (CRASS) started as a source code grep-er with a set of selected high-potential strings that may result in (security) problems. By now it is searching for strings that are interesting for analysts. Simplicity is the key: You don't need anything than a couple of standard `*nix` command line tools (especially grep), while the project still serves as a "what can go wrong" collection of things we see over the years.
		* [ripgrep](https://github.com/burntsushi/ripgrep)
			* ripgrep is a line-oriented search tool that recursively searches your current directory for a regex pattern. By default, ripgrep will respect your .gitignore and automatically skip hidden files/directories and binary files. ripgrep has first class support on Windows, macOS and Linux, with binary downloads available for every release. ripgrep is similar to other popular search tools like The Silver Searcher, ack and grep.
			* [ripgrep is faster than {grep, ag, git grep, ucg, pt, sift} - Andrew Gallant(2016)](https://blog.burntsushi.net/ripgrep/)
* **Specific Languages** <a name="spec"></a>
	* **`*`sh**
		* **Bash**
			* [Shellcheck](https://github.com/koalaman/shellcheck)
				* ShellCheck is a GPLv3 tool that gives warnings and suggestions for bash/sh shell scripts
	* **C/C++**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
		* **Tooling**
			* [Clang Static Analyzer](https://clang-analyzer.llvm.org/)
				* The Clang Static Analyzer is a source code analysis tool that finds bugs in C, C++, and Objective-C programs.
			* [cppcheck](https://github.com/danmar/cppcheck)
				* static analysis of C/C++ code
			* [Flawfinder](https://sourceforge.net/projects/flawfinder/)
				* Flawfinder is a program that examines C source code and reports possible security weaknesses ('flaws') sorted by risk level. It's very useful for quickly finding and removing some security problems before a program is widely released.
	* **CSharp**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
		* **Tooling**
			* [OWASP SafeNuGet](https://github.com/owasp/SafeNuGet)
				* OWASP SafeNuGet is an MsBuild task to warn about insecure NuGet libraries: https://nuget.org/packages/SafeNuGet/
			* [Puma Scan](https://github.com/pumasecurity/puma-scan)
				* Puma Scan is a .NET software secure code analysis tool providing real time, continuous source code analysis as development teams write code. In Visual Studio, vulnerabilities are immediately displayed in the development environment as spell check and compiler warnings, preventing security bugs from entering your applications. Puma Scan also integrates into the build to provide security analysis at compile time.
			* [Security Code Scan](https://security-code-scan.github.io/)
				* static code analyzer for .NET
	* **Go**
		* **Articles/Blogposts/Writeups**
			* [Go code auditing - 0xdabbad00](http://0xdabbad00.com/2015/04/18/go_code_auditing/)
			* [Security assessment techniques for Go projects - TrailofBits](https://blog.trailofbits.com/2019/11/07/attacking-go-vr-ttps/)
		* **Talks/Presentations/Videos**
		* **Tooling**
			* [gosec](https://github.com/securego/gosec)
				* Inspects source code for security problems by scanning the Go AST.
			* [glasgo](https://github.com/ttarvis/glasgo)
				* A static analysis tool intended to check for potential security issues. New tests will be added soon. Special thanks to NCC Group Plc.
			* [GAS - Go AST Scanner](https://github.com/GoASTScanner/gas)
				* Inspects source code for security problems by scanning the Go AST.
			* [golangci-lint](https://github.com/golangci/golangci-lint)
				* golangci-lint is a fast Go linters runner. It runs linters in parallel, uses caching, supports yaml config, has integrations with all major IDE and has dozens of linters included.
			* [SafeSQL](https://github.com/stripe/safesql)
				* SafeSQL is a static analysis tool for Go that protects against SQL injections.
			* [nancy](https://github.com/sonatype-nexus-community/nancy)
				* nancy is a tool to check for vulnerabilities in your Golang dependencies, powered by Sonatype OSS Index, and as well, works with Nexus IQ Server, allowing you a smooth experience as a Golang developer, using the best tools in the market!
	* **Java**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
			* [Finding security vulnerabilities in Java with CodeQL - @lcartey(GitHub Satellite 2020)](https://www.youtube.com/watch?v=nvCd0Ee4FgE&feature=emb_title)
				* CodeQL is GitHub's expressive language and engine for code analysis, which allows you to explore source code to find bugs and security vulnerabilities. During this beginner-friendly workshop, you will learn to write queries in CodeQL and find known security vulnerabilities in open source Java projects.
		* **Tooling**
			* [FindBugs](https://find-sec-bugs.github.io/)
				* The FindBugs plugin for security audits of Java web applications.
			* [SpotBugs](https://github.com/spotbugs/spotbugs)
				* SpotBugs is the spiritual successor of FindBugs, carrying on from the point where it left off with support of its community.
			* [Soot](https://github.com/Sable/soot)
				* Soot is a Java optimization framework. It provides four intermediate representations for analyzing and transforming Java bytecode: 'Baf: a streamlined representation of bytecode which is simple to manipulate.'; 'Jimple: a typed 3-address intermediate representation suitable for optimization.'; 'Shimple: an SSA variation of Jimple.'; 'Grimp: an aggregated version of Jimple suitable for decompilation and code inspection.';
			* [T.J. Watson Libraries for Analysis (WALA)](http://wala.sourceforge.net/wiki/index.php/Main_Page)
				* The T. J. Watson Libraries for Analysis (WALA) provide static analysis capabilities for Java bytecode and related languages and for JavaScript.
	* **Javascript**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
			* [Finding security vulnerabilities in JavaScript with CodeQL - @adityasharad(GitHub Satellite 2020)](https://www.youtube.com/watch?v=pYzfGaLTqC0)
				* CodeQL is GitHub's expressive language and engine for code analysis, which allows you to explore source code to find bugs and security vulnerabilities. During this beginner-friendly workshop, you will learn to write queries in CodeQL and find known security vulnerabilities in open source JavaScript projects.
		* **Tooling**
			* [T.J. Watson Libraries for Analysis (WALA)](http://wala.sourceforge.net/wiki/index.php/Main_Page)
				* The T. J. Watson Libraries for Analysis (WALA) provide static analysis capabilities for Java bytecode and related languages and for JavaScript.
			* [NodeJsScan](https://github.com/ajinabraham/NodeJsScan)
				* Static security code scanner (SAST) for Node.js applications.
			* [ESLint](https://github.com/eslint/eslint)
				* ESLint is a tool for identifying and reporting on patterns found in ECMAScript/JavaScript code.
			* [eslint-plugin-no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized)
				* Custom ESLint rule to disallows unsafe innerHTML, outerHTML, insertAdjacentHTML and alike
			* [npm-audit](https://docs.npmjs.com/cli/audit)
				* [Auditing package dependencies for security vulnerabilities](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities)
			* [retire.js](https://github.com/retirejs/retire.js/)
				* scanner detecting the use of JavaScript libraries with known vulnerabilities
	* **PHP**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
		* **Tooling**
			* [RIPS](http://rips-scanner.sourceforge.net/)
				* RIPS is a tool written in PHP to find vulnerabilities in PHP applications using static code analysis. By tokenizing and parsing all source code files RIPS is able to transform PHP source code into a program model and to detect sensitive sinks (potentially vulnerable functions) that can be tainted by user input (influenced by a malicious user) during the program flow. Besides the structured output of found vulnerabilities RIPS also offers an integrated code audit framework for further manual analysis.
			* [PHPMD - PHP Mess Detector](http://phpmd.org/about.html)
				* What PHPMD does is: It takes a given PHP source code base and look for several potential problems within that source. These problems can be things like: Possible bugs; Suboptimal code; Overcomplicated expressions; Unused parameters, methods, properties.
			* [Phan](https://github.com/phan/phan)
				* Phan is a static analyzer for PHP. Phan prefers to avoid false-positives and attempts to prove incorrectness rather than correctness.
			* [phpcs-security-audit v3](https://github.com/FloeDesignTechnologies/phpcs-security-audit)
				* phpcs-security-audit is a set of PHP_CodeSniffer rules that finds vulnerabilities and weaknesses related to security in PHP code
			* [SensioLabs Security Checker](https://github.com/sensiolabs/security-checker)
				* The SensioLabs Security Checker is a command line tool that checks if your application uses dependencies with known security vulnerabilities. It uses the Security Check Web service and the Security Advisories Database.
	* **Python**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
			* [Python Static Analysis - Spencer J McIntyre - Derbycon7](https://www.youtube.com/watch?v=hWIiyOV4Wbk&index=45&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
				* Python is a popular language and that is true as well within the Security industry. This talk will outline how Python code can be statically analyzed using publicly available tools such as bandit. It will then take a more technical approach and outline how the abstract syntax tree (AST) can be processed and searched based on behavior clues to identify potential security issues. Many security tools search for vulnerabilities by analyzing the contents of static strings and examining their variable names. This alternative approach instead demonstrates how the AST can be analyzed to identify pieces of sensitive information such as encryption keys and passwords based on matching them with usage patterns. This will be a technical talk focused on using automated techniques to find security vulnerabilities in Python projects. The audience will leave with an understanding of these techniques and how they can be applied to the projects they are either developing themselves or using in their daily routines. This talk will end with a live demonstration of a forked version of the public Bandit scanner where these techniques have been implemented.
		* **Tooling**
			* [Django-Security](https://github.com/sdelements/django-security)
				* This package offers a number of models, views, middlewares and forms to facilitate security hardening of Django applications.
			* [Bandit](https://github.com/PyCQA/bandit)
				* Bandit is a tool designed to find common security issues in Python code. To do this Bandit processes each file, builds an AST from it, and runs appropriate plugins against the AST nodes. Once Bandit has finished scanning all the files it generates a report.
			* [Dlint](https://github.com/duo-labs/dlint)
				* Dlint is a tool for encouraging best coding practices and helping ensure Python code is secure.	
			* [Pyre](https://github.com/facebook/pyre-check)
				* Pyre is a performant type checker for python.
			* [LibCST](https://github.com/Instagram/LibCST)
				* LibCST parses Python 3.0, 3.1, 3.3, 3.5, 3.6, 3.7 or 3.8 source code as a CST tree that keeps all formatting details (comments, whitespaces, parentheses, etc). It's useful for building automated refactoring (codemod) applications and linters. LibCST creates a compromise between an Abstract Syntax Tree (AST) and a traditional Concrete Syntax Tree (CST). By carefully reorganizing and naming node types and fields, we've created a lossless CST that looks and feels like an AST.
			* [Python Taint](https://github.com/python-security/pyt)
				* Static analysis of Python web applications based on theoretical foundations (Control flow graphs, fixed point, dataflow analysis)
			* [Safety](https://github.com/pyupio/safety)
				* Safety checks your installed dependencies for known security vulnerabilities.
	* **Ruby**
		* **Articles/Blogposts/Writeups**
			* [Static Analysis in Ruby - Jesus Castello](https://www.rubyguides.com/2015/08/static-analysis-in-ruby/)
			* [Code Smells - Reek](https://github.com/troessner/reek/blob/master/docs/Code-Smells.md)
				* Smells are indicators of where your code might be hard to read, maintain or evolve, rather than things that are specifically wrong. Naturally this means that Reek is looking towards your code's future (and that can make its reports seem somewhat subjective, of course).
			* [How to Find Ruby Code Smells with Reek - Piotr Szotkowski(2015)](https://rollout.io/blog/how-to-find-ruby-code-smells-with-reek/)
		* **Talks/Presentations/Videos**
			* [Ruby OOP Code Smells - Piotr Szotkowski](https://www.youtube.com/watch?v=pazYe7WRWRU)
		* **Tooling**
			* [RuboCop](https://github.com/rubocop-hq/rubocop)
				* RuboCop is a Ruby static code analyzer and code formatter. Out of the box it will enforce many of the guidelines outlined in the community Ruby Style Guide.
			* [brakeman](https://github.com/presidentbeef/brakeman)
				* A static analysis security vulnerability scanner for Ruby on Rails applications
			* [RubyCritic](https://github.com/whitesmith/rubycritic)
				* RubyCritic is a gem that wraps around static analysis gems such as Reek, Flay and Flog to provide a quality report of your Ruby code.
			* [Flog](https://github.com/seattlerb/flog)
				* Flog reports the most tortured code in an easy to read pain report. The higher the score, the more pain the code is in.
			* [Flay](https://github.com/seattlerb/flay)
				* Flay analyzes code for structural similarities. Differences in literal values, variable, class, method names, whitespace, programming style, braces vs do/end, etc are all ignored. Making this totally rad.
			* [Reek](https://github.com/troessner/reek)
				* Reek is a tool that examines Ruby classes, modules and methods and reports any Code Smells it finds.
			* [bundler-audit](https://github.com/rubysec/bundler-audit)
				* Patch-level verification for Bundler
	* **Rust**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
		* **Tooling**
			* [cargo-audit](https://github.com/RustSec/cargo-audit)
				* Audit Cargo.lock files for crates with security vulnerabilities
* **Infrastructure-as-Code Scanners & Linters** <a name="iaac"></a>
	* **Non-Specific**
		* [conftest](https://github.com/open-policy-agent/conftest)
			* Conftest helps you write tests against structured configuration data. Using Conftest you can write tests for your Kubernetes configuration, Tekton pipeline definitions, Terraform code, Serverless configs or any other config files.
		* [checkov](https://github.com/bridgecrewio/checkov)
			* Checkov is a static code analysis tool for infrastructure-as-code. It scans cloud infrastructure provisioned using Terraform, Cloudformation or kubernetes and detects security and compliance misconfigurations.
	* **AWS**
		* [CFRipper](https://github.com/Skyscanner/cfripper/)
			* CFRipper is a Library and CLI security analyzer for AWS CloudFormation templates. You can use CFRipper to prevent deploying insecure AWS resources into your Cloud environment. You can write your own compliance checks by adding new custom plugins.
		* [cfn_nag](https://github.com/stelligent/cfn_nag)
			* The cfn-nag tool looks for patterns in CloudFormation templates that may indicate insecure infrastructure.
		* [parliament](https://github.com/duo-labs/parliament/)
			* parliament is an AWS IAM linting library.
	* **Terraform**
		* [Regula](https://github.com/fugue/regula)
			* Regula is a tool that evaluates Terraform infrastructure-as-code for potential AWS, Azure, and Google Cloud security misconfigurations and compliance violations prior to deployment.
		* [tfsec](https://github.com/liamg/tfsec)
			* tfsec uses static analysis of your terraform templates to spot potential security issues. Now with terraform v0.12+ support.
		* [Terrascan](https://github.com/cesar-rodriguez/terrascan)
			* A collection of security and best practice tests for static code analysis of terraform templates using terraform_validate.
		* [Terrafirma](https://github.com/wayfair/terrafirma)
			* Terrafirma is a Terraform static analysis tool designed for detecting security misconfigurations. Inspired by projects such as bandit and SecurityMonkey it is designed for use in a continous integration/deployment environment.

## Application Security Pipeline <a name="appsecpipeline"></a>
* **General**
	* **Articles/Blogposts/Writeups**
		* [Scale your security with DevSecOps: 4 valuable mindsets and principles - Clint Gibler](https://techbeacon.com/devops/how-scale-security-devsecops-4-valuable-mindsets-principles)
		* [Lessons Learned from the DevSecOps Trenches - OWASP AppSec Cali 2019](https://tldrsec.com/blog/appsec-cali-2019-lessons-learned-from-the-devsecops-trenches/)
		* [Achieving DevSecOps with Open-Source Tools - notsosecure.com(2019)](https://www.notsosecure.com/achieving-devsecops-with-open-source-tools/)
	* **Talks/Presentations/Videos**
		* [How to 10X Your Company’s Security (Without a Series D) - Clint Gibler(BSidesSF2020)](https://www.youtube.com/watch?v=tWA_EBNsQH8&feature=emb_title)
			* [Slides](https://docs.google.com/presentation/d/1lfEvXtw5RTj3JmXwSQDXy8or87_BHrFbo1ZtQQlHbq0/mobilepresent?slide=id.g6555b225cd_0_1069)
			* I’ll summarize and distill the insights, unique tips and tricks, and actionable lessons learned from a vast number of DevSecOps/modern AppSec talks and blog posts, saving attendees 100s of hours. I’ll show where we’ve been, where we’re going, and provide a lengthy bibliography for further review.
		* [DevSecOps : What, Why and How - Anant Shrivastava(BHUSA 2019)](https://www.youtube.com/watch?v=DzX9Vi_UQ8o)
			* [Slides](https://i.blackhat.com/USA-19/Thursday/us-19-Shrivastava-DevSecOps-What-Why-And-How.pdf)
			* In this talk, we shall focus on how a DevOps pipeline can easily be metamorphosed into a DevSecOps and the benefits which can be achieved with this transformation. The talk (assisted with various demos) will focus on developing a DevSecOps pipeline using free/open-source tools in various deployment platforms, i.e. on-premise, cloud native and hybrid scenarios.
* **Continous Integration** <a name="ci"></a>
	* **Alerting**
	* **Git-related**
		* [githooks](https://githooks.com/)
			* Git hooks are scripts that Git executes before or after events such as: commit, push, and receive. Git hooks are a built-in feature - no need to download anything. Git hooks are run locally.
	* **Integration**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
		* **Tools**
			* [StackStorm](https://github.com/StackStorm/st2)
				* StackStorm (aka "IFTTT for Ops") is event-driven automation for auto-remediation, security responses, troubleshooting, deployments, and more. Includes rules engine, workflow, 160 integration packs with 6000+ actions (see https://exchange.stackstorm.org) and ChatOps.
	* **Testing**
	* **Policy as Code**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
			* [Security & Policy Configurations for Infrastructure as Code with Rosemary Wang - OWASP DevSlop - Tanya Janca, Nicole Becher, Rosemary Wang(2020)](https://www.youtube.com/watch?v=KOTXCIN0yE0&feature=share)
				* How can we enforce security and policy on our infrastructure by shifting configuration testing left? Reactively enforcing security does not scale for infrastructure as code. We explored techniques for proactively checking the security and policy of our infrastructure as code, using examples featuring Open Policy Agent and Terraform.
		* **Tools**
			* [DevSec Hardening Framework](https://github.com/dev-sec)
			* [serverspec](https://github.com/mizzy/serverspec)
				* RSpec tests for your servers configured by CFEngine, Puppet, Chef, Ansible, Itamae or anything else even by hand
			* [Chef InSpec](https://github.com/inspec/inspec)
				* Chef InSpec is an open-source testing framework for infrastructure with a human- and machine-readable language for specifying compliance, security and policy requirements.
			* [Test-kitchen](https://github.com/test-kitchen/test-kitchen)
				* Test Kitchen is an integration tool for developing and testing infrastructure code and software on isolated target platforms.
			* [inspec-iggy](https://github.com/mattray/inspec-iggy)
				* InSpec-Iggy (InSpec Generate -> "IG" -> "Iggy") is an InSpec plugin for generating compliance controls and profiles from Terraform tfstate files and AWS CloudFormation templates. Iggy generates InSpec controls by mapping Terraform and CloudFormation resources to InSpec resources and exports a profile that may be used from the inspec CLI and report to Chef Automate.
* **Continous Deployment** <a name="cd"></a>
	* **Articles/Blogposts/Writeups**
		* [Security-focused CI/CD Pipeline - alxk(2018)](https://alex.kaskaso.li/post/effective-security-pipeline)
			* In this post we’ll walk through the main components of a DevSecOps Continuous Integration pipeline. This will allow us to catch security issues both during development and on a continuous basis in production.
	* **Talks/Presentations/Videos**
		* [Open Source Speaker Series: Release Management in Large Free Software Projects - Martin Michlmayer(2007)](https://www.youtube.com/watch?v=IKsQsxubuAA)
			* Release management can be quite challenging in free software projects since the work of many distributed developers needs to be finished at the same time so it can be integrated and tested for the next release. It is particularly challenging in free software projects which mainly consist of volunteers because there is little control over the work performed by contributors. This talk will discuss what kind of problems free software projects face during release preparations and investigate how large volunteer teams can make releases on time and with high levels of quality. In particular, the focus will be on the time based release strategy. Instead of making release when particular functionality or set of features have been implemented, time based releases are made according to a specific time interval. This talk will argue that time based release management acts as an effective coordination mechanism in large volunteer projects and will show examples from a number of projects, including GNOME and X.org.	
		* [Releasing the World's Largest Python Site Every 7 Minutes](https://www.youtube.com/watch?v=2mevf60qm60)
			* Being able to release rapidly and continuously allows businesses to react to opportunities, shorten feedback loop for product iteration cycle and reduce debug effort for erroneous changes. At Instagram, we operate the world's largest fleet of servers running on Python and we continuously deploy every X minutes. Anyone can do it, this talk will teach you the practical steps and talk about the ideas and problems we faced at every phase of our automation journey.
	* **Papers**
		* [Time-Based Release Management in Free and Open Source (FOSS) Projects - Martin Michlmayr, Brian Fitzgerald(2012)](http://www.cyrius.com/publications/michlmayr_fitzgerald-time_based_release_management.pdf)
			* As the Free and Open Source (FOSS) concept has matured, its commercial significance has also increased, and issues such as quality and sustainability have moved to the fore. In this study, the authors focus on timebased release management in large volunteerFOSS projects, and reveal howthey address quality and sustainability issues. They discuss the differences between release management in the traditional software context and contrast it with FOSS settings. Based on detailed case studies of a number of prominent FOSS projects, they describe the move to time-based release management and identify the factors and criteria necessary for a successful transition. The authors also consider the implications for software development more generally in the current dynamic Internet-enabled environment.
	* **Tooling**
* **CI/CD Scanning Tooling/Approaches** <a name="cdscan"></a>
	* **Homegrown Implementing Scanner Tooling**
		* **Talks/Presentations/Videos**
			* [Scaling Security Assessment at the Speed of DevOps - Blake Hitchcock, Brian Manifold, Roger Seagle(OWASP AppSec USA2016 DC)](https://www.youtube.com/watch?v=hEHCB7iWUzk&index=24&list=PLpr-xdpM8wG8DPozMmcbwBjFn15RtC75N)
				* [...]Therefore, we have developed and are preparing to open source a new distributed security testing framework called Norad which facilitates security assessment at scale. This framework automates multiple open-source and vendor security tools and aggregates their results for review. It also provides an SDK which promotes the development of community developed security test content. This talk will explain Norad's design philosophy, architecture, and demonstrate its usage.
			* [Cleaning Your Applications' Dirty Laundry with Scumblr - Scott Behrens, Andrew Hoernecke(AppSecUSA 2016)](https://www.youtube.com/watch?v=XItlPMcUL38&app=desktop)
				* Attendees of this talk will get an understanding for how we designed a tool that has been successful in tackling a broad range of security challenges. We'll share our latest uses for the tools include details on how we're using Scumblr for vulnerability management, application risk tracking and other uses. Finally, we'll discuss how you can replicate what we've done by sharing new plugins that integrate with Arachni, AppSpider, Github, while also showing just how easy it is to create new integrations that open up new opportunities for automation, data collection and analysis.
			* [SCORE Bot: Shift Left, at Scale! - Vidhu Jayabalan - Laksh Raghavan(OWASP AppSecUSA2018)](https://www.youtube.com/watch?v=4rjmtdvrGrg)
				* In today’s DevSecOps world, “shift to the left” is not a new mantra for AppSec practitioners. It is imperative to notify developers about potential security issues as early as possible. While heavy-weight static and dynamic analysis tools and fuzzers exist to find generic technical security flaws, finding custom security issues that are specific to an organization’s proprietary frameworks, APIs, libraries, etc. is often tricky, time-consuming and expensive to capture and maintain as “custom rules” in those tools. IDE plug-ins are often messy to deploy and maintain at scale in the real-world when you are dealing with highly diverse programming languages/frameworks and thus various versions of different IDE products. Secure COde REview Bot (SCORE Bot) fills that gap and provides real-time, in-context security-oriented code review that focusses on org-specific security issues. It does that by automatically hooking into the GitHub Pull Request (PR) process and posts PR comments with not only the details about the identified security vulnerabilities but also remediation advice so that developers have actionable guidance to fix those security issues. Driven by insights from behavioral science and experimentation (A/B testing), SCORE Bot became our reliable eyes-and-ears of the code being written at PayPal and a trusted security peer reviewer for our developers. In this talk, we’ll share the lessons-learned from rolling out SCORE Bot at PayPal with details on what worked, what proved challenging with some real-world metrics from our deployment that scaled to cater to diverse programming languages, frameworks and CI/CD pipelines.
			* [Introducing Salus: How Coinbase scales security automation - Julian Borrey(DevSecCon2018)](https://www.youtube.com/watch?v=z_byZPlXzKM&app=desktop)
				* Coinbase is a company that empowers its developers to deploy fresh code to production just minutes after writing it yet there are has massive security requirements. Cryptocurrency companies are constantly being attacked, and Coinbase, which stores billions of dollars of irreversible cryptocurrency, is one of the biggest bounties on the internet. One of the pillars that allows us to maintain security in a CICD engineering organization is automated security scanning. Such scanners are often configured on a per-repository bases and may look for CVEs in dependencies or common anti-patterns that lead to vulnerabilities. In order for the Coinbase security team keep up with our ever growing product space, we built a tool that helps us centrally orchestrate our scanning pipeline on every project simultaneously. This tool is called Salus and is now being released free and open source. It is not necessarily easy to integrate security scanners en masse. A security team will start by finding relevant scanners and then inserting them into a project’s test suite. At first, when Coinbase had just a few projects, custom configuration for each repository worked fine. Each time the security team wanted to use a new scanner, update scanner configuration or roll out new policies, we updated each repository. As Coinbase scaled and became more polyglot, the time it took to maintain our security scanners rose dramatically until it was untenable to maintain strong scanning on every repository. As David Wheeler said, “All problems in computer science can be solved by another level of indirection.” Salus is our level of indirection to solve this problem. It is a docker container equipped with security scanners for many commonly used languages and frameworks as well a small ruby application used to coordinate the scanners. A developer can now add the Salus scanner to their test suite and on each build, it will pull down the latest Salus container, volume in their source code and execute the relevant scanners. We ensure that Salus results are immediately communicated to the developer and metrics about each project are communicated to the logging pipeline. Salus became a single place for the security team to make changes to the scanning pipeline that would be instantly applied org wide. Metrics aggregation also allowed for immediate insight into possible dangers as new vulnerabilities are discovered or to keep a pulse on the aggregate security posture of the company. Today, Ruby, Node, Python, Go, Shell and arbitrary pattern searches are represented in Salus and this will expand in the future as the project evolves. This talk aims to explain how an engineering team can start using Salus to enable them to stay safe with as little friction and effort as possible.
			* [Orchestrating Security Tools with AWS Step Functions - (LASCON2019)](https://www.youtube.com/watch?v=TGBTrshyE9Y&list=PLLWzQe8KOh5kiARJe_i-im28No_mt_b_z&index=46)
				* Increasingly frequent deployments make it impossible for security teams to manually review all of the code before it is released. We wrote a Terraform-deployed application to solve this problem by tightly integrating into the developer workflow. The plugin-based application has three core components, each represented by at least one lambda function: a trigger, processing and analysis, and output. The plugins, such a static analysis, dependency checking, github integrations, container security scanning, or secret leak detection can be written in any language supported by AWS Lambda. The underlying technology for this tool is a serverless system utilizing several AWS Services, such as API Gateways, Step Functions and Lambdas. In this talk you'll not only learn about our tool and how to implement it in your CI/CD pipeline, but also how to easily deploy complex serverless systems and step functions for your own automated tooling.
		* **Tooling**
			* [Jaeles](https://github.com/jaeles-project/jaeles)
				* framework written in Go for building your own Web Application Scanner.
			* [Predator](https://github.com/s0md3v/Predator)
				* Predator is a prototype web application designed to demonstrate anti-crawling, anti-automation & bot detection techniques. It can be used a honeypot, anti-crawling system or a false positive test bed for vulnerability scanners.
			* [Reapsaw](https://github.com/dowjones/reapsaw)
				* Reapsaw is an orchestration platform for various security tools (static and run-time) which helps in identifying different types of security bugs during the process (open source vulnerabilities, static code security bugs, insecure functions, secrets in code, authentication bypass etc.). It can be easily integrated into already-established process and tools in an organizations SDLC, bug trackers, source repositories and other testing tools. Being CI/CD friendly,once enabled within the CI pipeline, reapsaw will help in identifying very high fidelity and low false positive bugs into developers backlog. This will enable in quick feedback and provide developers friendly recommendations on fixes.
				* [Zero to Hero: Continuous Security with Reapsaw - Pranav Patel(2019)](https://medium.com/dowjones/zero-to-hero-continuous-security-with-reapsaw-656bab07566c)
			* [OWASP Benchmark](https://github.com/OWASP/Benchmark)
				* The OWASP Benchmark Project is a Java test suite designed to verify the speed and accuracy of vulnerability detection tools. It is a fully runnable open source web application that can be analyzed by any type of Application Security Testing (AST) tool, including SAST, DAST (like OWASP ZAP), and IAST tools. The intent is that all the vulnerabilities deliberately included in and scored by the Benchmark are actually exploitable so its a fair test for any kind of application vulnerability detection tool. The Benchmark also includes scorecard generators for numerous open source and commercial AST tools, and the set of supported tools is growing all the time.
* **(DIY) Building an AppSec Pipeline** <a name="cddiy"></a>
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
		* [Building a Secure DevOps Pipeline - Matt Tesauro, Aaron Weaver(OWASP AppSecUSA 2017)](https://www.youtube.com/watch?v=IAzPKzwY-ks)
			* Is software development outpacing your ability to secure your company’s portfolio of apps?  You don’t have to buy into Agile, DevOps or CI/CD to realize the business wants to move faster.  And it's not like you didn’t already have more than enough to do. This talk will cover how to take the lessons learned from forward thinking software development and show you how they have been applied across several business.  This isn’t a theoretical talk.  It covers the results of  successfully applying these strategies to AppSec across multiple companies ranging from 4,000 to 40,000+ employees.  Yes, real stats on improvements seen will be provided. By changing focus from a point in time security testing and assessments to automation, continual health checks and event-based security, your AppSec program can start to keep pace with the increasing speed of delivery your business is trying to obtain.  By embracing the same methodologies, you can turn Docker from a problem to how you horizontally scale your security work.  Don't swim against the current of DevOps, Agile software development and Continuous Delivery. Instead use those movements to speed your AppSec program to new levels.
		* [`*`AST In CI/CD – how to make it WORK! - Ofer Maor(DevSecCon Singapore 2018)](https://www.youtube.com/watch?v=eY3RmQ_eNgA)
			* SAST, IAST, DAST, MAST, `*`AST – There are plenty of technologies and ways to test your software, but how do we do that without slowing us down in a rapid development environment. In this talk we will give practical advice on how to integrate software security testing into your CI/CD and your development process so it works. The talk will review the pros and cons of each of the testing technologies, and how to adapt it to rapid development, and how to manage the balance between risk and speed to build a proper signoff process, so that real threats will become blockers, but other issues will be handled in a parallel slower cycle, without slowing down the main delivery.
		* [Creating An AppSec Pipeline With Containers In A Week: How We Failed And Succeeded - Jeroen Willemsen(OWASP AppSecEU Belfast 2017)](https://www.youtube.com/watch?v=3PgWM8qwWas)
			* Join us on our adventure of setting up a appsec pipeline with Docker containers. What did go wrong, how did we succeed? How do you fight false positives and how do you get the best out of the products out there without bothering the development teams too much.
		* [Securing without Slowing DevOps - Wolfgang Goerlich - Circle City Con 5.0](https://www.youtube.com/watch?v=y8MopriNaMo&feature=youtu.be)
	* **Tooling**
		* [pre-commit](https://pre-commit.com/)
			* A framework for managing and maintaining multi-language pre-commit hooks.
		* [Danger.JS](https://danger.systems/js/)
			* Danger runs during your CI process, and gives teams the chance to automate common code review chores. This provides another logical step in your build, through this Danger can help lint your rote tasks in daily code review. You can use Danger to codify your teams norms. Leaving humans to think about harder problems. This happens by Danger leaving messages inside your PRs based on rules that you create with JavaScript or TypeScript. Over time, as rules are adhered to, the message is amended to reflect the current state of the code review.
	* **Encrypting Commits**
		* [git-crypt - transparent file encryption in git](https://www.agwa.name/projects/git-crypt/)
			* git-crypt enables transparent encryption and decryption of files in a git repository. Files which you choose to protect are encrypted when committed, and decrypted when checked out. git-crypt lets you freely share a repository containing a mix of public and private content. git-crypt gracefully degrades, so developers without the secret key can still clone and commit to a repository with encrypted files. This lets you store your secret material (such as keys or passwords) in the same repository as your code, without requiring you to lock down your entire repository.
		* [git-secret](https://git-secret.io/)
			* git-secret is a bash tool to store your private data inside a git repo. How’s that? Basically, it just encrypts, using gpg, the tracked files with the public keys of all the users that you trust. So everyone of them can decrypt these files using only their personal secret key. Why deal with all this private-public keys stuff? Well, to make it easier for everyone to manage access rights. There are no passwords that change. When someone is out - just delete their public key, reencrypt the files, and they won’t be able to decrypt secrets anymore.
	* **Removing Secrets from Commits/Repo**
		* **Articles/BLogposts/Writeups**
			* [Removing sensitive data from a repository - github](https://help.github.com/en/github/authenticating-to-github/removing-sensitive-data-from-a-repository)
			* [Exposing secrets on GitHub: What to do after leaking credentials and API keys - Mackenzie Jackson](https://blog.gitguardian.com/leaking-secrets-on-github-what-to-do/)
			* [GitHub for Bug Bounty Hunters - Ed Overflow](https://edoverflow.com/2017/github-for-bugbountyhunters/)
			* [Credential mitigation in large-scale organizations - Tobias Gabriel, Nikolas Kratzschmar(GitHub Satellite 2020)](https://www.youtube.com/watch?v=kCo0OJZHRX8)
			* [“CI Knew There Would Be Bugs Here” — Exploring Continuous Integration Services as a Bug Bounty Hunter - Ed Overflow](https://edoverflow.com/2019/ci-knew-there-would-be-bugs-here/)
		* **Tools**
			* [git-secrets](https://github.com/awslabs/git-secrets)
				* git-secrets scans commits, commit messages, and --no-ff merges to prevent adding secrets into your git repositories. If a commit, commit message, or any commit in a --no-ff merge history matches one of your configured prohibited regular expression patterns, then the commit is rejected.
			* [gitleaks](https://github.com/zricethezav/gitleaks)
				* Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks aims to be the easy-to-use, all-in-one solution for finding secrets, past or present, in your code.
			* [tartufo](https://github.com/godaddy/tartufo)
				* tartufo searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed. tartufo also can be used by git pre-commit scripts to screen changes for secrets before they are committed to the repository.
			* [gitignore](https://github.com/github/gitignore)
				* This is GitHub’s collection of .gitignore file templates. We use this list to populate the .gitignore template choosers available in the GitHub.com interface when creating new repositories and files.
			* [talisman](https://github.com/thoughtworks/talisman)
				* Talisman is a tool that installs a hook to your repository to ensure that potential secrets or sensitive information do not leave the developer's workstation. It validates the outgoing changeset for things that look suspicious - such as potential SSH keys, authorization tokens, private keys etc.
			* [detect-secrets](https://github.com/Yelp/detect-secrets)
				* detect-secrets is an aptly named module for (surprise, surprise) detecting secrets within a code base. However, unlike other similar packages that solely focus on finding secrets, this package is designed with the enterprise client in mind: providing a backwards compatible, systematic means of: Preventing new secrets from entering the code base, Detecting if such preventions are explicitly bypassed, and Providing a checklist of secrets to roll, and migrate off to a more secure storage.
			* [Git-Hound](https://github.com/ezekg/git-hound)
				* Hound is a Git plugin that helps prevent sensitive data from being committed into a repository by sniffing potential commits against PCRE regular expressions.
			* [RepoSsessed](https://github.com/IOActive/RepoSsessed)
				* RepoSsessed is a project designed to parse public source code repositories and find various types of vulnerabilities. The current focus is on finding secrets, but see the Next Steps section to see what is being added.
			* [truffleHog](https://github.com/dxa4481/truffleHog)
				* Searches through git repositories for high entropy strings and secrets, digging deep into commit history
* **Static Analysis Approaches & Tooling** <a name="static"></a>
	* **Articles/Blogposts/Writeups**
		* [Static Analysis at Scale: An Instagram Story - Benjamin Woodruff(2019)](https://instagram-engineering.com/static-analysis-at-scale-an-instagram-story-8f498ab71a0c)
		* [Scaling Static Analyses at Facebook - ino Distefano, Manuel Fähndrich, Francesco Logozzo, Peter W. O'Hearn(2019)](https://cacm.acm.org/magazines/2019/8/238344-scaling-static-analyses-at-facebook/fulltext)
			* Static analysis tools are programs that examine, and attempt to draw conclusions about, the source of other programs without running them. At Facebook, we have been investing in advanced static analysis tools that employ reasoning techniques similar to those from program verification. The tools we describe in this article (Infer and Zoncolan) target issues related to crashes and to the security of our services, they perform sometimes complex reasoning spanning many procedures or files, and they are integrated into engineering workflows in a way that attempts to bring value while minimizing friction.
		* [Zoncolan: How Facebook uses static analysis to detect and prevent security issues](https://engineering.fb.com/security/zoncolan/)
	* **Talks/Presentations/Videos**
		* [Rolling Your Own: How to Write Custom, Lightweight Static Analysis Tools - ](https://www.youtube.com/watch?v=n6sFCrKQT3I)
			* [Slides](https://docs.google.com/presentation/d/1S0o4d2tN2buv3FNszu4n47wNOChF-5UWLv-XxgN1CBI)
		* [Practical Static Analysis for Continuous Application Security - Justin Collins(OWASP AppSecUSA 2016)](https://www.youtube.com/watch?v=VXJNuDV6DQo&index=18&list=PLpr-xdpM8wG8DPozMmcbwBjFn15RtC75N)
			* Static code analysis tools that attempt determine what code does without actually running the code provide an excellent opportunity to perform lightweight security checks as part of the software development lifecycle. Unfortunately, building generic static analysis tools, especially for security, is a costly, time-consuming effort. As a result very few tools exist and commercial tools are very expensive - if they even support your programming language. The good news is building targeted static analysis tools for your own environment with rules specific to your needs is much easier! Since static analysis tools can be run at any point in the software development lifecycle, even simple tools enable powerful security assurance when added to continuous integration. This talk will go through straight-forward options for static analysis, from grep to writing rules for existing tools through writing static analysis tools from scratch.
		* [Static Analysis Security Testing for Dummies… and You - Kevin Fealey(LASCON 2015)](https://www.youtube.com/watch?v=QTVxASPP2LA)
			* In this talk, we’ll help you understand the strengths and weaknesses of SAST tools by illustrating how they trace your code for vulnerabilities. You’ll see out-of-the-box rules for commercial and open-source SAST tools, and learn how to write custom rules for the widely-used open source SAST tool, PMD. We’ll explain the value of customizing tools for your organization; and you’ll learn how to integrate SAST technologies into your existing build and deployment pipelines. Lastly, we’ll describe many of the common challenges organizations face when deploying a new security tool to security or development teams, as well as some helpful hints to resolve these issues
		* [Static analysis for code and infrastructure​ - Nick Jones(DevSecCon2016)](https://www.youtube.com/watch?v=vJbh711yRNk)
			* Many will likely have seen or used static analysis tools in the past, but they’re often poorly understood. This talk covers the theory behind a number of the techniques commonly used to analyze applications, including taint checking and analysis of control flow graphs and field initializations. After covering the benefits and pitfalls that these techniques bring to the table, it then goes on to address how to best fit these tools into your development environment and infrastructure, demonstrate how to catch software bugs early in your development cycle and how analysis maContinousy be applied to infrastructure as code definitions.
		* [Variant Analysis – A critical step in handling vulnerabilities - Kevin Backhouse(DevSecCon London 2018)](https://www.youtube.com/watch?v=6WwP7eUY52Y&app=desktop)
			* In software development, we frequently see the same logical coding mistakes being made repeatedly over the course of a project’s lifetime, and sometimes across multiple projects. Sometimes there are a number of simultaneously active instances of these mistakes, and sometimes there’s only ever one active instance at a time, but it keeps reappearing. When these mistakes lead to security vulnerabilities, the consequences can be severe. With each vulnerability discovered or reported, if the root cause was a bug in the code, we’re presented with an opportunity to investigate how often this mistake is repeated, whether there are any other unknown vulnerabilities as a result, and implement a process to prevent it reappearing. In this talk, I’ll be introducing Variant Analysis, a process for doing just this, and discuss how it can be integrated into your development and security operations. I’ll also be sharing real-world stories of what has happened when variant analysis was neglected, as well as stories of when it’s saved the day.
		* [Automated Discovery of Deserialization Gadget Chains - Ian Haken(BHUSA 2018)](https://www.youtube.com/watch?v=MTfE2OgUlKc)
			* Although vulnerabilities stemming from the deserialization of untrusted data have been understood for many years, unsafe deserialization continues to be a vulnerability class that isn't going away. Attention on Java deserialization vulnerabilities skyrocketed in 2015 when Frohoff and Lawrence published an RCE gadget chain in the Apache Commons library and as recently as last year's Black Hat, Muñoz and Miroshis presented a survey of dangerous JSON deserialization libraries.
	* **Papers**
		* [Tricorder: Building a Program Analysis Ecosystem - Caitlin Sadowski, Jeffrey van Gogh, Ciera Jaspan, Emma Söderberg, Collin Winter(2015)](https://research.google/pubs/pub43322/)
			* Static analysis tools help developers find bugs, improve code readability, and ensure consistent style across a project. However, these tools can be difficult to smoothly integrate with each other and into the developer workflow, particularly when scaling to large codebases. We present TRICORDER, a program analysis platform aimed at building a data-driven ecosystem around program analysis. We present a set of guiding principles for our program analysis tools and a scalable architecture for an analysis platform implementing these principles. We include an empirical, in-situ evaluation of the tool as it is used by developers across Google that shows the usefulness and impact of the platform.
		* [What Developers Want and Need from Program Analysis: An Empirical Study - Maria Christakis, Christian Bird(2016)](https://www.microsoft.com/en-us/research/uploads/prod/2016/07/What-Developers-Want-and-Need-from-Program-Analysis-An-Empirical-Study.pdf)
			* Program Analysis has been a rich and fruitful field of research for many decades, and countless high quality program analysis tools have been produced by academia. Though there are some well-known examples of tools that have found their way into routine use by practitioners, a common challenge faced by researchers is knowing how to achieve broad and lasting adoption of their tools. In an effort to understand what makes a program analyzer most attractive to developers, we mounted a multi-method investigation at Microsoft. Through interviews and surveys of developers as well as analysis of defect data, we provide insight and answers to four high level research questions that can help researchers design program analyzers meeting the needs of software developers. First, we explore what barriers hinder the adoption of program analyzers, like poorly expressed warning messages. Second, we shed light on what functionality developers want from analyzers, including the types of code issues that developers care about. Next, we answer what non-functional characteristics an analyzer should have to be widely used, how the analyzer should fit into the development process, and how its results should be reported. Finally, we investigate defects in one of Microsoft’s flagship software services, to understand what types of code issues are most important to minimize, potentially through program analysis.
	* **Tooling**
		* **Config-Mgmt**
			* [Checkov](https://github.com/bridgecrewio/checkov)
				* Checkov is a static code analysis tool for infrastructure-as-code. It scans cloud infrastructure provisioned using Terraform or cloudformation and detects security and compliance misconfigurations. Checkov is written in Python and provides a simple method to write and manage policies. It follows the CIS Foundations benchmarks where applicable.
		* **Custom-Static Analyzer(Build-Your-Own)**
			* [SPARTA](https://github.com/facebookincubator/SPARTA)
				* SPARTA is a library of software components specially designed for building high-performance static analyzers based on the theory of Abstract Interpretation.
			* [ANTLR](https://github.com/antlr/antlr4)
				* ANTLR (ANother Tool for Language Recognition) is a powerful parser generator for reading, processing, executing, or translating structured text or binary files. It's widely used to build languages, tools, and frameworks. From a grammar, ANTLR generates a parser that can build parse trees and also generates a listener interface (or visitor) that makes it easy to respond to the recognition of phrases of interest.
			* [bblfshd](https://github.com/bblfsh/bblfshd)
				* A self-hosted server for source code parsing
			* [PhASAR](https://phasar.org/phasar/)
				* PhASAR is a LLVM-based static analysis framework written in C++. The framework allows for solving arbitrary (decidable) data-flow problems on the LLVM intermediate representation (IR).
		* **Tool Coordination/Orchestration**
			* [Salus](https://github.com/coinbase/salus)
				* Salus (Security Automation as a Lightweight Universal Scanner), named after the Roman goddess of protection, is a tool for coordinating the execution of security scanners. You can run Salus on a repository via the Docker daemon and it will determine which scanners are relevant, run them and provide the output. Most scanners are other mature open source projects which we include directly in the container.
* **Dynamic Analysis - Continuous Scanning** <a name="dynscan"></a>
	* See [Fuzzing](Fuzzing.md)
	* **Articles/Blogposts/Writeups**
	* **Talks & Presentations**
		* [Differences Between Web Application Scanning Tools when Scanning for XSS and SQLi - Robert Feeney(AppSecUSA 2017)](https://www.youtube.com/watch?v=VO2uBSfXZso)
			* This presentation addresses the problems that current web application scanners face in dealing with both traditional and contemporary web architectures and technologies. It suggests improvements and identifies pitfalls of using automation without applying intelligence and a contextual view of the target being assessed.
		* [Continous Security in The DevOps World - Julien Vehent](https://jvehent.github.io/continuous-security-talk/#/)
		* [Test Driven Security in the DevOps pipeline - Julien Vehent(AppSecUSA 2017)](https://www.youtube.com/watch?v=1Nlbf7XXn7s)
			* The myth of attackers breaking through layers of firewalls or decoding encryption with their smartphones makes for great movies, but poor real world examples. In the majority of cases, attackers go for easy targets: web frameworks with security vulnerabilities, out of date systems, administration pages open to the Internet with guessable passwords or security credentials mistakenly leaked in open source code are all popular candidates. The goal of Test Driven Security is to take care of the baseline: apply elementary sets of controls on applications and infrastructures, and test them continuously, directly inside the DevOps deployment pipeline.
		* [Practical Tips for Defending Web Applications in the Age of DevOps - Zane Lackey(BHUSA2017)](https://www.youtube.com/watch?v=IvdKtf3ol2U)
			* This talk will share practical lessons learned at Etsy on the most effective application security techniques in todays increasingly rapid world of application creation and delivery. Specifically, it will cover how to: Adapt traditionally heavyweight controls like static analysis and dynamic scanning to lightweight efforts that work in modern development and deployment practices; Obtain visibility to enable, rather than hinder, development and DevOps teams ability to iterate quickly; Measure maturity of your organizations security efforts in a non-theoretical way
			* * [How to adapt the SDLC for DevSecOps - Zane Lackey(InsomniHack2018)](https://www.youtube.com/watch?v=o1f5BU6z-Kg)
	* **Tooling**
		* [fuzz-lightyear](https://github.com/Yelp/fuzz-lightyear)
			* A pytest-inspired, DAST framework, capable of identifying vulnerabilities in a distributed, micro-service ecosystem through chaos engineering testing and stateful, Swagger fuzzing.
* **Dependency Management** <a name="depmgmt"></a>
	* **Articles/Blogposts/Writeups**
		* [Creating a Comprehensive 3rd-Party Package License Policy for OSS - Kate Downing](https://fossa.com/blog/creating-a-comprehensive-third-party-package-license-policy/)
	* **Talks/Presentations/Videos**
		* [Practical Approach to Automate the Discovery & Eradication of Open-Source Software Vulnerabilities - Aladdin Almubayed(BHUSA2019)](https://www.youtube.com/watch?v=ks9J0uZGMh0)
			* Over the last decade, there has been steady growth in the adoption of open-source components in modern web applications. Although this is generally a good trend for the industry, there are potential risks stemming from this practice that requires careful attention. In this talk, we will describe a simple but pragmatic approach to identifying and eliminating open-source vulnerabilities in Netflix applications at scale.
			* [Slides](https://i.blackhat.com/USA-19/Thursday/us-19-Almubayed-Practical-Approach-To-Automate-The-Discovery-And-Eradication-Of-Open-Source-Software-Vulnerabilities-At-Scale.pdf)
		* [Use Case – Astrid: Artifactory-Sourced Dependency Insight at Netflix - Artifactory](https://www.youtube.com/watch?list=PLY0Zjn5rFo4NHb-5fdiMzNJFan9_raiF_&v=hJWlg4PFWzk)
			* With a dependency management strategy based solely on binary integration, Netflix successfully performs thousands of production changes per day with only tens of operations engineers and no NOC. This success is due in large part to tools and techniques developed to allow product engineering teams to move quickly with as much context as possible. Astrid stitches together information from as low level as a Java method call to thousand-plus instance auto scaling groups in AWS to provide engineers with a multi-dimensional view of the impact of a piece of code on the Netflix ecosystem. We will provide a live demonstration early access view of Astrid, which Netflix plans to open source in 2016.
			* Never opensourced.
	* **Tools**
		* [Dependency-Check](https://github.com/jeremylong/DependencyCheck)
			* Dependency-Check is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project's dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries.
		* [LibScout](https://github.com/reddr/LibScout)
			* LibScout is a light-weight and effective static analysis tool to detect third-party libraries in Android/Java apps. The detection is resilient against common bytecode obfuscation techniques such as identifier renaming or code-based obfuscations such as reflection-based API hiding or control-flow randomization. Further, LibScout is capable of pinpointing exact library versions including versions that contain severe bugs or security issues.
		* [third-party-lib-analyzer](https://github.com/jtmelton/third-party-lib-analyzer)
			* A tool for analyzing third party libraries and how they connect to user classes. TPLA constructs a graph database of all dependencies, user classes, and relationships between all classes. It also allows some built in queries to be executed with reports generated based on the results.
		* [bundler-audit](https://github.com/rubysec/bundler-audit)
			* Patch-level verification for bundler.
* **Metrics** <a name="metrics"></a>
	* **Articles/Blogposts/Writeups**
		* [Magic Numbers: An In-Depth Guide to the 5 Key Performance Indicators for Web Application Security](https://owasp.org/www-pdf-archive/Magic_Numbers_-_5_KPIs_for_Measuring_WebAppSec_Program_Success_v3.2.pdf)
		* [Using Metrics to Manage Your Application Security Program - Jim Bird(2016)](https://www.veracode.com/sites/default/files/Resources/Whitepapers/using-metrics-to-manage-your-application-security-program-sans-veracode.pdf)
		* [How we use activity-oriented metrics @justeat_tech - Simone Basso](https://medium.com/@smnbss/how-we-use-activity-oriented-metrics-6d85c6f9d400)
	* **Talks/Presentations/Videos**
		* [Domino's Delivery of a Faster Response was No Standard Order - Michael Sheppard(AppSecUSA2018)](https://www.youtube.com/watch?v=BxXV1pVSMn0&feature=youtu.be&t=1751)
			* Come listen to Domino's Pizza share how they transformed a complex, multi-ticket, time-consuming process into an Automated Application Security Engagement workflow. Using deep knowledge of Atlassian tools, a little ingenuity, and a lot of ITSM, a great partner in Forty8Fifty Labs, Security Enablement approach and DevOps best practices, Domino's Information Security Team responds faster than ever.
		* [Measuring End-to-End Security Engineering - Davit Baghdasaryan, Garret Held(AppSecUSA 2017)](https://www.youtube.com/watch?v=MLmQ4uSi4EU)
			* This talk will introduce a new approach to SDL. At Twilio we call it End to End Security Engineering. It’s End-to-End because it covers the full product lifecycle, from Security Design to Monitoring and gives the ability to measure the state of security at each point.The approach defines a ‘perfect secure system’ and produces metrics which tell us where we are relative to that perfect system. The final state of the product’s security and risk depends on ‘collective understanding’ of threats and attacks as well as investments in building controls, tests and detections. Then we measure and adjust them to improve their effectiveness.
		* [Software Security Metrics - Caroline Wong(OWASP AppSec Cali2016)](https://www.youtube.com/watch?v=50vOxExpAOU)
			* [Slides](https://www.slideshare.net/Cigital/software-security-metrics)
			* More often than not, company executives ask the wrong questions about software security.  This session will discuss techniques for changing the conversation about software security in order to encourage executives to ask the right questions – and provide answers that show progress towards meaningful objectives.  Caroline will discuss a progression of software security capabilities and the metrics that correspond to different levels of maturity.  She’ll discuss an approach for developing key metrics for your unique software security program and walk through a detailed example.
		* [Effective AppSec Metrics - Caroline Wong(OWASP SF 2017)](https://www.youtube.com/watch?v=dY8IuQ8rUd4)
			* Executives often ask the wrong questions about application security. This session will discuss techniques for changing the conversation in order to encourage execs to ask the right questions—and provide data-driven answers that show progress towards meaningful objectives.
		* [Starting a metrics program - Marcus Ranum(OWASP AppSec California 2016)](https://www.youtube.com/watch?v=yW7kSVwucSk)
			* Security practitioners constantly bemoan their difficulty in communicating effectively with business units or senior management. The key, of course, is using the right language - namely, metrics. In this presentation we'll outline a bunch of useful things you should know about setting up your own metrics process.
* **Automated Response** <a name="auto"></a>
	* **Articles/Blogposts/Writeups**
		* [Put Your Robots to Work: Security Automation at Twitter - Justin Collins, Neil Matatall, Alex Smolen(OWASP AppSecUSA 2012)](https://www.youtube.com/watch?v=Ivc5Sj0nj2c&app=desktop)
			* With daily code releases and a growing infrastructure, manually reviewing code changes and protecting against security regressions quickly becomes impractical. Even when using security tools, whether commercial or open source, the difficult work of integrating them into the development and security cycles remains. We need to use an automated approach to push these tools as close to when the code is written as possible, allowing us to prevent potential vulnerabilities before they are shipped. We worked with development, operations, and release teams to create a targeted suite of tools focused on specific security concerns that are effective and don't introduce any noise. This presentation will give an overview of what we've done over the past year, what we have learned along the way, and will provide advice for anyone else going down this road.
	* **Tools**
		* [Providence](https://github.com/salesforce/Providence)
			* Providence is a system for code commit & bug system monitoring. It is deployed within an organization to monitor code commits for security (or other) concerns, via customizable plugins. A plugin performs logic whenever a commit occurs.
			* [Blogpost](https://engineering.salesforce.com/announcing-providence-rapid-vulnerability-prevention-3505ffd17e17)


## Programming <a name="programming"></a>

### APIs <a name="apis"></a>
* **101**
	* [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist/)
		* Checklist of the most important security countermeasures when designing, testing, and releasing your API
* **General/Articles/Writeups**
	* [RESTful API Best Practices and Common Pitfalls - Spencer Schneidenbach](https://medium.com/@schneidenbach/restful-api-best-practices-and-common-pitfalls-7a83ba3763b5)
	* [White House Web API Standards](https://github.com/WhiteHouse/api-standards)
		* This document provides guidelines and examples for White House Web APIs, encouraging consistency, maintainability, and best practices across applications. White House APIs aim to balance a truly RESTful API interface with a positive developer experience (DX).
	* [HTTP API Design Guide](https://github.com/interagent/http-api-design)
		* HTTP API design guide extracted from work on the [Heroku Platform API](https://devcenter.heroku.com/articles/platform-api-reference)
* **Tools**
	* [Syntribos](https://github.com/openstack/syntribos)
		* Syntribos is an open source automated API security testing tool that is maintained by members of the [OpenStack Security Project](https://wiki.openstack.org/wiki/Security). Given a simple configuration file and an example HTTP request, syntribos can replace any API URL, URL parameter, HTTP header and request body field with a given set of strings. Syntribos iterates through each position in the request automatically. Syntribos aims to automatically detect common security defects such as SQL injection, LDAP injection, buffer overflow, etc. In addition, syntribos can be used to help identify new security defects by automated fuzzing.

---------
### Assembly x86/x64/ARM <a name="asm"></a>
* **101**
	* [x86 Assembly - Wikipedia](https://en.wikipedia.org/wiki/X86)
	* [x86-64 Assembly - Wikipedia](https://en.wikipedia.org/wiki/X86-64)
* **General/Articles/Writeups**
	* [Mov is turing complete](http://www.cl.cam.ac.uk/~sd601/papers/mov.pdf)
* Learning
	* [Guide to x86 Assembly](http://www.cs.virginia.edu/~evans/cs216/guides/x86.html)
	* [Intro to x86 calling conventions](http://codearcana.com/posts/2013/05/21/a-brief-introduction-to-x86-calling-conventions.html)
	* [Reading ASM](http://cseweb.ucsd.edu/classes/sp11/cse141/pdf/02/S01_x86_64.key.pdf)
	* [Machine-Level Representation of Programs](https://2013.picoctf.com//docs/asmhandout.pdf)
	* [Intro to x86 - OpensSecurityTraining.info](http://opensecuritytraining.info/IntroX86.html)
	* [cgasm](https://github.com/bnagy/cgasm)
		* cgasm is a standalone, offline terminal-based tool with no dependencies that gives me x86 assembly documentation. It is pronounced "SeekAzzem".
	* [x86 Assembly Crash Course](https://www.youtube.com/watch?v=75gBFiFtAb8)
	* [Intro to x86 Assembly Language - DavyBot(Youtube Video Playlist)](https://www.youtube.com/watch?v=wLXIWKUWpSs&list=PLmxT2pVYo5LB5EzTPZGfFN0c2GDiSXgQe)
	* [Learning assembly for linux-x64](https://github.com/0xAX/asm)
	* [Introduction to writing x86 assembly code in Visual Studio](http://lallouslab.net/2014/07/03/introduction-to-writing-x86-assembly-code-in-visual-studio/)
	* [Introduction to writing x64 assembly in Visual Studio](http://lallouslab.net/2016/01/11/introduction-to-writing-x64-assembly-in-visual-studio/)
	* [x86 Call/Return Protocol](http://pages.cs.wisc.edu/~remzi/Classes/354/Fall2012/Handouts/Handout-CallReturn.pdf)
* Reference
	* [Nasm x86 reference](https://www.cs.uaf.edu/2006/fall/cs301/support/x86/)
	* [x86 Assembly Guide/Reference - Wikibooks](https://en.wikibooks.org/wiki/X86_Assembly)
		* Introduction for those who don’t know ASM and a reference for those that do.
	* [x86 Disassembly/Calling Conventions](https://en.wikibooks.org/wiki/X86_Disassembly/Calling_Conventions)
	* [x86 Disassembly/Calling Convention Examples](https://en.wikibooks.org/wiki/X86_Disassembly/Calling_Convention_Examples)
	* [sandpile.org](http://www.sandpile.org/)
		* The world's leading source for technical x86 processor information.
		* Good source of reference docs/images for x86 ASM
	* [Walkthrough: Creating and Using a Dynamic Link Library (C++)](https://msdn.microsoft.com/en-us/library/ms235636.aspx)
	* [Intel x86 Assembler Instruction Set Opcode Table](http://sparksandflames.com/files/x86InstructionChart.html)
* **Videos**
	* [Introduction Video Series(6) to x86 Assembly](https://www.youtube.com/watch?v=qn1_dRjM6F0&list=PLPXsMt57rLthf58PFYE9gOAsuyvs7T5W9)
	* [Intro to x86 - Derbycon5](http://www.irongeek.com/i.php?page=videos/derbycon5/stable34-intro-to-x86-stephanie-preston)
* **Tools**
	* [WinREPL](https://github.com/zerosum0x0/WinREPL)
		* x86 and x64 assembly "read-eval-print loop" shell for Windows
	* [aslrepl](https://github.com/enferex/asrepl)
		* asrepl is an assembly based REPL. The REPL processes each line of user input, the output can be witnessed by issuing the command 'regs' and looking at the register state.


----------
### Android (Kotlin/Android Java) <a name="android"></a>
* [Kotlin - Wikipedia](https://en.wikipedia.org/wiki/Kotlin_(programming_language))
* [Java - Wikipedia](https://en.wikipedia.org/wiki/Java_(programming_language))
* **Learn**
	* [Android Secure Coding Standard](https://www.securecoding.cert.org/confluence/display/android/Android+Secure+Coding+Standard)
* **Reference**
* **Tools**
	* [java-aes-crypto (Android class)](https://github.com/tozny/java-aes-crypto)
		* A simple Android class for encrypting & decrypting strings, aiming to avoid the classic mistakes that most such classes suffer from.
	* [smalisca](https://github.com/dorneanu/smalisca)
		* Static Code Analysis for Smali files



----------
### Bash <a name="bash"></a>
* [Bash - GNU](https://www.gnu.org/software/bash/)
* [Bash (Unix shell) - Wikipedia](https://en.wikipedia.org/wiki/Bash_(Unix_shell))
*  **Learn**
	* [BASH Programming - Introduction HOW-TO - tldp](http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html)
	* [Community Bash Style Guide](https://github.com/azet/community_bash_style_guide)
	* [The Bash Guide - A quality-driven guide through the shell's many features.](https://guide.bash.academy)
* **Reference**
	* [Bash Reference Manual](https://tiswww.case.edu/php/chet/bash/bashref.html)
	* [An A-Z Index of the Bash command line for Linux. - ss64](https://ss64.com/bash/)
	* [bash(1) - Linux man page](https://linux.die.net/man/1/bash)
* **Tools**
* **Scripts**



----------
### C/C++ <a name="c"></a>
* **101**
	* [C (programming language) - Wikipedia](https://en.wikipedia.org/wiki/C_(programming_language))
	* [C++ - Wikipedia](https://en.wikipedia.org/wiki/C%2B%2B)
	* [C++ Homepage](https://isocpp.org/)
* **Learn**
	* [Stanford C 101](http://cslibrary.stanford.edu/101/EssentialC.pdf)
		* Stanford CS Education Library: A 45 page summary of the C language. Explains all the common features and techniques for the C language. The coverage is pretty quick, so it is most appropriate for someone with some programming background who needs to see how C works. Topics include variables, int types, floating point types, promotion, truncation, operators, control structures (if, while, for), functions, value parameters, reference parameters, structs, pointers, arrays, the pre-processor, and the standard C library functions. (revised 4/2003)
		* [Homepage](http://cslibrary.stanford.edu/101/)
	* [Stanford C Pointers and Memory](http://cslibrary.stanford.edu/102/PointersAndMemory.pdf)
		* Stanford CS Education Library: a 31 page introduction to programming with pointers and memory in C, C++ and other languages. Explains how pointers and memory work and how to use them -- from the basic concepts through all the major programming techniques. Can be used as an introduction to pointers for someone with basic programming experience or as a quick review. Many advanced programming and debugging problems only make sense with a solid understanding of pointers and memory -- this document tries to provide that understanding.
	* [Homepage](http://cslibrary.stanford.edu/102/)
	* [How to C in 2016](https://matt.sh/howto-c)
	* [A critique of "How to C in 2016" by Matt](https://github.com/Keith-S-Thompson/how-to-c-response)
	* [C Right-Left Rule](http://ieng9.ucsd.edu/~cs30x/rt_lt.rule.html)
	* [What a C programmer should know about memory](http://marek.vavrusa.com/c/memory/2015/02/20/memory/)
* **Reference**
	* [C++ TutorialsPoint](https://www.tutorialspoint.com/cplusplus/)
	* [C Function Call Conventions and the Stack](https://archive.is/o2nD5)
	* [What a C programmer should know about memory](http://marek.vavrusa.com/c/memory/2015/02/20/memory/)
	* [Cplusplus.com](http://www.cplusplus.com/)
	* [C reference - cppreference.com](http://en.cppreference.com/w/c)
* **Security**
	* [SEI CERT C Coding Standard](https://www.securecoding.cert.org/confluence/display/seccode/SEI+CERT+Coding+Standards)
	* [SEI CERT C++ Coding Standard](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=637)
	* [Vulnerabilities in C : When integers go bad!](https://blog.feabhas.com/2014/10/vulnerabilities-in-c-when-integers-go-bad/)
	* [Modern Memory Safety: C/C++ Vulnerability Discovery, Exploitation, Hardening](https://github.com/struct/mms)
		* This repo contains the slides for a training course originally developed in 2012. It has been delivered to many students since its creation. It's sold out at the Black Hat USA conference several years in a row. The content has gone through many iterations based on feedback from those classes. The original training focused mainly on browser vulnerability discovery and exploitation. This latest version still focuses on that but also covers more topics such as custom memory allocators, hardening concepts, and exploitation at a high level.
* **Techniques**
	* [Hide data inside pointers](http://arjunsreedharan.org/post/105266490272/hide-data-inside-pointers)
* **Tools**
	* [plog](https://github.com/SergiusTheBest/plog)
		* Portable, simple and extensible C++ logging library
	* [Attack Surface Meter](https://github.com/andymeneely/attack-surface-metrics)
		* Python package for collecting attack surface metrics from a software system. In its current version, Attack Surface Meter is capable of analyzing software systems written in the C programming language with skeletal support for analyzing software systems written in the Java programming language. The attack surface metrics collected are:
		* Proximity to Entry/Exit/Dangerous - The mean of shortest unweighted path length from a function/file to Entry Points/Exit Points/Dangerous Points.
	    * Risky Walk - The probability that a function/file will be invoked on a random execution path starting at the attack surface.
* **Projects**
	* [Build Your Own Text Editor - viewsourcecode.org/snaptoken](https://viewsourcecode.org/snaptoken/kilo/index.html)
* **Other**
	* [Stroustrup C++ 'interview']()https://www-users.cs.york.ac.uk/susan/joke/cpp.htm
	* [Creators admit Unix, C hoax](https://www-users.cs.york.ac.uk/susan/joke/c.htm)



----------
### C# <a name="c#"></a>
* **101**
* **Learn**
	* **Articles/Blogposts/Writeups**
		* [Book of the Runtime (BOTR) for the .NET Runtime](https://github.com/dotnet/coreclr/tree/master/Documentation/botr)
			* This contains a collection of articles about the non-trivial internals of the .NET Runtime. Its intended audience are people actually modifying the code or simply wishing to have a deep understanding of the runtime.
		* [.Net The Managed Heap and Garbage Collection in the CLR](https://www.microsoftpressstore.com/articles/article.aspx?p=2224054)
		* [Compiling C# Code at Runtime](https://www.codeproject.com/Tips/715891/Compiling-Csharp-Code-at-Runtime)
		* [The 68 things the CLR does before executing a single line of your code (`*`)](https://web.archive.org/web/20170614215931/http://mattwarren.org:80/2017/02/07/The-68-things-the-CLR-does-before-executing-a-single-line-of-your-code/)
		* [Dynamic Source Code Generation and Compilation](https://docs.microsoft.comen-us/dotnet/framework/reflection-and-codedom/dynamic-source-code-generation-and-compilation)
* **Reference**
	* [Transport Layer Security (TLS) best practices with the .NET Framework - docs.ms](https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls)
* **Security**
	* [.NET serialiception](https://blog.scrt.ch/2016/05/12/net-serialiception/)
* **Tools**
	* [Roslyn](https://github.com/dotnet/roslyn)
		* Roslyn provides open-source C# and Visual Basic compilers with rich code analysis APIs. It enables building code analysis tools with the same APIs that are used by Visual Studio.
		* [Overview](https://github.com/dotnet/roslyn/wiki/Roslyn%20Overview)




----------
### Go <a name="go"></a>
* **101**
	* [Go Programming Language](https://golang.org/)
* **Learn**
	* [Hacking with Go](https://github.com/parsiya/Hacking-with-Go)
		* This is my attempt at filling the gap in Go security tooling. When starting to learn Go, I learned from a lot of tutorials but I could find nothing that is geared towards security professionals. These documents are based on the Gray/Black Hat Python/C# series of books. I like their style. Join me as I learn more about Go and attempt to introduce Go to security denizens without fluff and through practical applications.
* **Security
	* **Articles/Blogposts/Writeups**
		* [memory security in go - spacetime.dev](https://spacetime.dev/memory-security-go)
		* [Diving Deep into Regular Expression Denial of Service (ReDoS) in Go - Erez Yalon(2018)](https://www.checkmarx.com/2018/05/07/redos-go/)
	* **Educational**
		* [Go-SCP](https://github.com/OWASP/Go-SCP)
			* Go Language - Web Application Secure Coding Practices is a guide written for anyone who is using the Go Programming Language and aims to use it for web development. This book is collaborative effort of Checkmarx Security Research Team and it follows the OWASP Secure Coding Practices - Quick Reference Guide v2 (stable) release. The main goal of this book is to help developers avoid common mistakes while at the same time, learning a new programming language through a "hands-on approach". This book provides a good level of detail on "how to do it securely" showing what kind of security problems could arise during development.
		* [GoVWA (Go Vulnerable Web Application)](https://github.com/0c34/govwa)
			* GoVWA (Go Vulnerable Web Application) is a web application developed to help the pentester and programmers to learn the vulnerabilities that often occur in web applications which is developed using golang. Vulnerabilities that exist in GoVWA are the most common vulnerabilities found in web applications today. So it will help programmers recognize vulnerabilities before they happen to their application. Govwa can also be an additional application of your pentest lab for learning and teaching.
	* **Talks/Presentations/Videos**
* **Reference**
	* [golang-tls](https://github.com/denji/golang-tls)
		* Simple Golang HTTPS/TLS Examples
* **Security**
	* [Go code auditing - 0xdabbad00](http://0xdabbad00.com/2015/04/18/go_code_auditing/)
* **Tools**
	* [gorilla/securecookie](https://github.com/gorilla/securecookie)
		* securecookie encodes and decodes authenticated and optionally encrypted cookie values.
	* [gorilla/csrf](https://github.com/gorilla/csrf)
		* gorilla/csrf is a HTTP middleware library that provides cross-site request forgery (CSRF) protection.
	* [nosurf](https://github.com/justinas/nosurf)
		* nosurf is an HTTP package for Go that helps you prevent Cross-Site Request Forgery attacks. It acts like a middleware and therefore is compatible with basically any Go HTTP application.
	* [CFSSL](https://github.com/cloudflare/cfssl)
		* CFSSL is CloudFlare's PKI/TLS swiss army knife. It is both a command line tool and an HTTP API server for signing, verifying, and bundling TLS certificates. It requires Go 1.12+ to build.




----------
### Java <a name="java"></a>
* **101**
	* [Java - Wikipedia](https://en.wikipedia.org/wiki/Java_(programming_language))
* **Learn**
	* [SEI CERT Oracle Coding Standard for Java](https://www.securecoding.cert.org/confluence/display/java/SEI+CERT+Oracle+Coding+Standard+for+Java)
	* [Protect Your Java Code - Through Obfuscators and Beyond](https://www.excelsior-usa.com/articles/java-obfuscators.html)
* **Reference**
	* [Secure Coding Guidelines for Java SE - Oracle](http://www.oracle.com/technetwork/java/seccodeguide-139067.html)
	* [Custom Classloaders - The black art of java](http://blog.cyberborean.org/2007/07/04/custom-classloaders-the-black-art-of-java)
* **Tools**
	* [Serianalyzer](https://github.com/mbechler/serianalyzer)
		* A static byte code analyzer for Java deserialization gadget research
	* [List of 3rd Party Security Libraries for Java - OWASP](https://www.owasp.org/index.php/Category:Java#tab=Related_3rd_Party_Projects)
		* A list of third party (i.e. not part of Java SE or EE) security frameworks. This page contains a list of Java security libraries and frameworks and indicates which security features each library supports.




---------------
### Javascript <a name="javascript"></a>
* **101**
* **Vanilla JS**
* **Node.js**
	* **Articles/Blogposts/Writeups**
		* [We’re under attack! 23+ Node.js security best practices - Yoni Goldberg, Kyle Martin and Bruno Scheufler](https://medium.com/@nodepractices/were-under-attack-23-node-js-security-best-practices-e33c146cb87d)
		* [Node.js Best Practices](https://github.com/i0natan/nodebestpractices)
			* The largest Node.JS best practices list. Curated from the top ranked articles and always updated
* **Learn**
	* [Mostly Adequate Guide](https://drboolean.gitbooks.io/mostly-adequate-guide/)
		* This is a book on the functional paradigm in general. We'll use the world's most popular functional programming language: JavaScript. Some may feel this is a poor choice as it's against the grain of the current culture which, at the moment, feels predominately imperative.
	* [Spellbook of Modern Web Dev](https://github.com/dexteryy/spellbook-of-modern-webdev)
		* A Big Picture, Thesaurus, and Taxonomy of Modern JavaScript Web Development
* **Reference**
	* [project-guidelines](https://github.com/wearehive/project-guidelines)
		*  A set of best practices for JavaScript projects - wearehive
	* [styleguides - Javascript](https://github.com/causes/styleguides/tree/master/javascript)
* **Security**
	* **Talks/Presentations/Videos**
		* [OWASP Top 10 for JavaScript Developers - Lewis Ardern(OWASP Global AppSec Tel Aviv 2019)](https://www.youtube.com/watch?v=IcGrLBO4ttw)
			* With the release of the OWASP TOP 10 2017 we saw new issues rise as contenders of most common issues in the web landscape. Much of the OWASP documentation displays issues, and remediation advice/code relating to Java, C++, and C#; however not much relating to JavaScript. JavaScript has drastically changed over the last few years with the release of Angular, React, and Vue, alongside the popular use of NodeJS and its libraries/frameworks.  This talk will introduce you to the OWASP Top 10 explaining JavaScript client and server-side vulnerabilities.
* **Tools**
	* [NodeJsScan](https://github.com/ajinabraham/NodeJsScan)
		* Static security code scanner (SAST) for Node.js applications.


----------
### Lisp <a name="lisp"></a>
* **101**
	* [Lisp - Wikipedia](https://en.wikipedia.org/wiki/Lisp_(programming_language))
	* [Common Lisp](https://common-lisp.net/)
	* [What makes lisp macros so special - StackOverflow](https://stackoverflow.com/questions/267862/what-makes-lisp-macros-so-special)
* **Learn**
	* [Lisp - TutorialsPoint](https://www.tutorialspoint.com/lisp/)
* **Reference**
* **Tools**
* **Other**
	[Lisp - Paul Graham](http://www.paulgraham.com/lisp.html)


----------
### Lua <a name="lua"></a>
* [Lua](https://www.lua.org/)
	* Official Homepage
* [Lua - Getting Started](https://www.lua.org/start.html)
* **Learn**
	* [Learn X in Y minutes, Where X=Lua](https://learnxinyminutes.com/docs/lua/)
	* [Lua code: security overview and practical approaches to static analysis](http://spw17.langsec.org/papers/costin-lua-static-analysis.pdf)
		* Abstract — Lua is an interpreted, cross-platform, embeddable, performant and low-footprint language. Lua’s popularity is on the rise in the last couple of years. Simple design and efficient usage of resources combined with its performance make it attractive or production web applications even to big organizations such as Wikipedia, CloudFlare and GitHub. In addition to this, Lua is one of the preferred choices for programming embedded and IoT devices. This context allows to assume a large and growing Lua codebase yet to be assessed. This growing Lua codebase could be potentially driving production servers and extremely large number of devices, some perhaps with mission-critical function for example in automotive or home-automation domains. However, there is a substantial and obvious lack of static analysis tools and vulnerable code corpora for Lua as compared to other increasingly popular languages, such as PHP, Python and JavaScript. Even the state-of-the-art commercial tools that support dozens of languages and technologies actually do not support Lua static code analysis. In this paper we present the first public Static Analysis for SecurityTesting (SAST) tool for Lua code that is currently focused on web vulnerabilities. We show its potential with good and promising preliminary results that we obtained on simple and intentionally vulnerable Lua code samples that we synthesized for our experiments. We also present and release our synthesized corpus of intentionally vulnerable Lua code, as well as the testing setups used in our experiments in form of virtual and completely reproducible environments. We hope our work can spark additional and renewed interest in this apparently overlooked area of language security and static analysis, as well as motivate community’s contribution to these open-source projects. The tool, the samples and the testing VM setups will be released and updated at http://lua.re and http://lua.rocks
* **Tools**
	* [REPL.lua](https://github.com/hoelzro/lua-repl)
		* a reusable Lua REPL written in Lua, and an alternative to /usr/bin/lua


-----------
### Perl <a name="perl"></a>
* [Perl Programming Language](https://www.perl.org/)
* [Perl - Wikipedia](https://en.wikipedia.org/wiki/Perl)
* **Learn**
	* [Perl & Linguistics](http://world.std.com/~swmcd/steven/perl/linguistics.html)
	* [SEI CERT Perl Coding Standard](https://www.securecoding.cert.org/confluence/display/perl/SEI+CERT+Perl+Coding+Standard)
	* [Introduction to Perl](http://www.perl.com/pub/2000/10/begperl1.html)
* **Reference**
	* [Perl Docs](https://perldoc.perl.org/)
* **Tools**



----------
### Powershell <a name="power"></a>
* **101**
	* [PowerShell Basics - Carlos Perez](https://www.darkoperator.com/powershellbasics/)
* **Learn**
	* [Learn Windows PowerShell in a Month of Lunches, Third Edition - Book](https://www.manning.com/books/learn-windows-powershell-in-a-month-of-lunches-third-edition)
	* [learning-powershell/ - github repo](https://github.com/PowerShell/PowerShell/tree/master/docs/learning-powershell)
	* [Getting Started with Microsoft PowerShell - MS Virtual Academy](https://mva.microsoft.com/en-us/training-courses/getting-started-with-microsoft-powershell-8276?l=r54IrOWy_2304984382)
	* [Weekend Scripter: The Best Ways to Learn PowerShell - technet](https://blogs.technet.microsoft.com/heyscriptingguy/2015/01/04/weekend-scripter-the-best-ways-to-learn-powershell/)
	* [Powershell Tutorial Online](http://powershelltutorial.net/)
	* [DEFCON25_PS_Workshop - Carlos Perez](https://github.com/darkoperator/DEFCON25_PS_Workshop)
* **Reference**
	* [The PowerShell Best Practices and Style Guide(Unofficial)](https://github.com/PoshCode/PowerShellPracticeAndStyle)
	* [Invoke-Expression - docs.ms](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-5.1)
* **Security**
	* **Talks/Presentations/Videos**
		* [Defensive Coding Strategies for a High-Security Environment - Matt Graeber - PowerShell Conference EU 2017](https://www.youtube.com/watch?reload=9&v=O1lglnNTM18)
* **Tools**
	* [Pester](https://github.com/pester/Pester)
		* Pester provides a framework for running unit tests to execute and validate PowerShell commands from within PowerShell. Pester consists of a simple set of functions that expose a testing domain-specific language (DSL) for isolating, running, evaluating and reporting the results of PowerShell commands.
	* [Dirty Powershell Webserver](http://obscuresecurity.blogspot.com/2014/05/dirty-powershell-webserver.html)
	* [Useful Powershell scripts](https://github.com/clymb3r/PowerShell)
* **Other**
	* [PowerShell Productivity Hacks: How I use Get-Command - Mike Robbins](https://mikefrobbins.com/2019/09/05/powershell-productivity-hacks-how-i-use-get-command/)
'''
Try/Catch Exception in Powershell

try {
#stuff
} catch {
$ErrorMessage = $_.Exception.Message
$ErrorSource = $_.Exception.Source
$err = $ErrorSource + " reports: " + $ErrorMessage
}

'''


----------
### PHP <a name="php"></a>
* **101**
	* [PHP The Right Way](http://www.phptherightway.com/)
* **Articles/Blogposts/Writeups**
	* [I Forgot Your Password: Randomness Attacks Against PHP Applications - George Argyros, Aggelos Kiayis](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.360.4033&rep=rep1&type=pdf)
* **Articles/Blogposts/Writeups**
	* [PHP Documentation](https://secure.php.net/docs.php)
* **Educational**
	* [PHP: a fractal of bad design](https://eev.ee/blog/2012/04/09/php-a-fractal-of-bad-design/)
	* [Reference — What does this symbol mean in PHP?](https://stackoverflow.com/questions/3737139/reference-what-does-this-symbol-mean-in-php)
* **Security**
	* [Security - PHP.net](https://www.php.net/manual/en/security.php)
	* [Survive The Deep End: PHP Security - phpsecurity.readthedocs](https://phpsecurity.readthedocs.io/en/latest/)	
* **Tools**
	* [Static analysis tools for PHP](https://github.com/exakat/php-static-analysis-tools)
		* A reviewed list of useful PHP static analysis tools
	* [PHPStan](https://github.com/phpstan/phpstan)
		* PHPStan focuses on finding errors in your code without actually running it. It catches whole classes of bugs even before you write tests for the code.
* **Other**
	* [awesome-php](https://github.com/ziadoz/awesome-php)
		* A curated list of amazingly awesome PHP libraries, resources and shiny things.




----------
### Python <a name="python"></a>
* **101**
	* [Learn Python the Hard Way](http://learnpythonthehardway.org/book/)
	* [Python For Beginners]()
		* Welcome! Are you completely new to programming? If not then we presume you will be looking for information about why and how to get started with Python. Fortunately an experienced programmer in any programming language (whatever it may be) can pick up Python very quickly. It's also easy for beginners to use and learn, so jump in!
* **Documentation/Reference**
	* [Python Developer's Guide](http://docs.python.org/devguide/)
	* [Extending and Embedding the Python Interpreter](http://docs.python.org/2.7/extending/index.html)
	* [Python/C API Reference Manual](http://docs.python.org/2.7/c-api/index.html)
	* [Python 3.6.2 documentation](https://docs.python.org/3/)
	* [Python 2.7 documentation](https://docs.python.org/2.7/)
	* [The Hitchhiker’s Guide to Python!](http://docs.python-guide.org/en/latest/)
	* [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
	* [What the f\*ck Python!](https://github.com/satwikkansal/wtfpython)
		* An interesting collection of surprising snippets and lesser-known Python features.
* **Internals**
	* [Diving deep into Python – the not-so-obvious language parts](http://sebastianraschka.com/Articles/2014_deep_python.html)
	* [PEP: 551 Title: Security transparency in the Python runtime Version](https://github.com/python/peps/blob/cd795ec53c939e5b40808bb9d7a80c428c85dd52/pep-0551.rst)
	* [Python Compiler Internals - Thomas Lee(2012)](http://tomlee.co/wp-content/uploads/2012/11/108_python-language-internals.pdf)
	* [How Fast Can We Make Interpreted Python? - Russel Power and Alex Rubinsteyn](http://arxiv.org/pdf/1306.6047v2.pdf)
	* [Python Attributes and Methods](http://www.cafepy.com/article/python_attributes_and_methods/python_attributes_and_methods.html)
	* [Understanding Python by breaking it](http://blog.hakril.net/articles/0-understanding-python-by-breaking-it.html)
	* [Eli Bendersky's Python Internals series](http://eli.thegreenplace.net/tag/python-internals)
	* [Adding a New Statement to Python(2010)](http://eli.thegreenplace.net/2010/06/30/python-internals-adding-a-new-statement-to-python/)
	* [Yaniv Aknin's Python Innards series](http://tech.blog.aknin.name/category/my-projects/pythons-innards/)
	* [Allison Kaptur's Python Internals Series](http://akaptur.github.io/blog/categories/python-internals/)
	* [My Python Internals Series!](http://mathamy.com/tag/python-internals.html)
* **Learn**
	* [Obfuscating python](https://reverseengineering.stackexchange.com/questions/1943/what-are-the-techniques-and-tools-to-obfuscate-python-programs)
	* [Understanding Python Bytecode](http://security.coverity.com/blog/2014/Nov/understanding-python-bytecode.html)
	* [Reverse debugging for Python](https://morepypy.blogspot.com/2016/07/reverse-debugging-for-python.html?m=1)
	* [Python in a hacker's toolbox (PyConPl'15)](http://gynvael.coldwind.pl/?lang=en&id=572)
	* [Virtualenv](https://virtualenv.pypa.io/en/latest/userguide/)
	* [Reading and Writing CSV Files in Python - Jon Fincher](https://realpython.com/python-csv/)
	* [A Whirlwind Tour of Python](https://github.com/jakevdp/WhirlwindTourOfPython)
		* The Jupyter Notebooks behind my OReilly report, "A Whirlwind Tour of Python"
	* [wtfpython](https://github.com/satwikkansal/wtfpython)
		* Python, being a beautifully designed high-level and interpreter-based programming language, provides us with many features for the programmer's comfort. But sometimes, the outcomes of a Python snippet may not seem obvious to a regular user at first sight.  Here is a fun project to collect such tricky & counter-intuitive examples and lesser-known features in Python, attempting to discuss what exactly is happening under the hood!  While some of the examples you see below may not be WTFs in the truest sense, but they'll reveal some of the interesting parts of Python that you might be unaware of. I find it a nice way to learn the internals of a programming language, and I think you'll find them interesting as well!  If you're an experienced Python programmer, you can take it as a challenge to get most of them right in first attempt. You may be already familiar with some of these examples, and I might be able to revive sweet old memories of yours being bitten by these gotchas sweat_smile
	* **Build & Understand**
		* [Build an API under 30 lines of code with Python and Flask](https://impythonist.wordpress.com/2015/07/12/build-an-api-under-30-lines-of-code-with-python-and-flask/)
* **Security**
	* [10 common security gotchas in Python and how to avoid them - Anthony Shaw](https://hackernoon.com/10-common-security-gotchas-in-python-and-how-to-avoid-them-e19fbe265e03?gi=ac211b3349e8)
* **Libraries**
	* [Python Library for interacting with Serial Ports](http://pyserial.sourceforge.net/)
	* [Hachoir](https://bitbucket.org/haypo/hachoir/wiki/Home)
		* Hachoir is a Python library that allows to view and edit a binary stream field by field
	* [Equip: python bytecode instrumentation](https://github.com/neuroo/equip)
		* equip is a small library that helps with Python bytecode instrumentation. Its API is designed to be small and flexible to enable a wide range of possible instrumentations. The instrumentation is designed around the injection of bytecode inside the bytecode of the program to be instrumented. However, the developer does not need to know anything about the Python bytecode since the injected code is Python source.
	* [Construct2](https://github.com/construct/construct)
		* Construct is a powerful declarative parser (and builder) for binary data.  Instead of writing imperative code to parse a piece of data, you declaratively define a data structure that describes your data. As this data structure is not code, you can use it in one direction to parse data into Pythonic objects, and in the other direction, convert ("build") objects into binary data.
	* [Impacket](https://github.com/CoreSecurity/impacket)
		* Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (for instance NMB, SMB1-3 and MS-DCERPC) the protocol implementation itself. Packets can be constructed from scratch, as well as parsed from raw data, and the object oriented API makes it simple to work with deep hierarchies of protocols. The library provides a set of tools as examples of what can be done within the context of this library.
	* [Trollius and asyncio](https://trollius.readthedocs.io/asyncio.html)
	* [Scapy3k](https://github.com/phaethon/scapy)
		* This is a fork of scapy (http://www.secdev.org) to make it compatible with python3. Fork based on scapy v2.3.1 All tests from regression (758 tests), ipsec, and both other test suites pass. Also, I tested full tutorial series [Building Network Tools with Scapy by @thepacketgeek](http://thepacketgeek.com/series/building-network-tools-with-scapy/) using scapy-python3. Please, submit all issues https://github.com/phaethon/scapy preferrably with .pcap files for tests. Bugs for individual layers are usually easy to fix.
	* [python-digitalocean](https://github.com/koalalorenzo/python-digitalocean)
		* Python module to manage Digital Ocean droplets
	* [docopt](https://github.com/docopt/docopt)
		* Pythonic command line arguments parser, that will make you smile https://github.com/docopt/docopt
* **Analysis & Debugging**
	* [py-spy](https://github.com/benfred/py-spy)
		* py-spy is a sampling profiler for Python programs. It lets you visualize what your Python program is spending time on without restarting the program or modifying the code in any way. py-spy is extremely low overhead: it is written in Rust for speed and doesn't run in the same process as the profiled Python program. This means py-spy is safe to use against production Python code.





------------------------------------------------------------------------------------------------------------------------------------------------------
### Ruby <a name="ruby"></a>
* **101**
	* [Ruby Homepage](https://www.ruby-lang.org/en/)
	* [Official Ruby Docs](https://ruby-doc.org/)
	* [Ruby Gems](https://rubygems.org/)
	* [Ruby on Rails](http://rubyonrails.org/)
* **Articles/Blogposts/Writeups**
	* [How Do Ruby/Rails Developers Keep Updated on Security Alerts?(2015) - gavinmiller.io](http://gavinmiller.io/2015/staying-up-to-date-with-security-alerts/)
* **Documentation**
* **Learn**
	* [Ruby - Tutorials Point](http://www.tutorialspoint.com/ruby/)
	* [Ruby in 20 Minutes](https://www.ruby-lang.org/en/documentation/quickstart/)
* **Educational**
* **Security**
	* [Rails SQL Injection](https://rails-sqli.org/)
		* The Ruby on Rails web framework provides a library called ActiveRecord which provides an abstraction for accessing databases. This page lists many query methods and options in ActiveRecord which do not sanitize raw SQL arguments and are not intended to be called with unsafe user input. Careless use of these methods can open up code to SQL Injection exploits. The examples here do not include SQL injection from known CVEs and are not vulnerabilites themselves, only potential misuses of the methods. Please use this list as a guide of what not to do. This list is in no way exhaustive or complete!
	* [rails-security-checklist](https://github.com/eliotsykes/rails-security-checklist)
		* Community-driven Rails Security Checklist (see our GitHub Issues for the newest checks that aren't yet in the README)
	* [RailsConf 2015 - Nothing is Something](https://www.youtube.com/watch?v=OMPfEXIlTVE)
* **Reference**
	* [ruby-style-guide](https://github.com/bbatsov/ruby-style-guide)
		* A community-driven Ruby coding style guide
* **Useful Libraries/programs/Frameworks**
	* [Shellpaste](https://github.com/andrew-morris/shellpaste)
		* Tiny snippet of code that pulls ASCII shellcode from pastebin and executes it. The purpose of this is to have a minimal amount of benign code so AV doesn't freak out, then it pulls down the evil stuff. People have been doing this kind of stuff for years so I take no credit for the concept. That being said, this code (or similar code) works surprisingly often during pentests when conventional malware fails.
* **Tools**
	* [rb2exe](https://github.com/loureirorg/rb2exe)
		* Ruby to EXE - Turn ruby scripts into portable executable apps



----------
### Rust <a name="rust"></a>
* **101**
* **Learn**
	* **Articles/Blogposts/Writeups**
		* [A half-hour to learn Rust - Amos](https://fasterthanli.me/blog/2020/a-half-hour-to-learn-rust/)
			* In this article, instead of focusing on one or two concepts, I'll try to go through as many Rust snippets as I can, and explain what the keywords and symbols they contain mean.
	* **Talks/Presentations/Videos**
		* [Rust for C++ developers - What you need to know to get rolling with crates - Pavel Yosifovich(NDC 2019)](https://www.youtube.com/watch?v=k7nAtrwPhR8&feature=youtu.be)
* **Reference**
* **Useful Libraries/Frameworks**




----------
### SQL <a name="sql"></a>
* [SafeSQL](https://github.com/stripe/safesql)
	* SafeSQL is a static analysis tool for Go that protects against SQL injections.
* [The Hitchhiker's Guide to SQL Injection prevention](https://phpdelusions.net/sql_injection)




---------------
### Swift <a name="swift"></a>
* [Alamofire](https://github.com/Alamofire/Alamofire)
	* Alamofire is an HTTP networking library written in Swift.

----------
### UEFI Programming <a name="uefi"></a>
* [Unified Extensible Firmware Interface Forum](http://www.uefi.org/)
* [Unified Extensible Firmware Interface](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface)
* **Learn**
	* [Programming for EFI: Creating a "Hello, World" Program](http://www.rodsbooks.com/efi-programming/hello.html)
	* [UEFI Programming - First Steps](http://x86asm.net/articles/uefi-programming-first-steps/)
	* [Getting started with UEFI application development](https://lihashgnis.blogspot.com/2016/08/getting-started-with-uefi-application.html)
	* [Getting started with UEFI Development](https://lihashgnis.blogspot.com/2016/08/getting-started-with-uefi-application.html)
* **Reference**
	* [UEFI - OSDev](http://wiki.osdev.org/UEFI)
* **Talks & Presentations**
	* [Simple Made Easy](https://www.infoq.com/presentations/Simple-Made-Easy)
		* Rich Hickey emphasizes simplicity’s virtues over easiness’, showing that while many choose easiness they may end up with complexity, and the better way is to choose easiness along the simplicity path.


----
### Other
* [A successful Git branching model](http://nvie.com/posts/a-successful-git-branching-model/)
* [Mostly Adequate Guide](https://drboolean.gitbooks.io/mostly-adequate-guide/)
	* This is a book on the functional paradigm in general. We'll use the world's most popular functional programming language: JavaScript. Some may feel this is a poor choice as it's against the grain of the current culture which, at the moment, feels predominately imperative.
