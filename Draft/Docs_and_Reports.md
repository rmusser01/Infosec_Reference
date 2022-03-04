# Documentation & Reporting

------------------------------------------------------------------------
## Table of Contents
- [Writing](#writing)
	- [Other materials](#other)
	- [Writing a Paper](#writepaper)
	- [Technical Writing](#techwrite)
	- [Writing RFCs](#rfc)
	- [Software Design Documentation/Functional Specifications](#sdda)
	- [Writing a Blogpost](#blog)
	- [Language](#lang)
	- [Taking Notes]()	
	- [Tools](#writetools)
	- [Note Taking/Management Software](#ntms)
		- [Text Sharing](#txtshare)
		- [Diagramming Tools](#diag)
		- [Manual Publishing](#manpub)
		- [Documentation Browsers]()
	- [Writing Reports](#)
		- [report Examples/Samples](#rsamples)
		- [Writing a Penetration Test Report](#writereport)
		- [Writing an Request for Proposal](#writingrfp)
		- [Templates](#templates)
	- [Writing Technical Documentation](#techdoc)
	- [Writing a Playbook](#playbook)
	- [Meta](#meta)
		- [Latex](#latex)
		- [Markdown](#markdown)
		- [Tools](#mtools)
	- [Poc - [Documentation](#pocdoc)
	- [Import/Export from Tools(Dumping data from tools into more readable/usable formats](#export)
	- [Graphing/Visualization Tools](#graph)
- [De/Briefing & Presenting
	- [101](#d101)
	- [General](#dg)
	- [Talks](#dt)
	- [Tools](#dto)
- [Penetration Testing Collaboration](#collab)
- [Video Documentation](#video)
- [Disclosure](#disclosure)
------------------------------------------------------------------------

To Do:
	* Add Note taking methods

-----------------
### Start Here	
* [How I read a research paper](https://muratbuffalo.blogspot.com/2013/07/how-i-read-research-paper.html)
* **Writing**<a name="writing"></a>
	* Start with the first two links, and go from there. They’re both great resources to writing technical documentation, the first being a beginners guide and the second being a general guide that beginners can understand.
		* [A beginners guide to writing documentation](http://www.writethedocs.org/guide/writing/beginners-guide-to-docs/)
		* [Teach, Don’t Tell](http://stevelosh.com/blog/2013/09/teach-dont-tell/)
		* [How to Write Papers So People Can Read Them - Derek Dreyer](https://www.youtube.com/watch?v=L_6xoMjFr70)
	* **Other Materials**<a name="other"></a>
		* [Politics and the English Language - George Orwell](http://www.npr.org/blogs/ombudsman/Politics_and_the_English_Language-1.pdf)
		* [Tips for Writing Better Infosec Job Descriptions](https://www.darkreading.com/cloud/tips-for-writing-better-infosec-job-descriptions/d/d-id/1330534?piddl_msgid=330184#msg_330184)
		* [Learning the Ropes 101: Stay Beautiful, Stay Verbose](https://blog.zsec.uk/stay-beautiful-stay-verbose/)
		* Three parter from jacobian.org:
			* [What to write](http://jacobian.org/writing/what-to-write/)
			* [Technical Style](http://jacobian.org/writing/technical-style/)
			* [Editors](http://jacobian.org/writing/editors/)
		* [The Ultimate Workflow for Writers Obsessed with Quality - Rob Hardy](https://betterhumans.coach.me/the-ultimate-workflow-for-writers-obsessed-with-quality-5b2810e1214b)
		* [A Few 80/20 Tips for Writing - syften.com](https://syften.com/blog/post/writing-style/)
		* [How To Write Like It’s Your Job - Bria Hughes(BSidesSF2020)](http://www.encyclopediabriannica.com/?p=667)
			* Good presentation on increasing your general writing ability.
		* [Reporting And Writing Basics - Reuters Handbook of Journalism(2018)](http://handbook.reuters.com/index.php?title=Reporting_and_Writing_Basics)
		* [Subjectivity in writing and evaluating writing - jakeseliger.com](https://jakeseliger.com/2014/12/20/subjectivity-in-writing-and-evaluating-writing/)
	* **Writing a Paper**<a name="writepaper"></a>
		* [How to write a great research paper - Simon Peyton Jones](https://www.microsoft.com/en-us/research/academic-program/write-great-research-paper/)
	* **Technical Writing**<a name="techwrite"></a>
		* [Writing Types of User Documentation](https://en.wikiversity.org/wiki/Technical_writing_Types_of_User_Documentation)
		* [The 7 Rules for Writing World Class Technical Documentation](http://www.developer.com/tech/article.php/3848981/The-7-Rules-for-Writing-World-Class-Technical-Documentation.htm)
		* [Teach Technical Writing in Two Hours per Week](http://www.cs.tufts.edu/~nr/pubs/two-abstract.html)
		* [Learn Technical Writing in Two Hours per Week - Norman Ramsey](http://www.cs.tufts.edu/~nr/pubs/learn-two.pdf)
		* [writingfordevelopers](https://writingfordevelopers.substack.com/)
		* [Microsoft Writing Style Guide](https://docs.microsoft.com/en-us/style-guide/welcome/)
		* [Notes on Technical Writing - Marcus Kazmierczak](https://mkaz.blog/misc/notes-on-technical-writing/)
		* [SANS 10 Cybersecurity Writing Mistakes(Videos)](https://www.youtube.com/playlist?list=PLtgaAEEmVe6As4oO81VRtC-27yWQrzWI-)
		* [Writing Tips for IT Professionals - Lenny Zeltser](https://zeltser.com/writing-tips-for-it-professionals/)
		* [Tech Writing Handbook - Kyle Wiens, Julia Bluff(iFixit)](https://help.dozuki.com/Tech_Writing)
			* This handbook will teach you how to create everything from manuals to work instructions. We’ll help you avoid the most common pitfalls of tech writing, from poor planning to outdated publishing.
		* [Technical Writing Courses - Google](https://developers.google.com/tech-writing)
			* "This collection of courses and learning resources aims to improve your technical documentation. Learn how to plan and author technical documents. You can also learn about the role of technical writers at Google."
		* [Learning Technical Writing Using the Engineering Method - Norman Ramsey(2016)](https://www.cs.tufts.edu/~nr/pubs/learn.pdf)
			* "This booklet explains how to study technical writing in the context of a weekly group. If nothing else, a group will show you that you are not alone in your difficulties. Problems you may have are problems that others also have, and you can find similar problems even in published papers. But we do not emphasize problems; instead we emphasize useful principles and practices—engineering heuristics—that you can learn to apply to your own manuscripts."
		* [Technical Writing Courses - Google](https://developers.google.com/tech-writing)
			* "This collection of courses and learning resources aims to improve your technical documentation. Learn how to plan and author technical documents. You can also learn about the role of technical writers at Google."
	* **Writing RFCs**<a name="rfc"></a>
		* [RFC 3552: Guidelines for Writing RFC Text on Security Considerations](https://tools.ietf.org/html/rfc3552)
	* **Software Design Documentation/Functional Specifications**<a name="sdd"></a>
		* [How to Write an Analysis & Design Document for a Software - Jackie Lohrey](https://www.techwalla.com/articles/how-to-write-an-analysis-design-document-for-a-software)
		* [Islandora Software Design Documents](https://github.com/Islandora/islandora/wiki/design-documents)
		* [Painless Functional Specifications – Part 1: Why Bother? - JoelonSoftware](https://www.joelonsoftware.com/2000/10/02/painless-functional-specifications-part-1-why-bother/)
			* [Part 2: What’s a Spec? - JoelonSoftware](https://www.joelonsoftware.com/2000/10/03/painless-functional-specifications-part-2-whats-a-spec/)
			* [Part 3: But… How? - JoelonSoftware](https://www.joelonsoftware.com/2000/10/04/painless-functional-specifications-part-3-but-how/)
			* [Part 4: Tips - JoelonSoftware](https://www.joelonsoftware.com/2000/10/15/painless-functional-specifications-part-4-tips/)
		* [whattimeisit.com - JoelonSoftware](https://www.joelonsoftware.com/whattimeisit/)
			* Functional Specification Example
		* [Controlling Your Environment Makes You Happy - JoelonSoftware](https://www.joelonsoftware.com/2000/04/10/controlling-your-environment-makes-you-happy/)
			* Should be read in conjunction with the above link.
		* [Design Docs at Google - Malte Ubi(2020)](https://www.industrialempathy.com/posts/design-docs-at-google/)
		* [Why Writing Software Design Documents Matters - Chris Fox](https://www.toptal.com/freelance/why-design-documents-matter)
		* [How to Write an Effective Design Document - Scott Hackett](https://web.archive.org/web/20190420045654/http://blog.slickedit.com/2007/05/how-to-write-an-effective-design-document/)
		* [How to write a good software design doc - Angela Zhang](https://medium.freecodecamp.org/how-to-write-a-good-software-design-document-66fcf019569c)
			* Be sure to read the first comment by John Rote
		* [Creating A Great Design Document - Tvzi Freeman(1997)](https://www.gamasutra.com/view/feature/131632/creating_a_great_design_document.php)
		* [A beginner’s guide to writing documentation - writethedocs.org](https://www.writethedocs.org/guide/writing/beginners-guide-to-docs/)
		* [How To Write Software Design Documents - Syed Ahmed](https://blog.tara.ai/software-design-documents/)
	* **Writing a Blogposts**<a name="blog"></a>
		* [Your Boss Wants You to Write Pentest Blog Posts... Now What? - Daniel Sandau](https://whiteoaksecurity.com/blog/2019/9/30/your-boss-wants-you-to-write-pentest-blog-posts-now-what)
* **Language**<a name="lang"></a>
	* [Bishop Fox Cybersecurity Style Guide](https://www.bishopfox.com/blog/2018/02/hello-world-introducing-the-bishop-fox-cybersecurity-style-guide/)
* **Taking Notes**<a name="notes"></a>
	* [My Forensic and Incident Response Note Taking Methodology - IronMoon](https://ironmoon.net/2019/02/04/My-Forensic-and-Incident-Response-Note-Taking-Methodology.html)
* **Tools**<a name="writetools"></a>
	* I Highly, Highly(!), recommend using a git system for note storage/usage. Versionioning, date checkins, history of edits, can have multiple versions split across different areas and merge them nicely without conflict... Pretty sweet stuff.
	* [Mark](https://github.com/kovetskiy/mark/)
		* tool for syncing your markdown documentation with Atlassian Confluence pages.
	* **Note Taking/Management Software**<a name="ntms"></a>
		* [leaps - shared text editing in Golang](https://github.com/denji/leaps)
			* Leaps is a service for hosting collaboratively edited documents using operational transforms to ensure zero-collision synchronization across any number of editing clients.
		* [Anno](https://github.com/gwgundersen/anno)
			* Anno is a local, browser-based user interface on top of Markdown files in a given directory. It makes writing, organizing, and searching through those files easy. That's it. There are many benefits to this approach:
		* [Zim(Desktop Wiki)](https://zim-wiki.org/index.html)
			*  Zim is a graphical text editor used to maintain a collection of wiki pages. Each page can contain links to other pages, simple formatting and images. Pages are stored in a folder structure, like in an outliner, and can have attachments. Creating a new page is as easy as linking to a nonexistent page. All data is stored in plain text files with wiki formatting. Various plugins provide additional functionality, like a task list manager, an equation editor, a tray icon, and support for version control.
		* [Dnote](https://github.com/dnote/dnote)
			* Dnote is a lightweight personal knowledge base. The main design goal is to keep you focused by providing a way of swiftly capturing new information without having to switch environment. To that end, you can use Dnote as a command line interface, browser extension, web client, or an IDE plugin.
		* [cherrytree](https://www.giuspen.com/cherrytree/)
			* A hierarchical note taking application, featuring rich text and syntax highlighting, storing data in a single xml or sqlite file.
		* [Joplin](https://github.com/laurent22/joplin)
			* Joplin is a free, open source note taking and to-do application, which can handle a large number of notes organised into notebooks. The notes are searchable, can be copied, tagged and modified either from the applications directly or from your own text editor. The notes are in Markdown format.
		* [Trilium Notes](https://github.com/zadam/trilium)
			* Trilium Notes is a hierarchical note taking application with focus on building large personal knowledge bases.
		* [mdBook](https://github.com/rust-lang/mdBook)
			* mdBook is a utility to create modern online books from Markdown files.
		* [Notable](https://github.com/notable/notable)
			* The Markdown-based note-taking app that doesn't suck.
	* **Text Sharing**<a name="txtshare"></a>
		* **Published**
			* [BookStack](https://www.bookstackapp.com/)
				* BookStack is a simple, self-hosted, easy-to-use platform for organising and storing information.
		* **Live**
			* [Cryptpad](https://github.com/xwiki-labs/cryptpad)
				* CryptPad is the Zero Knowledge realtime collaborative editor.
			* [codimd](https://github.com/hackmdio/codimd)
				* CodiMD lets you collaborate in real-time with markdown. Built on HackMD source code, CodiMD lets you host and control your team's content with speed and ease.
		* **Pastes**
			* [PrivateBin](https://privatebin.info/)
				* PrivateBin is a minimalist, open source online pastebin where the server has zero knowledge of pasted data.
	* **Diagramming Tools**<a name="diag"></a>
		* [Mermaid](https://github.com/mermaid-js/mermaid)
			* Generation of diagram and flowchart from text in a similar manner as markdown 
		* [PlantUML](http://plantuml.com/faq)
			* PlantUML is used to draw UML diagrams, using a simple and human readable text description.
	* **Manual Publishing**<a name="manpub"></a>
		* [Ronn](https://github.com/rtomayko/ronn)
			* Ronn builds manuals. It converts simple, human readable textfiles to roff for terminal display, and also to HTML for the web. The source format includes all of Markdown but has a more rigid structure and syntax extensions for features commonly found in manpages (definition lists, link notation, etc.). The ronn-format(7) manual page defines the format in detail.
	* **Documentation Browsers**
		* [Zeal](https://zealdocs.org)
			* Zeal is a simple offline documentation browser inspired by Dash.
* **Writing Reports** <a name="reports"></a>
	* **Report Examples/Samples**<a name="rsamples"></a>
		* [Public penetration testing reports](https://github.com/juliocesarfort/public-pentesting-reports)
			* Curated list of public penetration test reports released by several consulting firms and academic security groups
		* [Penetration tests done by cure53, good examples of how a report should be done.](https://cure53.de/#publications )
		* [Offensive Security 2013 Demo report](http://www.offensive-security.com/offsec/penetration-test-report-2013/)
		* [Project TJ-JPT](https://github.com/tjnull/TJ-JPT)
			* "This repo contains my pentesting template that I have used in PWK and for current assessments. The template has been formatted to be used in Joplin"
	* **Writing a Penetration Test Report**<a name="writereport"></a>
		* **Articles**
			* [Writing a Penetration Testing Report by SANS](https://www.sans.org/reading-room/whitepapers/bestprac/writing-penetration-testing-report-33343)
			* [Penetration Testing Execution Standard section on Reporting](http://www.pentest-standard.org/index.php/Reporting)
			* [Tips for Creating an Information Security Assessment Report Cheat Sheet](https://zeltser.com/security-assessment-report-cheat-sheet/)
			* [HowTo: Write pentest reports the easy way](http://blog.dornea.nu/2014/05/20/howto-write-pentest-reports-the-easy-way/)
			* [ The Penetration Testing Report - websecuritywatch](https://web.archive.org/web/20180201103151/http://www.websecuritywatch.com/the-penetration-testing-report/)
			* [Excellent blog post breaking down the various parts, a must read](http://wwwwebsecuritywatch.com/the-penetration-testing-report/)
			* [Your Reporting Matters: How to Improve Pen Test Reporting - Brian B. King](https://www.blackhillsinfosec.com/your-reporting-matters-how-to-improve-pen-test-reporting/)
				* [Video Presentation](https://www.youtube.com/watch?v=NUueNT1svb8)
			* [LTR101: Writing or Receiving Your First Pentest Report - Andy Gill](https://blog.zsec.uk/ltr101-pentest-reporting/)
			* [Security Assessment Report as a Critique, Not Criticism - Lenny Zeltser(2019)](https://zeltser.com/security-assessment-report-as-critique/)
		* **Talks**
			* [Hack for Show, Report for Dough - Brian B. King(WWHF 2018)](https://www.youtube.com/watch?v=c_LBWqNDY0M)
				* The fun part of pentesting is the hacking. But the part that makes it a viable career is the report. You can develop the most amazing exploit for the most surprising vulnerability, but if you can't document it clearly for the people who need to fix it, then you're just having fun. Which is fine! But if you want to make a career out of it, your reports need to be as clear and useful as your hacks are awesome. This talk shows simple techniques you can use to make your reports clear, useful, and brief. You'll see some before-and-after examples of a bad report made good, with clear explanations of what makes the difference. Those things will be useful no matter what tools you use to create reports. Then, if we have time, we'll look at some Microsoft Word hacks that will save you time and improve consistency.
		* **Tools that can help**
			* [I \<3 Reporting - ](https://github.com/leesoh/iheartreporting)
				* Reporting Tips for Penetration Testers
	* **Writing an Request for Proposal**<a name="Writingrfp"></a>
		* [security-assessment-rfp-cheat-sheet](http://zeltser.com/security-assessments/security-assessment-rfp-cheat-sheet.html)
	* **Templates**<a name="templates"></a>
		* [Report Template from vulnerabilityassessment.co.uk](http://www.vulnerabilityassessment.co.uk/report%20template.html)
		* [SANS InfoSec Policy Templates](https://www.sans.org/security-resources/policies/)
* **Writing Technical Documentation**<a name="techdoc"></a>
	* [The Elements Of Style: UNIX As Literature - Thomas Scoville](http://theody.net/elements.html)
	* [What nobody tells you about documentation - Daniele Procida](https://www.divio.com/blog/documentation/)
	* [Minimalism - Hans Van Der Meij](https://www.utwente.nl/en/bms/ist/minimalism/)
		* Writeup on the 'Minimalist' approach to technical documentation
* **Writing a Playbook**<a name="playbook"></a>
	* [PlayBooks](https://github.com/csandker/Playbooks)
		* PlayBooks is a project i've build to ease the creation of knowledge playbooks for different scenarios. Create your own Markdown playbooks for whatever scenario you usually encounter, from development tasks to a full RedTeam rundown.
* **Meta**<a name="meta"></a>
	* **LaTex**
	* **Markdown**
		* **101**
			* [What is Markdown?](http://daringfireball.net/projects/markdown/syntax)
			* [Markdown Syntax](http://daringfireball.net/projects/markdown/syntax)
			* [Markdown basics](https://help.github.com/articles/markdown-basics/)
		* **Using**
			* [Markdown For Penetration testers & Bug-bounty hunters - enciphers](https://enciphers.com/markdown-for-penetration-testers-bug-bounty-hunters/)
			* [Using markdown](https://guides.github.com/features/mastering-markdown/)
			* [Mastering Markdown](https://guides.github.com/features/mastering-markdown/)
		* **Tools**
	* **Tools**
		* [vim-wordy](https://github.com/reedes/vim-wordy/blob/master/README.markdown)
			* wordy is not a grammar checker. Nor is it a guide to proper word usage. Rather, wordy is a lightweight tool to assist you in identifying those words and phrases known for their history of misuse, abuse, and overuse, at least according to usage experts.
		* [tldr](https://github.com/tldr-pages/tldr)
			* A collection of simplified and community-driven man pages.
		* [CyberSecurity Style Guide Dictionary file(cyber.dic)](https://github.com/bishopfox/cyberdic)
			* This is the companion dictionary of the Cybersecurity Style Guide. The cyber.dic dictionary file can be added to your word processor to augment its standard spellcheck list. This is a resource for anyone who regularly writes about tech and is not a fan of the red underline that plagues any highly technical document.
		* [Scanning reports to tabular (sr2t)](https://gitlab.com/0bs1d1an/sr2t)
			* This tool takes a scanning tool's output file, and converts it to a tabular format (CSV, XLSX, or text table). This tool can process output from the following tools: Nmap (XML); Nessus (XML); Nikto (XML); Dirble (XML); Testssl (JSON); Fortify (FPR)
		* [Bullets To Table](https://github.com/suhailidrees/bullets_to_table)
			* Convert a bullet list into a table
* **PoC Documentation**<a name="pocdoc"></a>
	* [CaptureIT](https://github.com/MSAdministrator/CaptureIT)
		* CaptureIT can generate GIFs of both the actively selected window or your entire desktop
	* [Peek](https://github.com/phw/peek)
		* Peek makes it easy to create short screencasts of a screen area. It was built for the specific use case of recording screen areas, e.g. for easily showing UI features of your own apps or for showing a bug in bug reports. With Peek, you simply place the Peek window over the area you want to record and press "Record". Peek is optimized for generating animated GIFs, but you can also directly record to WebM or MP4 if you prefer. Peek is not a general purpose screencast app with extended features but rather focuses on the single task of creating small, silent screencasts of an area of the screen for creating GIF animations or silent WebM or MP4 videos. Peek runs on X11 or inside a GNOME Shell Wayland session using XWayland.
	* [flameshot](https://github.com/lupoDharkael/flameshot)
		* Powerful yet simple to use screenshot software
* **Import/Export from Tools(Dumping data from tools into more readable/usable formats**<a name="export"></a>
	* **Articles/Blogposts/Writeups**
		* [Exporting Nessus Results into a Database - Eddie Zhang](https://eddiez.me/nessus-db-export/)
		* [Nessus CSV Parser and Extractor](https://www.infosecmatter.com/nessus-csv-parser-and-extractor/)
		* [Read .nessus file into Excel (with Power Query)(2016)](https://www.verifyit.nl/wp/?p=175591)
			* Read a .nessus file (hosts properties, vulnerability and compliance scan results) into excel.
	* **Tools**
		* [Nessus Professional Database Export](https://github.com/eddiez9/nessus-database-export)
    		* Script to export Nessus results to a relational database for use in reports, analysis, or whatever else.
		* [nessusporter](https://github.com/Tw1sm/nessporter)
			* Easily download entire folders of Nessus scans in the format(s) of your choosing. This script uses provided credentials to connect to a Nessus server and store a session token, which is then used for all subsquent requests.
		* [pynessus](https://github.com/rmusser01/pynessus)
			* Python Parser for Nessus Output
		* [VULNREPO](https://github.com/kac89/vulnrepo)
			* VULNRΞPO - Free vulnerability report generator and repository end-to-end encrypted, security report maker, vulnerability report builder. Complete templates of issues, CWE, CVE, AES encryption, Nessus/Burp/OpenVAS issues import, Jira export, TXT/HTML/PDF report, attachments, automatic changelog and statistics, vulnerability management.
* **Graphing/Visualization Tools**<a name="graph"></a>
	* **Tools**
		* [markmap](https://github.com/dundalek/markmap)
			* Markmap is a javascript component that will visualize your markdown documents as mindmaps. It is useful for better navigation and overview of the content.
			* [Example](https://markmap.js.org/repl)
		* [markmap-lib](https://github.com/gera2ld/markmap-lib)
			* Visualize your Markdown as mindmaps.
		* [Graphviz](https://graphviz.org/)
			* Graphviz is open source graph visualization software. Graph visualization is a way of representing structural information as diagrams of abstract graphs and networks. It has important applications in networking, bioinformatics, software engineering, database and web design, machine learning, and in visual interfaces for other technical domains.
		* [Diagram.codes](https://www.diagram.codes/)
		* Describe your diagrams with a simple text language and automatically generate an image you can export.
		* [REAL WORLD PlantUML](https://real-world-plantuml.com/)



----------------------------
### <a name="debrief"></a> De/Briefing & Presenting
* **101**<a name="101"></a>
	* [Debriefing: A Simple Tool to Help Your Team Tackle Tough Problems](https://hbr.org/2015/07/debriefing-a-simple-tool-to-help-your-team-tackle-tough-problems)
	* [Sample Debriefing Statement - Albion College](https://www.albion.edu/academics/student-research/institutional-review-board/submitting-a-proposal/sample-debriefing-statement)
* **General**<a name="dg"></a>
	* [Debriefing Facilitation Guide: Leading Groups at Etsy to Learn from Accidents - Etsy](https://extfiles.etsy.com/DebriefingFacilitationGuide.pdf)
	* [Presentation Tips for Technical Talks - SheHacksPurple](https://medium.com/@shehackspurple/presentation-tips-for-technical-talks-8d59f3de9f6d)
	* [Make your PowerPoint presentations accessible to people with disabilities - support.office.com](https://support.office.com/en-us/article/make-your-powerpoint-presentations-accessible-to-people-with-disabilities-6f7772b2-2f33-4bd2-8ca7-dae3b2b3ef25)
		* This topic gives you step-by-step instructions to make your PowerPoint presentations accessible to people with disabilities.
* **Talks**<a name="dt"></a>
	* [‘Thought Leader’ gives talk that will inspire your thoughts | CBC Radio (Comedy/Satire Skit)](https://www.youtube.com/watch?v=_ZBKX-6Gz6A)
		* Self proclaimed “thought leader,” Pat Kelly gives his talk on “thought leadership” at the annual This Is That Talks in Whistler, B.C. In the seminar, Kelly covers: How to talk with your hands, how to get a standing ovation, and how to inspire people by saying nothing at all.
		* I feel this is valuable for identifying the pattern and flow used. Note the individual does not say anything of value, but is able to capture the audience and not break the flow of his presentation, again, without saying anything of value. A Real Business Proffessional™
	* [A presentation or presentations because presenting - Jason Blanchard - Derbycon7](https://www.youtube.com/watch?v=FcgM7c0vzcE&app=desktop)
	* [How To Speak by Patrick Winston(MIT)](https://www.youtube.com/watch?v=Unzc731iCUY)
		* Patrick Winston's How to Speak talk has been an MIT tradition for over 40 years. Offered every January, the talk is intended to improve your speaking ability in critical situations by teaching you a few heuristic rules.
* **Tools**<a name="dto"></a>
	* [A Project Post Mortem Template - brolik.com](http://brolik.com/blog/project-post-mortem-template/)
	* [Chart.xkcd](https://github.com/timqian/chart.xkcd)
		* Chart.xkcd is a chart library that plots “sketchy”, “cartoony” or “hand-drawn” styled charts.
	



--------------------
### <a name="collab">Penetration Testing Collaboration</a>
* **Collaboration Tools**
	* [Kvasir](https://github.com/KvasirSecurity/Kvasir)
		* Kvasir is a vulnerability / penetration testing data management system designed to help mitigate the issues found when performing team-based assessments. Kvasir does this by homogenizing data sources into a pre-defined structure.
	* [Dradis](https://github.com/dradis/dradisframework#welcome-to-dradis)
		* Dradis is an open source collaboration framework, tailored to InfoSec teams.
	* [Faraday](https://github.com/infobyte/faraday)
		* Faraday introduces a new concept (IPE) Integrated Penetration-Test Environment a multiuser Penetration test IDE. Designed for distribution, indexation and analysis of the generated data during the process of a security audit.  The main purpose of Faraday is to re-use the available tools in the community to take advantage of them in a multiuser way.
	* [Lair](https://github.com/lair-framework/lair)
		* Lair is a reactive attack collaboration framework and web application built with meteor. 
	* [envizon](https://github.com/evait-security/envizon)
		* "We use envizon for our pentests in order to get an overview of a network and quickly identify the most promising targets. The version 3.0 introduce new features such as screenshotting web services, organizing vulnerabilities or generating reports with custom docx templates."
	* [Collaboration and Report @ Rawsec Inventory](https://inventory.raw.pm/tools.html#title-tools-collaboration-report) - Complete list of Collaboration and Report tools/platforms
* **Documenation Tools**
	* [DART](https://github.com/lmco/dart/blob/master/README.md)
		* DART is a test documentation tool created by the Lockheed Martin Red Team to document and report on penetration tests, especially in isolated network environments.
	* [Serpico](https://github.com/SerpicoProject/Serpico)
		* Serpico is a penetration testing report generation and collaboration tool. It was developed to cut down on the amount of time it takes to write a penetration testing report.
	* [Vulnreport](https://github.com/Salesforce/Vulnreport)
		* Vulnreport is a platform for managing penetration tests and generating well-formatted, actionable findings reports without the normal overhead that takes up security engineer's time. The platform is built to support automation at every stage of the process and allow customization for whatever other systems you use as part of your pentesting process.
	* [Ghostwriter](https://github.com/GhostManager/Ghostwriter)
		* Ghostwriter is a Django project written in Python 3.7 and is designed to be used by a team of operators. The platform is made up of several Django apps that own different roles but work together. See the Wiki for more information.
		* [Wiki](https://ghostwriter.wiki/)
		* [Introducing Ghostwriter - Christopher Maddalena](https://posts.specterops.io/introducing-ghostwriter-part-1-61e7bd014aff)
	* [sh00t](https://github.com/pavanw3b/sh00t)
		* sh00t is a task manager to let you focus on performing security testing. Provides To Do checklists of test cases and helps to create bug reports with customizable bug templates
* **Video Recording/Visual Documentation**<a name="video"></a>
	* [Open Broadcaster Software OBS](https://obsproject.com/)
		* Open Broadcaster Software is free and open source software for video recording and live streaming. Cross Platform, Windows/OsX/Linux
	* [Cryptoshot](https://github.com/DiabloHorn/cryptoshot) 
		* This application will make a screenshot of the desktop. If the desktop consists of multiple monitors, it should still work fine. However it has only been tested with a dual monitor setup. The windows project has the added functionality of sending the screenshot to a server of your choosing.
	* [Record terminal sessions and have the ability to replay it](http://linux.byexamples.com/archives/279/record-the-terminal-session-and-replay-later/)
	* [Pocuito](https://github.com/tunnelshade/pocuito)
		* A tiny chrome extension to record and replay your web application proof-of-concepts. Replaying PoCs from bug tracker written steps is a pain most of the time, so just record the poc, distribute and replay it whenever necessary without much hassle.
	* [kap](https://github.com/wulkano/kap)
			* An open-source screen recorder built with web technology
	* [CrScreenshotDxe](https://github.com/NikolajSchlej/CrScreenshotDxe)
		* UEFI DXE driver to take screenshots from GOP-compatible graphic console
	* [ScreenToGif](https://github.com/NickeManarin/ScreenToGif)
		* ScreenToGif allows you to record a selected area of your screen, edit and save it as a gif or video
* **Sample/Template Documents**
	* [Pentest/Red Team Offering Documents - mubix](https://drive.google.com/drive/folders/0ByiDshWJ_PnZdnJZQ0h3MWZyRUk)



----------------
### <a name="disclosure"></a>Disclosure
* **101**
	* [OWASP Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)
	* [NCSAM: Coordinated Vulnerability Disclosure Advice for Researchers](https://community.rapid7.com/community/infosec/blog/2016/10/28/ncsam-coordinated-vulnerability-disclosure-advice-for-researchers)
	* [Protecting Your Sources When Releasing Sensitive Documents](https://source.opennews.org/articles/how-protect-your-sources-when-releasing-sensitive-/)
	* [Good comparison of various forms of disclosure](http://blog.opensecurityresearch.com/2014/06/approaches-to-vulnerability-disclosure.html)
	* [Threatbutt irresponsible disclosure policy](http://threatbutt.com/bugbounty.html)
	* [The CERT Guide to Coordinated Vulnerability Disclosure - Allen Householder](https://vuls.cert.org/confluence/display/CVD)
* **CVE**
	* [Request a CVE ID](http://cve.mitre.org/cve/request_id.html#cna_coverage)
	* [My first CVE-2016-1000329 in BlogPHP](https://www.stevencampbell.info/2016/12/my-first-cve-2016-1000329-in-blogphp/)
* **Dealing with the press/journalists:**
	* [Hacking the media for fame/profit talk](http://www.irongeek.com/i.php?page=videos/derbycon4/Hacking-The-Media-For-Fame-And-Profit-Jenn-Ellis-Steven-Reganh)
* **History**
	* [Coordinated Vulnerability Disclosure: Bringing Balance to the Force - blogs.technet](https://blogs.technet.microsoft.com/ecostrat/2010/07/22/coordinated-vulnerability-disclosure-bringing-balance-to-the-force/)
	* [Full disclosure (computer security) - Wikipedia](https://en.wikipedia.org/wiki/Full_disclosure_(computer_security))
	* [Schneier: Full Disclosure of Security Vulnerabilities a 'Damned Good Idea' - Bruce Schneier](https://www.schneier.com/essays/archives/2007/01/schneier_full_disclo.html)
	* [Responsible Disclosure is Wrong](https://adamcaudill.com/2015/11/19/responsible-disclosure-is-wrong/)
* **How-To**
	* [How to Disclose or Sell an Exploit - DEF CON 21 - James Denaro](https://www.youtube.com/watch?v=N1Xj3f4felg)
	* [How to Disclose an Exploit Without Getting in Trouble DEF CON 22 - Jim Denaro and Tod Beardsley](https://www.youtube.com/watch?v=Y8Cpio6z9qA)
* **Articles/Blogposts/Writeups**
	* [Ethical dilemmas with responsible disclosure - Ken Munro(2020)](https://www.pentestpartners.com/security-blog/ethical-dilemmas-with-responsible-disclosure/)
* **Talks/Presentations/Videos**
	* [Selling 0-Days to Governments and Offensive Security Companies - Maor Shwartz(BHUSA2019)](https://www.youtube.com/watch?v=ZDHHGZlEfsQ&feature=emb_logo)
		* Selling 0-days is a fascinating process that not a lot of people are familiar with. This talk will discuss a vulnerability brokerage company called Q-recon and provide a glimpse of how this market works. In the presentation, questions will be answered from three different angles: researcher, broker and client
* **Tools**
	* [Portcullis Computer Security Co-ordinated Disclosure Toolkit](https://github.com/portcullislabs/co-ordinated-disclosure-toolkit)
	* [Clean writeup of Full-Disclosure release policy that is more similar to Coordinated Disclosure.](http://www.ilias.de/docu/goto_docu_wiki_1357_RFPolicy.html)



