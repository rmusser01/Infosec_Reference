# Fuzzing (and bug hunting)

-------------------------------------------------
## Table of Contents
- [Genera](#general)
	* [101](#101)
	* [Books](#books)
	* [Bug Hunting in Source Code](#bughunt)
	* [Educational/Informative](#edu)
	* [History](#history)
	* [General](#general2)
	* [Presentations/Talks](#pres)
	* [Training](#train)
- [Fuzzing Stuff & Hunting Bugs](#fuzzhunt)
	* [Dynamic Fuzzing](#dynamic)
	* [Static Fuzzing](#static)
	* [Android Bug Hunting/Fuzzing](#android)
	* [Browser Bug Hunting/Fuzzing](#browser)
	* [C/C++ Fuzzing](#c)
	* [Cellular Related Technologies Bug Hunting/Fuzzing](#cell)
	* [Cisco](#cisco)
	* [COM Fuzzing](#com)
	* [Embedded Devices](#embedded)
	* [File Formats Bug Hunting/Fuzzing](#file)
	* [Network Protocol Bug Hunting/Fuzzing](#network)
	* [Fuzzing Linux](#linux)
	* [Medical Devices](#medical)
	* [OS X Bug Hunting/Fuzzing](#osx)
	* [PDF](#pdf)
	* [RTP](#rtp)
	* [Source Fuzzing/Bug Hunting](#source)
	* [USB Bug Hunting/Fuzzing](#usb)
	* [Virtual Appliance Bug Hunting/Fuzzing](#virtual)
	* [Web Application Bug Hunting/Fuzzing](#web)
	* [Windows Fuzzing/Bug Hunting](#windows)
- [Non Specific Fuzzing Related Tools](#nonspecific)
	* [AFL](#afl)
	* [Peach](#peach)
	* [Miscellaneous/Other](#misc)



------------
### <a name="general"></a>General<a name="general"></a>
* **101**
	* [15 minute guide to fuzzing](https://www.mwrinfosecurity.com/our-thinking/15-minute-guide-to-fuzzing/)
	* [Fuzzing basics...how to break software - grid - Scott M](http://www.irongeek.com/i.php?page=videos/derbycon6/411-fuzzing-basicshow-to-break-software-grid-aka-scott-m)
		* Ever wanted to break software? You know you want to...it's fun! In this talk, I will share some tools & techniques I've used to improve software by breaking it.
	* [Quick explanation of fuzzing and various fuzzers](http://whoisjoe.info/?p=16)
* **Books**
	* [*THE* Book on fuzzing](http://fuzzing.org/)
* **Bug Hunting in Source Code**
	* [GitHub for Bug Bounty Hunters](https://gist.github.com/EdOverflow/922549f610b258f459b219a32f92d10b)
	* [Secure Code Review - OpenSecurityTraining.info](http://opensecuritytraining.info/SecureCodeReview.html)
	* [High-Level Approaches for Finding Vulnerabilities](http://jackson.thuraisamy.me/finding-vulnerabilities.html)
	* [Vulnerabilities 101 : How to Launch or Improve Your  Vulnerability Research Game - Joshua Drake, Steve Christey Coley](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEFCON-24-Drake-Christey-Vulnerabilities-101-UPDATED.pdf)
	* [Bug Hunting with Static Code  Analysis - Nick Jones](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-bug-hunting-with-static-code-analysis-bsides-2016.pdf)
* **Educational/Informative**
	* [Faster Fuzzing with Python](https://labs.mwrinfosecurity.com/blog/2014/12/10/faster-fuzzing-with-python/)
	* [Good slides on fuzzing](https://courses.cs.washington.edu/courses/cse484/14au/slides/Section8.pdf)
	* [The Power Of Pair: One Template That Reveals 100+ Uaf Ie Vulnerabilities - BlackhatEU14](http://www.securitytube.net/video/12924?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SecurityTube+%28SecurityTube.Net%29)
	* [Mining for Bugs with Graph Database Queries [31c3]](https://www.youtube.com/watch?v=291hpUE5-3g)
	* [ClusterFuzz](http://nullcon.net/website/archives/ppt/goa-15/analyzing-chrome-crash-reports-at-scale-by-abhishek-arya.pdf)
	* [Google VRP and Unicorns](https://sites.google.com/site/bughunteruniversity/behind-the-scenes/presentations/google-vrp-and-unicorns)
		* In July 2017 at BountyCraft event we delivered a presentation entitled "Google VRP and Unicorns", featuring a selection of interesting bugs reported to our program, and disclosing some planned updates in store for Google VRP.
	* [How to Spot Good Fuzzing Research - trailofbits](https://blog.trailofbits.com/2018/10/05/how-to-spot-good-fuzzing-research/)
* **History**
	* [Symbolic execution timeline](https://github.com/enzet/symbolic-execution)
		* Diagram highlights some major tools and ideas of pure symbolic execution, dynamic symbolic execution (concolic) as well as related ideas of model checking, SAT/SMT solving, black-box fuzzing, taint data tracking, and other dynamic analysis techniques.
* **General**
	* [Fools of Golden Gate](https://blog.silentsignal.eu/2017/05/08/fools-of-golden-gate/)
		* How major vulnerabilities/large amounts of publicly vulnerable systems can exist without public recognition for long periods of time. (i.e. CVEs(10.0) exist, but no mapping in nessus/metasploit/etc)
	* [Fuzzing workflows; a fuzz job from start to finish](https://foxglovesecurity.com/2016/03/15/fuzzing-workflows-a-fuzz-job-from-start-to-finish/)
	* [Youtube Playlist of Fuzzing Videos](https://www.youtube.com/playlist?list=PLtPrYlwXDImiO_hzK7npBi4eKQQBgygLD)
	* [Effective Bug Discovery](http://uninformed.org/?v=all&a=27&t=sumry)
		* Sophisticated methods are currently being developed and implemented for mitigating the risk of exploitable bugs. The process of researching and discovering vulnerabilities in modern code will require changes to accommodate the shift in vulnerability mitigations. Code coverage analysis implemented in conjunction with fuzz testing reveals faults within a binary file that would have otherwise remained undiscovered by either method alone. This paper suggests a research method for more effective runtime binary analysis using the aforementioned strategy. This study presents empirical evidence that despite the fact that bug detection will become increasingly difficult in the future, analysis techniques have an opportunity to evolve intelligently. 
	* [Upping Your Bug Hunting Skills Using Symbolic Virtual Machines by Anto  - x33fcon](https://www.youtube.com/watch?v=IPSZxGaLlyk)
	* [The Best of Bug Finding - Duo Tech Talk (Charlie Miller)](https://www.youtube.com/watch?v=1M1EOzulQsw)
		* I look at how security vulnerabilities are found (or missed) and some of my favorite bugs and exploits I’ve come across in my career. 
	* [fuzzdb](https://github.com/fuzzdb-project/fuzzdb)
		* Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.
* **Presentations/Talks**
	* [Unusual bugs - 23C3](https://www.youtube.com/watch?v=qj79Qdmw0Pk) 
		* In this presentation I'll present a series of unusual security bugs. Things that I've ran into at some point and went "There's gotta be some security consequence here". None of these are really a secret, and most of them are even documented somewhere. But apparently most people don't seem to know about them.  What you'll see in this presentation is a list of bugs and then some explanation of how these could be exploited somehow. Some of the things I'll be talking about are (recursive) stack overflow, NULL pointer dereferences, regular expressions and more. 
* **Training**
	* [Modern fuzzing of C/C++ Projects - Slides](https://docs.google.com/presentation/d/1pbbXRL7HaNSjyCHWgGkbpNotJuiC4O7L_PDZoGqDf5Q/edit#slide=id.p4)
	* [libfuzzer-workshop](https://github.com/Dor1s/libfuzzer-workshop)
		* Materials of "Modern fuzzing of C/C++ Projects" workshop.



-----------------
### <a name="fuzzhunt"></a> Fuzzing Stuff & Hunting Bugs
* **Dynamic Fuzzing**
	* **Frameworks**
		* [Triton](https://github.com/JonathanSalwan/Triton)
			* Triton is a dynamic binary analysis (DBA) framework. It provides internal components like a Dynamic Symbolic Execution (DSE) engine, a Taint engine, AST representations of the x86 and the x86-64 instructions set semantics, SMT simplification passes, an SMT Solver Interface and, the last but not least, Python bindings.
		* [XDiFF](https://github.com/IOActive/XDiFF)
			* XDiFF is an Extended Differential Fuzzing Framework built for finding vulnerabilities in software. It collects as much data as possible from different executions an then tries to infer different potential vulnerabilities based on the different outputs obtained. The fuzzer uses Python and runs on multiple OSs (Linux, Windows, OS X, and Freebsd). Its main goal is to detect issues based on diffential fuzzing aided with the extended capabilities to increase coverage. Still, it will found common vulnerabilities based on hangs and crashes, allowing to attach a memory debugger to the fuzzing sessions.
	* **Differential Fuzzers**	
		* **101**
			* [Differential testing - Wikipedia](https://en.wikipedia.org/wiki/Differential_testing)
				* Differential testing, also known as differential fuzzing, is a popular software testing technique that attempts to detect bugs, by providing the same input to a series of similar applications (or to different implementations of the same application), and observing differences in their execution. Differential testing complements traditional software testing, because it is well-suited to find semantic or logic bugs that do not exhibit explicit erroneous behaviors like crashes or assertion failures. Differential testing is sometimes called back-to-back testing.
		* **Articles/Blogposts/Writeups**
			* [Exposing Hidden Exploitable Behaviors in Programming Languages Using Differential Fuzzing - Fernando Arnaboldi](https://www.blackhat.com/docs/eu-17/materials/eu-17-Arnaboldi-Exposing-Hidden-Exploitable-Behaviors-In-Programming-Languages-Using-Differential-Fuzzing-wp.pdf)
		* **Talks and Presentations**
			* [Exposing Hidden ExploitableBehaviors in ProgrammingLanguagesUsingDifferential Fuzzing - Fernando Arnaboldi](https://www.blackhat.com/docs/eu-17/materials/eu-17-Arnaboldi-Exposing-Hidden-Exploitable-Behaviors-In-Programming-Languages-Using-Differential-Fuzzing-wp.pdf)
			* [Differential Slicing: Identifying Causal Execution Differences for Security Applications](http://bitblaze.cs.berkeley.edu/papers/diffslicing_oakland11.pdf)
				* Abstract —A security analyst often needs to understand two runs of the same program that exhibit a difference in program state or output. This is important, for example, for vulnerability analysis, as well as for analyzing a malware program that features different behaviors when run in different environments. In this paper we propose a differential slicing approach that automates the analysis of such execution differences. Differential slicing outputs a causal difference graph that captures the input differences that triggered the observe d difference and the causal path of differences that led from thos e input differences to the observed difference. The analyst uses the graph to quickly understand the observed difference. We implement differential slicing and evaluate it on the analysis of 11 real-world vulnerabilities and 2 malware samples with environment-dependent behaviors. We also evaluate it in an informal user study with two vulnerability analysts. Our results show that differential slicing successfully identifies the input differences that caused the observed difference and that the causal difference graph significantly reduces the amount of time and effort required for an analyst to understand the observed difference
		* **Tools**
			* [XDiFF](https://github.com/IOActive/XDiFF)
				* XDiFF is an Extended Differential Fuzzing Framework built for finding vulnerabilities in software. It collects as much data as possible from different executions an then tries to infer different potential vulnerabilities based on the different outputs obtained.
	* **SAT/SMT Solvers**
		* **101**
			* [Quick introduction into SAT/SMT solvers and symbolic execution - Dennis Yurichev](https://yurichev.com/writings/SAT_SMT_draft-EN.pdf)
			* [SAT_SMT_Article](https://github.com/DennisYurichev/SAT_SMT_article)
		* **Articles/Blogposts/Writeups**
		* **Talks and Presentations**
	* **Taint Analysis**
		* **101**
		* **Articles/Blogposts/Writeups**
			* [Taint analysis and pattern matching with Pin - Jonathan Salwan](http://shell-storm.org/blog/Taint-analysis-and-pattern-matching-with-Pin/)
		* **Talks and Presentations**
			* [Applying Taint Analysis and Theorem Proving to Exploit Development - Sean Heelan - RECON2010](http://static1.squarespace.com/static/507c09ede4b0954f51d59c75/t/508eb764e4b047ba54db4999/1351530340153/applying_taint_analysis_and_theorem_proving_to_xdev.pdf)
			* [All You Ever Wanted to Know About Dynamic Taint Analysis and Forward Symbolic Execution (but might have been afraid to ask)](http://users.ece.cmu.edu/~ejschwar/papers/oakland10.pdf)
				* Abstract — Dynamic taint analysis and forward symbolic execution are quickly becoming staple techniques in security analyses. Example applications of dynamic taint analysis and forward symbolic execution include malware analysis, input filter generation, test case generation, and vulnerability dis- covery. Despite the widespread usage of these two techniques, there has been little effort to formally define the algorithms and summarize the critical issues that arise when these techniques are used in typical security contexts. The contributions of this paper are two-fold. First, we precisely describe the algorithms for dynamic taint analysis and forward symbolic execution as extensions to the run-time se- mantics of a general language. Second, we highlight important implementation choices, common pitfalls, and considerations when using these techniques in a security context.
		* **Papers**
			* [A Critical Review of Dynamic Taint Analysis and Forward Symbolic Execution](https://asankhaya.github.io/pdf/CriticalReviewofDynamicTaintAnalysisandForwardSymbolicExecution.pdf)
				* In this note , we describe a critical review of the paper titled “All you wanted to know about dynamics taint analysis and forward symbolic execution (but may have been afraid to ask)” [1] . We analyze the paper using Paul Elder critical thinking framework [2] . We sta rt with a summary of the paper and motivation behind the research work described in [1]. Then we evaluate the study with respect to the universal intellectual standards of [2]. We find that the paper provides a good survey of the existing techniques and algorithms used for security analysis. It explains them using the theoretical framework of operational runtime semantics. However in some places t he paper can do a better job in highlighting what new insights or heuristics can be gained from a runtime seman tics formulation. The paper fails to convince the reader how such an intricate understanding of operational semantics of a new generic language SimpIL helps in advancing the state of the art in dynamic taint analysis and forward symbolic execution. We also found that the Paul Elder critical thinking framework is a useful technique to reason about and analyze research papers.
			* [TAJ: Effective Taint Analysis of Web Applications - Java Webapps](http://manu.sridharan.net/files/pldi153-tripp.pdf)
				* Taint analysis, a form of information-flow analysis, establishes whether values from untrusted methods and parameters may flow into security-sensitive operations. Taint analysis can detect many common vulnerabilities in Web applications, and so has attracted much attention from both the research community and industry. However, most static taint-analysis tools do not address criti- cal requirements for an industrial-strength tool. Specifically, an industrial-strength tool must scale to large industrial Web applica- tions, model essential Web-application code artifacts, and generate consumable reports for a wide range of attack vectors. We have designed and implemented a static Taint Analysis for Java (TAJ) that meets the requirements of industry-level applica- tions. TAJ can analyze applications of virtually any size, as it em- ploys a set of techniques designed to produce useful answers given limited time and space. TAJ addresses a wide variety of attack vec- tors, with techniques to handle reflective calls, flow through con- tainers, nested taint, and issues in generating useful reports. This paper provides a description of the algorithms comprising TAJ, evaluates TAJ against production-level benchmarks, and compares it with alternative solutions.
	* **Tools**
		* [usercorn](https://github.com/lunixbochs/usercorn)
			* dynamic binary analysis via platform emulation 
	* **Writeups**
		* [Fuzzing TCP servers - Robert Swiecki](http://blog.swiecki.net/2018/01/fuzzing-tcp-servers.html)
		* [From Fuzzing to 0day.](http://blog.techorganic.com/2014/05/14/from-fuzzing-to-0-day/)
* **Static Fuzzing**
	* **101**
	* **Articles/Blogposts/Writeups**
	* **Frameworks**
		* [Paper Machete](https://github.com/cetfor/PaperMachete/wiki)
			* Paper Machete (PM) orchestrates Binary Ninja and GRAKN.AI to perform static analysis on binary targets with the goal of finding exploitable vulnerabilities. PM leverages the Binary Ninja MLIL SSA to extract semantic meaning about individual instructions, operations, register/variable state, and overall control flow. This data is then migrated into GRAKN.AI, a hyper-relational database. We then run queries against the database that are designed to look for indications of common software vulnerability classes.
	* **Tools**
	* **Talks/Writeups**
		* [Aiding Static Analysis: Discovering Vulnerabilities in Binary Targets through Knowledge Graph Inferences - John Toterhi - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t116-aiding-static-analysis-discovering-vulnerabilities-in-binary-targets-through-knowledge-graph-inferences-john-toterhi)
			* Static analysis is the foundation of vulnerability research (VR). Even with today's advanced genetic fuzzers, concolic analysis frameworks, emulation engines, and binary instrumentation tools, static analysis ultimately makes or breaks a successful VR program. In this talk, we will explore a method of enhancing our static analysis process using the GRAKN.AI implementation of Google's knowledge graph and explore the semantics from Binary Ninja's Medium Level static single assignment (SSA) intermediate language (IL) to perform inference queries on binary-only targets to identify vulnerabilities.
* **Android Bug Hunting/Fuzzing**
	* **Articles/Writeups**
		* [Fuzzing Object s d’ART Digging Into the New Android L Runtime Internals](http://census-labs.com/media/Fuzzing_Objects_d_ART_hitbsecconf2015ams_WP.pdf)
	* **Tools**
		* [MFFA - Media Fuzzing Framework for Android](https://github.com/fuzzing/MFFA)
		* [android-afl](https://github.com/ele7enxxh/android-afl)
			* Fuzzing Android program with american fuzzy lop (AFL)
		* [Droid Application Fuzz Framework](https://github.com/ajinabraham/Droid-Application-Fuzz-Framework)
			* Droid Application Fuzz Framework (DAFF) helps you to fuzz Android Browsers and PDF Readers for memory corruption bugs in real android devices. You can use the inbuilt fuzzers or import fuzz files from your own custom fuzzers. DAFF consist of inbuilt fuzzers and crash monitor. It currently supports fuzzing the following applications:
		* [MFFA - Media Fuzzing Framework for Android (Stagefright fuzzer)](https://github.com/fuzzing/MFFA)
			* The main idea behind this project is to create corrupt but structurally valid media files, direct them to the appropriate software components in Android to be decoded and/or played and monitor the system for potential issues (i.e system crashes) that may lead to exploitable vulnerabilities. Custom developed Python scripts are used to send the malformed data across a distributed infrastructure of Android devices, log the findings and monitor for possible issues, in an automated manner. The actual decoding of the media files on the Android devices is done using the Stagefright command line interface. The results are sorted out, in an attempt to find only the unique issues, using a custom built triage mechanism.
* **Browser Bug Hunting/Fuzzing**
	* [Browser Bug Hunting and Mobile](http://slides.com/revskills/fzbrowsers#/)
	* [Grinder - Fuzzer](https://github.com/stephenfewer/grinder)
		* Grinder is a system to automate the fuzzing of web browsers and the management of a large number of crashes. Grinder Nodes provide an automated way to fuzz a browser, and generate useful crash information (such as call stacks with symbol information as well as logging information which can be used to generate reproducible test cases at a later stage). A Grinder Server provides a central location to collate crashes and, through a web interface, allows multiple users to login and manage all the crashes being generated by all of the Grinder Nodes.
	* [browserfuzz](https://bitbucket.org/blackaura/browserfuzz)
		* A very simple browser fuzzer based on tornado.
	* [Browser bug hunting - Memoirs of a last man standing, Atte Kettunen](https://vimeo.com/109380793)
	* [morph](https://github.com/walkerfuz/morph)
		* an open source browser fuzzing framework for fun.
* **C/C++ Fuzzing**
	* [ansvif](https://oxagast.github.io/ansvif/) - An advanced cross platform fuzzing framework designed to find vulnerabilities in C/C++ code.
	* [libFuzzer](http://libfuzzer.info) - In-process, coverage-guided, evolutionary fuzzing engine for targets written in C/C++.
* **Cellular Related Technologies Bug Hunting/Fuzzing**
	* [Binary SMS - The old backdoor to your new thing](https://www.contextis.com/resources/blog/binary-sms-old-backdoor-your-new-thing/)
	* [Fuzzing the Phone in your Phone](https://www.blackhat.com/presentations/bh-usa-09/MILLER/BHUSA09-Miller-FuzzingPhone-PAPER.pdf)
* **Cisco**
	* [asadbg](https://github.com/nccgroup/asadbg)
		* asadbg is a framework of tools to aid in automating live debugging of Cisco ASA devices, as well as automating interaction with the Cisco CLI over serial/ssh to quickly perform repetitive tasks.
	* [asatools - NCCGroup](https://github.com/nccgroup/asatools)
		* Main repository to pull all Cisco ASA-related projects.
	* [asafw](https://github.com/nccgroup/asafw)
		* Set of scripts to deal with Cisco ASA firmware [pack/unpack etc.]
* **COM Fuzzing**
	* [COMRaider](http://sandsprite.com/iDef/COMRaider/)
		* ActiveX Fuzzing tool with GUI, object browser, system scanner, and distributed auditing capabilities
		* [Github](https://github.com/dzzie/COMRaider)
* **Embedded Devices Fuzzing/Bug Hunting**
	* [Bug Hunting: Drilling into the Internet of Things(IoT) - DuoLabs](https://duo.com/assets/ebooks/Duo-Labs-Bug-Hunting-Drilling-Into-the-Internet-of-Things-IoT.pdf)
* **File Formats Bug Hunting/Fuzzing**
	* [Practical File Format Fuzzing](http://www.irongeek.com/i.php?page=videos/derbycon3/3301-practical-file-format-fuzzing-jared-allar)
		* File format fuzzing has been very fruitful at discovering exploitable vulnerabilities. Adversaries take advantage of these vulnerabilities to conduct spear-phishing attacks. This talk will cover the basics of file format fuzzing and show you how to use CERT’s fuzzing frameworks to discovery vulnerabilities in file parsers.
	* [File Format Fuzzing in Android](https://deepsec.net/docs/Slides/2015/File_Format_Fuzzing_in_Android_-Alexandru_Blanda.pdf)
	* [Funky File Formats - Advanced Binary Exploitation](http://media.ccc.de/browse/congress/2014/31c3_-_5930_-_en_-_saal_6_-_201412291400_-_funky_file_formats_-_ange_albertini.html#video)
* **Network Protocols Bug Hunting/Fuzzing** <a name="network"></a>
	* **Articles/Writeups**
		* [Fuzzing proprietary protocols with Scapy, radamsa and a handful of PCAPs](https://blog.blazeinfosec.com/fuzzing-proprietary-protocols-with-scapy-radamsa-and-a-handful-of-pcaps/)
		* [Introduction to Custom Protocol Fuzzing](https://www.youtube.com/watch?v=ieatSJ7ViBw)
	* **Tools**
		* [boofuzz](https://github.com/jtpereyda/boofuzz)
			* Boofuzz is a fork of and the successor to the venerable Sulley fuzzing framework. Besides numerous bug fixes, boofuzz aims for extensibility. The goal: fuzz everything.
			* [boofuzz quickstart](https://boofuzz.readthedocs.io/en/latest/user/quickstart.html)
		* [rage_fuzzer](https://github.com/deanjerkovich/rage_fuzzer)
			* A dumb protocol-unaware packet fuzzer/replayer.
		* [Nightmare](https://github.com/joxeankoret/nightmare)
			* A distributed fuzzing testing suite with web administration, supports fuzzing using network protocols.
		* [pcrappyfuzzer](https://github.com/blazeinfosec/pcrappyfuzzer)
			* Script to perform quick 'n dirty fuzzing of PCAPs with radamsa and Scapy.
* **Fuzzing Linux**
	* **Kernel**
		* [KernelFuzzer](https://github.com/mwrlabs/KernelFuzzer) - Cross Platform Kernel Fuzzer Framework.
	* **Syscalls**
		* [syzkaller - linux syscall fuzzer](https://github.com/google/syzkaller)
			* An unsupervised, coverage-guided Linux syscall fuzzer. It is meant to be used with KASAN (CONFIG_KASAN=y), KTSAN (CONFIG_KTSAN=y), or KUBSAN.
* **Libraries**
	* [libFuzzer]((http://llvm.org/docs/LibFuzzer.html)
		* library for in-process evolutionary fuzzing of other libraries.
* **Medical Devices**
	* [Open Up and Say 0x41414141: Attacking Medical Devices - Robert PortvlIet - Toorcon19](https://www.youtube.com/watch?index=3&v=SBw78men_70&app=desktop)
		* Network accessible medical devices are ubiquitous in today’s clinical environment. These devices can be of great aid to healthcare profes- sionals in assessing, treating and monitoring a patient’s condition. However, they can also fall victim to a number of systemic vulnerabili- ties that can expose personal health information or PHI, compromise the integrity of patient data in transit, and affect the availability of the devices themselves. This talk looks at the methodology and approach to penetration testing of modern medical devices. It will provide an overview of the various stages of a medical device assessment, including discovery and analysis of a device’s remote and local attack surface, reverse engineering and exploitation of proprietary network protocols, vulner- ability discovery in network services, compromising supporting sys- tems, attacking common wireless protocols, exploitation of hardware debug interfaces and bus protocols and assessing proprietary wireless technologies. It will also cover a number of real world vulnerabilities that the speaker has discovered during medical device penetration testing assessments. These include weak cryptographic implementations, device impersonation and data manipulation vulnerabilities in pro- prietary protocols, unauthenticated database interfaces, hardcoded credentials/keys and other sensitive information stored in firmware/ binaries and the susceptibility of medical devices to remote denial of service attacks. The talk will conclude with some suggestions on how some of the most common classes of medical device vulnerabilities might be reme- diated by vendors and also how hospitals and other healthcare provid- ers can defend their medical devices in the meantime.
* **OS X Bug Hunting/Fuzzing**
	* [There's a lot of vulnerable OS X applications out there](https://vulnsec.com/2016/osx-apps-vulnerabilities/)
* **PDF**
	* [0-day streams: pdfcrack](https://www.youtube.com/watch?v=8VLNPIIgKbQ&app=desktop)
* **RTP**
	* [ohrwurm](http://mazzoo.de/blog/2006/08/25#ohrwurm)
		* ohrwurm is a small and simple RTP fuzzer, I tested it on a small number of SIP phones, none of them did withstand.
* **Source Code Fuzzing/Bug Hunting**
	* **Articles/Talks/Writeups**
		* [Improving security with Fuzzing and Sanitizers](https://media.ccc.de/v/SHA2017-148-improving_security_with_fuzzing_and_sanitizers)
			* A bug in Gstreamer could be used to own a Linux Desktop system. TCPDump released a security update fixing 42 CVEs. We have far too many security critical bugs in the free and open source software stack. But we have powerful tools to find them - we just have to use them.
		* [GitHub for Bug Bounty Hunters](https://gist.github.com/EdOverflow/922549f610b258f459b219a32f92d10b)
		* [Secure Code Review - OpenSecurityTraining.info](http://opensecuritytraining.info/SecureCodeReview.html)
		* [High-Level Approaches for Finding Vulnerabilities](http://jackson.thuraisamy.me/finding-vulnerabilities.html)
		* [Vulnerabilities 101 : How to Launch or Improve Your  Vulnerability Research Game - Joshua Drake, Steve Christey Coley](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEFCON-24-Drake-Christey-Vulnerabilities-101-UPDATED.pdf)
		* [Bug Hunting with Static Code  Analysis - Nick Jones](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-bug-hunting-with-static-code-analysis-bsides-2016.pdf)
	* **Tools**
		* [Google - AddressSanitizer, ThreadSanitizer, MemorySanitizer, LeaksSanitizer](https://github.com/google/sanitizers)
			* This project is the home for Sanitizers: AddressSanitizer, MemorySanitizer, ThreadSanitizer, LeakSanitizer. The actual code resides in the LLVM repository. Here we keep extended documentation, bugs and some helper code.
* **USB Bug Hunting/Fuzzing**
	* [Introduction to USB and Fuzzing DEFCON23 Matt DuHarte](https://www.youtube.com/watch?v=KWOTXypBt4E)
	* [Implementing an USB Host Driver Fuzzer - Daniel Mende - Troopers14](https://www.youtube.com/watch?v=h777lF6xjs4)
	* [USB Fuzzing Basics: From fuzzing to bug reporting](http://blog.quarkslab.com/usb-fuzzing-basics-from-fuzzing-to-bug-reporting.html)
	* [Introduction to USB and Fuzzing DEFCON23 Matt DuHarte](https://www.youtube.com/watch?v=KWOTXypBt4E)
* **Virtual Appliance Bug Hunting/Fuzzing**
	* [Hacking Virtual Appliances - DerbyconV](https://www.irongeek.com/i.php?page=videos/derbycon5/fix-me08-hacking-virtual-appliances-jeremy-brown)
		* Virtual Appliances have become very prevalent these days as virtualization is ubiquitous and hypervisors commonplace. More and more of the major vendors are providing literally virtual clones for many of their once physical-only products. Like IoT and the CAN bus, it's early in the game and vendors are late as usual. One thing that it catching these vendors off guard is the huge additional attack surface, ripe with vulnerabilities, added in the process. Also, many vendors see software appliances as an opportunity for the customer to easily evaluate the product before buying the physical one, making these editions more accessible and debuggable by utilizing features of the platform on which it runs. During this talk, I will provide real case studies for various vulnerabilities created by mistakes that many of the major players made when shipping their appliances. You'll learn how to find these bugs yourself and how the vendors went about fixing them, if at all. By the end of this talk, you should have a firm grasp of how one goes about getting remotes on these appliances.
* **Web Application Bug Hunting/Fuzzing**
	* [Advice From A Researcher: Hunting XXE For Fun and Profit](https://blog.bugcrowd.com/advice-from-a-researcher-xxe/)
	* See web section.
* **Windows Fuzzing/Bug Hunting**
	* **F** 
	* **Tools**
		* [WinAFL](https://github.com/ivanfratric/winafl) - A fork of AFL for fuzzing Windows binaries 
		* [!exploitable Crash Analyzer](https://msecdbg.codeplex.com/)
			* !exploitable (pronounced “bang exploitable”) is a Windows debugging extension (Windbg) that provides automated crash analysis and security risk assessment. The tool first creates hashes to determine the uniqueness of a crash and then assigns an exploitability rating to the crash: Exploitable, Probably Exploitable, Probably Not Exploitable, or Unknown. There is more detailed information about the tool in the following .pptx file or at http://www.microsoft.com/security/msec. Additonally, see the blog post at http://blogs.technet.com/srd/archive/2009/04/08/the-history-of-the-exploitable-crash-analyzer.aspx, or watch the video at http://channel9.msdn.com/posts/PDCNews/Bang-Exploitable-Security-Analyzer/.
		* [DiffRay](https://github.com/pinkflawd/DiffRay)
			* Tool for diffing Win7 & Win8 Libraries based on textfile outputs from IDA Pro.
		* [sandbox-attacksurface-analysis-tools](https://github.com/google/sandbox-attacksurface-analysis-tools)
			* This is a small suite of tools to test various properties of sandboxes on Windows. Many of the checking tools take a -p flag which is used to specify the PID of a sandboxed process. The tool will impersonate the token of that process and determine what access is allowed from that location. Also it's recommended to run these tools as an administrator or local system to ensure the system can be appropriately enumerated.
		* [CERT’s Failure Observation Engine (FOE)](https://www.cert.org/vulnerability-analysis/tools/foe.cfm)
			* The CERT Failure Observation Engine (FOE) is a software testing tool that finds defects in applications that run on the Windows platform. FOE performs mutational fuzzing on software that consumes file input. (Mutational fuzzing is the act of taking well-formed input data and corrupting it in various ways looking for cases that cause crashes.) The FOE automatically collects test cases that cause software to crash in unique ways, as well as debugging information associated with the crashes. The goal of FOE is to minimize the effort required for software vendors and security researchers to efficiently discover and analyze security vulnerabilities found via fuzzing.
			* [Walkthrough of setting up CERT’s FOE fuzzer and fuzzing irfanview](http://www.singlehop.com/blog/lets-fuzz-irfanview/)
	* **Articles/Writeups**
		* [Running Windows 64-bit in QEMU Emulation Mode](https://www.invincealabs.com/blog/2016/07/running-windows-64bit-qemu/)
		* [Smart COM Fuzzing - Auditing IE Sandbox Bypass in COM Objects• Xiaoning Li • Haifei Li](https://0b3dcaf9-a-62cb3a1a-s-sites.googlegroups.com/site/zerodayresearch/Smart_COM_Fuzzing_Auditing_IE_Sandbox_Bypass_in_COM_Objects_final.pdf)
		* [Fuzzing for MS15-010](http://blog.beyondtrust.com/fuzzing-for-ms15-010)
			* This past Patch Tuesday Microsoft released MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution.  This patch addressed multiple privately reported vulnerabilities in win32k.sys and one publicly disclosed vulnerability in cng.sys. This post goes through identifying the patched vulnerability.
		* [What Happens In Windows 7 Stays In Windows 7 - Marion Marschalek & Joseph Moti - Troopers14](https://www.youtube.com/watch?v=s_7Cy2w2dCw)
			* Diffing libs in Win7 compared to Win8 to id vuln dlls.
		* [Fuzzing for MS15-010](http://blog.beyondtrust.com/fuzzing-for-ms15-010)
			* Is what it says on the tin.
	* **Patch Analysis**
		* [Microsoft Patch Analysis for Exploitation - Stephen Sims](https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t111-microsoft-patch-analysis-for-exploitation-stephen-sims)
			* Since the early 2000's Microsoft has distributed patches on the second Tuesday of each month. Bad guys, good guys, and many in-between compare the newly released patches to the unpatched version of the files to identify the security fixes. Many organizations take weeks to patch and the faster someone can reverse engineer the patches and get a working exploit written, the more valuable it is as an attack vector. Analysis also allows a researcher to identify common ways that Microsoft fixes bugs which can be used to find 0-days. Microsoft has recently moved to mandatory cumulative patches which introduces complexity in extracting patches for analysis. Join me in this presentation while I demonstrate the analysis of various patches and exploits, as well as the best-known method for modern patch extraction.

-----------------
### Non-Specific Tools(Don't explicitly fit into above sections)

* **AFL**
	* [American Fuzzy Lop AFL](http://lcamtuf.coredump.cx/afl/)
		* American fuzzy lop is a security-oriented fuzzer that employs a novel type of compile-time instrumentation and genetic algorithms to automatically discover clean, interesting test cases that trigger new internal states in the targeted binary. This substantially improves the functional coverage for the fuzzed code. The compact synthesized corpora produced by the tool are also useful for seeding other, more labor- or resource-intensive testing regimes down the road. 
	* **101**
	* **Articles/Writeups/Talks**
		* [How to fuzz a server with American Fuzzy Lop](https://www.fastly.com/blog/how-fuzz-server-american-fuzzy-lop)
		* [Fuzz Smarter, Not Harder (An Afl-Fuzz Primer) BSides-SF 2016](http://www.securitytube.net/video/15372)
		* [How to: Fuzzing open source projects with american fuzzy lop (AFL)](https://0x00rick.com/research/2018/04/20/afl_intro.html)
	* **Associated Tools**
		* [crashwalk](https://github.com/bnagy/crashwalk)
			* Bucket and triage on-disk crashes. OSX and Linux.(automated triaging of AFL-based crashes)
		* [afl-dyninst ; AFL Fuzzing blackbox binaries](https://github.com/vrtadmin/moflow/tree/master/afl-dyninst)
			* American Fuzzy Lop + Dyninst == AFL Fuzzing blackbox binaries  The tool has two parts. The instrumentation tool and the instrumentation  library. Instrumentation library has an initialization callback and basic  block callback functions which are designed to emulate what AFL is doing with afl-gcc/afl-g++/afl-as.  Instrumentation tool (afl-dyninst) instruments the supplied binary by inserting callbacks for each basic block and an initialization  callback either at `_init` or at specified entry point.
* **Peach**
	* **101**
		* [Peach Documentation](http://old.peachfuzzer.com/Introduction.html)
		* [Creating Custom Peach Fuzzer Publishers](http://blog.opensecurityresearch.com/2014/01/creating-custom-peach-fuzzer-publishers.html)
			* [Code](https://github.com/OpenSecurityResearch/CustomPeachPublisher)
	* **Articles/Talks/Writeups**
		* [Fuzzing with Peach tutorial](http://www.flinkd.org/2011/07/fuzzing-with-peach-part-1/)
			* [Part 2](http://www.flinkd.org/2011/11/fuzzing-with-peach-part-2-fixups-2/)
		* [Fuzzing Vulnserver with Peach 3](http://rockfishsec.blogspot.com/2014/01/fuzzing-vulnserver-with-peach-3.html)
* **Miscellaneous/Other**
	* [Starting out with Joern](http://tsyrklevich.net/2015/03/28/starting-out-with-joern/)
	* [Kitty][https://github.com/cisco-sas/kitty]
		* Fuzzing framework written in python(Not a fuzzer)
	* [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml)
	* [PANDA ( Platform for Architecture-Neutral Dynamic Analysis )](https://github.com/moyix/panda)
	* [QIRA (QEMU Interactive Runtime Analyser)](http://qira.me/)
	* [Fuzzapi](https://github.com/lalithr95/fuzzapi) - Fuzzapi is rails application which uses API_Fuzzer and provide UI solution for gem.
	* [Zulu Fuzzer](https://github.com/nccgroup/Zulu)
		* The Zulu fuzzer
	* [honggfuzz](https://github.com/google/honggfuzz)
		* Security oriented fuzzer with powerful analysis options. Supports evolutionary, feedback-driven fuzzing based on code coverage (sw and hw) http://google.github.io/honggfuzz/
	* [Radamsa](https://code.google.com/p/ouspg/wiki/Radamsa)
		* Radamsa is a test case generator for robustness testing, aka a fuzzer. It can be used to test how well a program can stand malformed and potentially malicious inputs. It operates based on given sample inputs and thus requires minimal effort to set up. The main selling points of radamsa are that it is easy to use, contains several old and new fuzzing algorithms, is easy to script from command line and has already been used to find a slew of bugs in programs that actually matter. 
	* [binnavi](https://github.com/google/binnavi) - Binary analysis IDE, annotates control flow graphs and call graphs of disassembled code.
	* [Capstone](https://github.com/aquynh/capstone) - Capstone is a lightweight multi-platform, multi-architecture disassembly framework.
	* [Hodor Fuzzer](https://github.com/nccgroup/hodor) - Yet Another general purpose fuzzer.
	* [libfuzzer-gv](https://github.com/guidovranken/libfuzzer-gv) - enhanced fork of libFuzzer
	* [libFuzzer-gv: new techniques for dramatically faster fuzzing](https://guidovranken.wordpress.com/2017/07/08/libfuzzer-gv-new-techniques-for-dramatically-faster-fuzzing/)
	* [FuzzManager](https://github.com/MozillaSecurity/FuzzManager)
		* With this project, we aim to create a management toolchain for fuzzing. Unlike other toolchains and frameworks, we want to be modular in such a way that you can use those parts of FuzzManager that seem interesting to you without forcing a process upon you that does not fit your requirements.



### Sorting
* [dbusmap](https://github.com/taviso/dbusmap)
	* This is a simple utility for enumerating D-Bus endpoints, an nmap for D-Bus.


* [Firmware Slap](https://github.com/ChrisTheCoolHut/Firmware_Slap)
	* Firmware slap combines concolic analysis with function clustering for vulnerability discovery and function similarity in firmware. Firmware slap is built as a series of libraries and exports most information as either pickles or JSON for integration with other tools.

https://github.com/secfigo/Awesome-Fuzzing
* [AFL + QuickCheck = ? - Dan Luu](https://danluu.com/testing/)
* [Automating Windows Kernel Analysis With Symbolic Execution - Spencer McIntyre(BSides Cleveland 2019)](https://www.irongeek.com/i.php?page=videos/bsidescleveland2019/bsides-cleveland-c-03-automating-windows-kernel-analysis-with-symbolic-execution-spencer-mcintyre)

https://www.usenix.org/conference/woot12/workshop-program/presentation/vanegue
https://labs.mwrinfosecurity.com/publications/corrupting-memory-in-microsoft-office-protected-view-sandbox/?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&refsrc=email&iid=565088e5a455476c97c557e8bbcec069&fl=4&uid=150127534&nid=244+285282312
https://github.com/nccgroup/fuzzowski
https://mattwarren.org/2018/08/28/Fuzzing-the-.NET-JIT-Compiler/
https://github.com/jakobbotsch/Fuzzlyn


Fuzzing
https://raw.githubusercontent.com/secfigo/Awesome-Fuzzing/master/README.md
* Add Descriptions/generals to types of fuzzing
* [Basic fuzzing framework](https://www.cert.org/vulnerability-analysis/tools/bff-download.cfm)
* [Fuzzing 101 (Part 1)]()
* [Fuzzing 101 (Part 2)](https://vimeo.com/5237484)

https://github.com/MotherFuzzers/meetups/blob/master/README.md


https://github.com/googleprojectzero/BrokenType
	* https://bloggeek.me/webrtc-fuzz-testing/
	* https://webrtchacks.com/lets-get-better-at-fuzzing-in-2019-heres-how/
	* https://github.com/googleprojectzero/Street-Party
	* https://googleprojectzero.blogspot.com/2018/12/adventures-in-video-conferencing-part-5.html

Binary Instrumentation
	* http://deniable.org/reversing/binary-instrumentation
	* https://thefengs.com/wuchang/courses/cs492/afl/#0

http://joxeankoret.com/blog/2015/03/13/diaphora-a-program-diffing-plugin-for-ida-pro/
http://joxeankoret.com/blog/2018/08/12/histories-of-comparing-binaries-with-source-codes/
http://joxeankoret.com/blog/2018/11/04/new-cfg-based-heuristic-diaphora/
