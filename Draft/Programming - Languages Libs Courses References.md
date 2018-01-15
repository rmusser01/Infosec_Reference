# Programming Language Courses/References/Security (AppSec)

## Table of Contents
* [General](#general)
* [Source Code Analysis](#sca)
* [ASM](#asm)
* [Android](#android)
* [Bash](#bash)
* [C/C++](#c)
* [Go](#go)
* [Java](#java)
* [.Net](#net)
* [Perl](#perl)
* [Powershell](#power)
* [Python](#python)
* [Ruby](#ruby)
* [Papers](#papers)

### Sort

[Code Insecurity or Code in Security - Mano 'dash4rk' Paul](http://www.irongeek.com/i.php?page=videos/derbycon4/t205-code-insecurity-or-code-in-security-mano-dash4rk-paul)
	* Attendees of this talk will benefit from learning about what constitutes insecure code and the associated attacks that stem from such code. Applicable attacks ranging from injection to reversing will be demonstrated to reinforce contents of this talk. This way, the attendee would not only be taught about “What not to do?” but also, “Why this should not do, what they ought not to do?”. Finally, attendees will also be introduced to secure development processes such as protection needs elicitation, threat modeling, code review and analysis and secure deployment, to illustrate that while writing secure code is one important aspect of software security, there is more to securing applications, than what meets the eye. Come for a fun filled, interactive session and your chance to win one of the personalized and autographed copies of the speaker’s renowned book – The 7 qualities of highly secure software.

* [Django-Security](https://github.com/sdelements/django-security)
	* This package offers a number of models, views, middlewares and forms to facilitate security hardening of Django applications.
* [FindBugs](https://find-sec-bugs.github.io/)
	* The FindBugs plugin for security audits of Java web applications.
* [bundler-audit](https://github.com/rubysec/bundler-audit)
	* Patch-level verification for Bundler
* [OWASP SafeNuGet](https://github.com/owasp/SafeNuGet)
	* OWASP SafeNuGet is an MsBuild task to warn about insecure NuGet libraries: https://nuget.org/packages/SafeNuGet/

* [One Line of Code that Compromises Your Server - The dangers of a simplistic session secret](https://martinfowler.com/articles/session-secret.html)

* [SourceTrail](https://www.sourcetrail.com/)
	* A cross-platform source explorer for C/C++ and Java* 

* [Attack Surface Meter](https://github.com/andymeneely/attack-surface-metrics)
	* Python package for collecting attack surface metrics from a software system. In its current version, Attack Surface Meter is capable of analyzing software systems written in the C programming language with skeletal support for analyzing software systems written in the Java programming language. The attack surface metrics collected are:
	* Proximity to Entry/Exit/Dangerous - The mean of shortest unweighted path length from a function/file to Entry Points/Exit Points/Dangerous Points.
    * Risky Walk - The probability that a function/file will be invoked on a random execution path starting at the attack surface.

* [Code Insecurity or Code in Security - Mano 'dash4rk' Paul - Derbycon2014](https://www.irongeek.com/i.php?page=videos/derbycon4/t205-code-insecurity-or-code-in-security-mano-dash4rk-paul)
	* Attendees of this talk will benefit from learning about what constitutes insecure code and the associated attacks that stem from such code. Applicable attacks ranging from injection to reversing will be demonstrated to reinforce contents of this talk. This way, the attendee would not only be taught about “What not to do?” but also, “Why this should not do, what they ought not to do?”. Finally, attendees will also be introduced to secure development processes such as protection needs elicitation, threat modeling, code review and analysis and secure deployment, to illustrate that while writing secure code is one important aspect of software security, there is more to securing applications, than what meets the eye. Come for a fun filled, interactive session and your chance to win one of the personalized and autographed copies of the speaker’s renowned book – The 7 qualities of highly secure software.


http://en.cppreference.com/w/c	

* [Hide data inside pointers](http://arjunsreedharan.org/post/105266490272/hide-data-inside-pointers)
* [Alamofire](https://github.com/Alamofire/Alamofire)
	* Alamofire is an HTTP networking library written in Swift.

* [plog](https://github.com/SergiusTheBest/plog)
* Portable, simple and extensible C++ logging library
* [Dynamic Source Code Generation and Compilation](https://docs.microsoft.comen-us/dotnet/framework/reflection-and-codedom/dynamic-source-code-generation-and-compilation)

Libraries for Java -> https://www.owasp.org/index.php/Category:Java#tab=Related_3rd_Party_Projects

* [Microsoft Software Development Lifecycle Process Guidance](https://msdn.microsoft.com/en-us/library/windows/desktop/cc307406.aspx)

* [OWASP Proactive Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls?refresh=123#tab=OWASP_Proactive_Controls_2016)
	* The OWASP Top Ten Proactive Controls 2016 is a list of security concepts that should be included in every software development project. They are ordered by order of importance, with control number 1 being the most important.
* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [What I learned from doing 1000 code reviews](https://hackernoon.com/what-i-learned-from-doing-1000-code-reviews-fe28d4d11c71)



#### End Sort





-----------
### <a name="general">General</a>
The content here is just stuff I've come across or think would be useful to someone in infosec. It is not to be taken as anything beyond a suggestion about stuff.
* [Secure Coding Standards - Android](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=111509535)
* [Secure Coding Cheat Sheet - OWASP](https://www.owasp.org/index.php/Secure_Coding_Cheat_Sheet)
* [What a C programmer should know about memory](http://marek.vavrusa.com/c/memory/2015/02/20/memory/)
* [How to be a Programmer: Community Version](https://github.com/braydie/HowToBeAProgrammer)
	* To be a good programmer is difficult and noble. The hardest part of making real a collective vision of a software project is dealing with one's coworkers and customers. Writing computer programs is important and takes great intelligence and skill. But it is really child's play compared to everything else that a good programmer must do to make a software system that succeeds for both the customer and myriad colleagues for whom he or she is partially responsible. In this essay I attempt to summarize as concisely as possible those things that I wish someone had explained to me when I was twenty-one.
* [Loop Patterns](https://users.cs.duke.edu/~ola/patterns/plopd/loops.html#loop-and-a-half)
* [Learn_X_in_Y_Minutes](http://learnxinyminutes.com/)
* [Hyperpolyglot](http://hyperpolyglot.org/)
* [App Ideas - Stuff to build out ot improve your programming skills](https://github.com/tastejs/awesome-app-ideas)
* [Secure iOS application development](https://github.com/felixgr/secure-ios-app-dev)
	* This guide is a collection of the most common vulnerabilities found in iOS applications. The focus is on vulnerabilities in the applications’ code and only marginally covers general iOS system security, Darwin security, C/ObjC/C++ memory safety, or high-level application security. Nevertheless, hopefully the guide can serve as training material to iOS app developers that want to make sure that they ship a more secure app. Also, iOS security reviewers can use it as a reference during assessments.
* [Mostly Adequate Guide](https://drboolean.gitbooks.io/mostly-adequate-guide/)
	* This is a book on the functional paradigm in general. We'll use the world's most popular functional programming language: JavaScript. Some may feel this is a poor choice as it's against the grain of the current culture which, at the moment, feels predominately imperative. 
* [Six Stages of debugging](http://plasmasturm.org/log/6debug/)
	```
		* 1. That can’t happen.
		* 2. That doesn’t happen on my machine.
		* 3. That shouldn’t happen.
		* 4. Why does that happen?
		* 5. Oh, I see.
		* 6. How did that ever work?
	```


### Talks/Videos
Talks/Videos
* [Big picture software testing unit testing, Lean Startup, and everything in between PyCon 2017](https://www.youtube.com/watch?v=Vaq_e7qUA-4&feature=youtu.be&t=63s)
* [Boundaries - By Gary Bernhardt from SCNA 2012](https://www.destroyallsoftware.com/talks/boundaries)
	* This talk is about using simple values (as opposed to complex objects) not just for holding data, but also as the boundaries between components and subsystems. It moves through many topics: functional programming; mutability's relationship to OO; isolated unit testing with and without test doubles; and concurrency, to name some bar. The "Functional Core, Imperative Shell" screencast mentioned at the end is available as part of season 4 of the DAS catalog. 
* [Big picture software testing unit testing, Lean Startup, and everything in between PyCon 2017](https://www.youtube.com/watch?v=Vaq_e7qUA-4&feature=youtu.be&t=63s)
	* There are many ways you can test your software: unit testing, manual testing, end-to-end testing, and so forth. Take a step back and you'll discover even more form of testing, many of them very different in their goals: A/B testing, say, where you see which of two versions of your website results in more signups or ad clicks. How do these forms of testing differ, how do they relate to each other? How do you choose which kind of testing to pursue, given limited time and resources? How do you deal with strongly held yet opposite views arguing either that a particular kind of testing is essential or that it's a waste time? This talk will provide you with a model, a way to organize all forms of testing and understand what exactly they provide, and why. Once you understand the model you will be able to choose the right form of testing for *your* situation and goals.
* [RailsConf 2015 - Nothing is Something](https://www.youtube.com/watch?v=OMPfEXIlTVE)



### Articles
* [Counterfeit Object-oriented Programming](http://syssec.rub.de/media/emma/veroeffentlichungen/2015/03/28/COOP-Oakland15.pdf)
* [Getting Started with WinDbg part 1](http://blog.opensecurityresearch.com/2013/12/getting-started-with-windbg-part-1.html)
* [An Introduction to Debugging the Windows Kernel with WinDbg](http://www.contextis.com/resources/blog/introduction-debugging-windows-kernel-windbg/)
* [Hide data inside pointers](http://arjunsreedharan.org/post/105266490272/hide-data-inside-pointers)
* [Record and Replay Debugging with Firefox](https://developer.mozilla.org/en-US/docs/Mozilla/Debugging/Record_and_Replay_Debugging_Firefox)
* [rr](https://github.com/mozilla/rr)
	* rr is a lightweight tool for recording and replaying execution of applications (trees of processes and threads). More information about the project, including instructions on how to install, run, and build rr, is at http://rr-project.org.w



-----------
### <a name="sca">Source Code Analysis</a>
Source Code Analysis
* Tools
	* [RIPS](http://rips-scanner.sourceforge.net/)
		* RIPS is a tool written in PHP to find vulnerabilities in PHP applications using static code analysis. By tokenizing and parsing all source code files RIPS is able to transform PHP source code into a program model and to detect sensitive sinks (potentially vulnerable functions) that can be tainted by user input (influenced by a malicious user) during the program flow. Besides the structured output of found vulnerabilities RIPS also offers an integrated code audit framework for further manual analysis.
	* [PHPMD - PHP Mess Detector](http://phpmd.org/about.html)  * What PHPMD does is: It takes a given PHP source code base and look for several potential problems within that source. These problems can be things like: Possible bugs; Suboptimal code; Overcomplicated expressions; Unused parameters, methods, properties.
	* [PMD](http://pmd.sourceforge.net/)
		* PMD is a source code analyzer. It finds common programming flaws like unused variables, empty catch blocks, unnecessary object creation, and so forth. It supports Java, JavaScript, PLSQL, Apache Velocity, XML, XSL. Additionally it includes CPD, the copy-paste-detector. CPD finds duplicated code in Java, C, C++, C#, PHP, Ruby, Fortran, JavaScript, PLSQL, Apache Velocity, Ruby, Scala, Objective C, Matlab, Python, Go. 
	* [Graudit](http://www.justanotherhacker.com/projects/graudit.html)
		* Graudit is a simple script and signature sets that allows you to find potential security flaws in source code using the GNU utility grep. It's comparable to other static analysis applications like RATS, SWAAT and flaw-finder while keeping the technical requirements to a minimum and being very flexible.
	* [PumaScan](https://github.com/pumasecurity/puma-scan)
		* provides real time, continuous source code analysis
	* [How to find 56 potential vulnerabilities in FreeBSD code in one evening](https://www.viva64.com/en/b/0496/)
	* [Phan](https://github.com/phan/phan)
		* Phan is a static analyzer for PHP. Phan prefers to avoid false-positives and attempts to prove incorrectness rather than correctness.



---------
### <a name="asm">Assembly x86/x64/ARM</a>
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
* Videos
	* [Introduction Video Series(6) to x86 Assembly](https://www.youtube.com/watch?v=qn1_dRjM6F0&list=PLPXsMt57rLthf58PFYE9gOAsuyvs7T5W9)
	* [Intro to x86 - Derbycon5](http://www.irongeek.com/i.php?page=videos/derbycon5/stable34-intro-to-x86-stephanie-preston)
* Tools
	* [WinREPL](https://github.com/zerosum0x0/WinREPL)
		* x86 and x64 assembly "read-eval-print loop" shell for Windows
	* [aslrepl](https://github.com/enferex/asrepl)
		* asrepl is an assembly based REPL. The REPL processes each line of user input, the output can be witnessed by issuing the command 'regs' and looking at the register state.


----------
### Android (Kotlin/Android Java)
* [Kotlin - Wikipedia](https://en.wikipedia.org/wiki/Kotlin_(programming_language))
* [Java - Wikipedia](https://en.wikipedia.org/wiki/Java_(programming_language))
* Learn
	* [Android Secure Coding Standard](https://www.securecoding.cert.org/confluence/display/android/Android+Secure+Coding+Standard)
* Reference
* Tools
	* [java-aes-crypto (Android class)](https://github.com/tozny/java-aes-crypto)
		* A simple Android class for encrypting & decrypting strings, aiming to avoid the classic mistakes that most such classes suffer from.
	* [smalisca](https://github.com/dorneanu/smalisca)
		* Static Code Analysis for Smali files 






----------
### Bash 
* [Bash - GNU](https://www.gnu.org/software/bash/)
* [Bash (Unix shell) - Wikipedia](https://en.wikipedia.org/wiki/Bash_(Unix_shell))
*  Learn
	* [BASH Programming - Introduction HOW-TO - tldp](http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html)
	* [Community Bash Style Guide](https://github.com/azet/community_bash_style_guide)
	* [The Bash Guide - A quality-driven guide through the shell's many features.](https://guide.bash.academy)
* Reference
	* [Bash Reference Manual](https://tiswww.case.edu/php/chet/bash/bashref.html)
	* [An A-Z Index of the Bash command line for Linux. - ss64](https://ss64.com/bash/)
	* [bash(1) - Linux man page](https://linux.die.net/man/1/bash)
* Tools
* Scripts



----------
### <a name="c">C/C++</a>
* [C (programming language) - Wikipedia](https://en.wikipedia.org/wiki/C_(programming_language))
* [C++ - Wikipedia](https://en.wikipedia.org/wiki/C%2B%2B)
* [C++ Homepage](https://isocpp.org/)
* Learn
	* [Stanford C 101](http://cslibrary.stanford.edu/101/EssentialC.pdf)
		* Stanford CS Education Library: A 45 page summary of the C language. Explains all the common features and techniques for the C language. The coverage is pretty quick, so it is most appropriate for someone with some programming background who needs to see how C works. Topics include variables, int types, floating point types, promotion, truncation, operators, control structures (if, while, for), functions, value parameters, reference parameters, structs, pointers, arrays, the pre-processor, and the standard C library functions. (revised 4/2003) 
		* [Homepage](http://cslibrary.stanford.edu/101/)
	* [Stanford C Pointers and Memory](http://cslibrary.stanford.edu/102/PointersAndMemory.pdf)
		* Stanford CS Education Library: a 31 page introduction to programming with pointers and memory in C, C++ and other languages. Explains how pointers and memory work and how to use them -- from the basic concepts through all the major programming techniques. Can be used as an introduction to pointers for someone with basic programming experience or as a quick review. Many advanced programming and debugging problems only make sense with a solid understanding of pointers and memory -- this document tries to provide that understanding. 
	* [Homepage](http://cslibrary.stanford.edu/102/)
	* [How to C in 2016](https://matt.sh/howto-c)
	* [A critique of "How to C in 2016" by Matt](https://github.com/Keith-S-Thompson/how-to-c-response)
	* [C Right-Left Rule](http://ieng9.ucsd.edu/~cs30x/rt_lt.rule.html)
* Reference
	* [C++ TutorialsPoint](https://www.tutorialspoint.com/cplusplus/)
	* [C Function Call Conventions and the Stack](https://archive.is/o2nD5)
	* [What a C programmer should know about memory](http://marek.vavrusa.com/c/memory/2015/02/20/memory/)
	* [Cplusplus.com](http://www.cplusplus.com/)
* Security
	* [SEI CERT C Coding Standard](https://www.securecoding.cert.org/confluence/display/seccode/SEI+CERT+Coding+Standards)
	* [SEI CERT C++ Coding Standard](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=637)
	* [Vulnerabilities in C : When integers go bad!](https://blog.feabhas.com/2014/10/vulnerabilities-in-c-when-integers-go-bad/)
* Tools


----------
### <a name="c#"></a>C#
* [Compiling C# Code at Runtime](https://www.codeproject.com/Tips/715891/Compiling-Csharp-Code-at-Runtime)




----------
### <a name="go">Go</a>
* [Go Programming Language](https://golang.org/)
* [GAS - Go AST Scanner](https://github.com/GoASTScanner/gas)
	* Inspects source code for security problems by scanning the Go AST.




----------
### Java
* [Java - Wikipedia](https://en.wikipedia.org/wiki/Java_(programming_language))
* Learn
	* [SEI CERT Oracle Coding Standard for Java](https://www.securecoding.cert.org/confluence/display/java/SEI+CERT+Oracle+Coding+Standard+for+Java)
	* [Protect Your Java Code - Through Obfuscators and Beyond](https://www.excelsior-usa.com/articles/java-obfuscators.html)
* Reference
	* [Custom Classloaders - The black art of java](http://blog.cyberborean.org/2007/07/04/custom-classloaders-the-black-art-of-java)
* Tools
	* [Serianalyzer](https://github.com/mbechler/serianalyzer)
		* A static byte code analyzer for Java deserialization gadget research
	


----------
### Lisp
* [Lisp - Wikipedia](https://en.wikipedia.org/wiki/Lisp_(programming_language))
* [Common Lisp](https://common-lisp.net/)
* [What makes lisp macros so special - StackOverflow](https://stackoverflow.com/questions/267862/what-makes-lisp-macros-so-special)
* Learn
	* [Lisp - TutorialsPoint](https://www.tutorialspoint.com/lisp/)
* Reference
* Tools
* Other
	[Lisp - Paul Graham](http://www.paulgraham.com/lisp.html)


----------
### Lua
* [Lua](https://www.lua.org/)
	* Official Homepage
* [Lua - Getting Started](https://www.lua.org/start.html)
* Learn
	* [Learn X in Y minutes, Where X=Lua](https://learnxinyminutes.com/docs/lua/)
	* [Lua code: security overview and practical approaches to static analysis](http://spw17.langsec.org/papers/costin-lua-static-analysis.pdf)
		* Abstract — Lua is an interpreted, cross-platform, embeddable, performant and low-footprint language. Lua’s popularity is on the rise in the last couple of years. Simple design and efficient usage of resources combined with its performance make it attractive or production web applications even to big organizations such as Wikipedia, CloudFlare and GitHub. In addition to this, Lua is one of the preferred choices for programming embedded and IoT devices. This context allows to assume a large and growing Lua codebase yet to be assessed. This growing Lua codebase could be potentially driving production servers and extremely large number of devices, some perhaps with mission-critical function for example in automotive or home-automation domains. However, there is a substantial and obvious lack of static analysis tools and vulnerable code corpora for Lua as compared to other increasingly popular languages, such as PHP, Python and JavaScript. Even the state-of-the-art commercial tools that support dozens of languages and technologies actually do not support Lua static code analysis. In this paper we present the first public Static Analysis for SecurityTesting (SAST) tool for Lua code that is currently focused on web vulnerabilities. We show its potential with good and promising preliminary results that we obtained on simple and intentionally vulnerable Lua code samples that we synthesized for our experiments. We also present and release our synthesized corpus of intentionally vulnerable Lua code, as well as the testing setups used in our experiments in form of virtual and completely reproducible environments. We hope our work can spark additional and renewed interest in this apparently overlooked area of language security and static analysis, as well as motivate community’s contribution to these open-source projects. The tool, the samples and the testing VM setups will be released and updated at http://lua.re and http://lua.rocks
* Tools
	* [REPL.lua](https://github.com/hoelzro/lua-repl)
		* a reusable Lua REPL written in Lua, and an alternative to /usr/bin/lua

--------------
### <a name="net".NET</a>
* [Book of the Runtime (BOTR) for the .NET Runtime](https://github.com/dotnet/coreclr/tree/master/Documentation/botr)
	* This contains a collection of articles about the non-trivial internals of the .NET Runtime. Its intended audience are people actually modifying the code or simply wishing to have a deep understanding of the runtime.
* [.NET serialiception](https://blog.scrt.ch/2016/05/12/net-serialiception/)
* [.Net The Managed Heap and Garbage Collection in the CLR](https://www.microsoftpressstore.com/articles/article.aspx?p=2224054)


-----------
### <a name="perl"Perl</a>
Perl
* [Perl Programming Language](https://www.perl.org/)
* [Perl - Wikipedia](https://en.wikipedia.org/wiki/Perl)
* Learn
	* [Perl & Linguistics](http://world.std.com/~swmcd/steven/perl/linguistics.html)
	* [SEI CERT Perl Coding Standard](https://www.securecoding.cert.org/confluence/display/perl/SEI+CERT+Perl+Coding+Standard)
	* [Introduction to Perl](http://www.perl.com/pub/2000/10/begperl1.html)
* Reference
	* [Perl Docs](https://perldoc.perl.org/)
* Tools



----------
### <a name="power">Powershell</a>
* **Learn**
* [Learn Windows PowerShell in a Month of Lunches, Third Edition - Book](https://www.manning.com/books/learn-windows-powershell-in-a-month-of-lunches-third-edition)
* [learning-powershell/ - github repo](https://github.com/PowerShell/PowerShell/tree/master/docs/learning-powershell)
* [Getting Started with Microsoft PowerShell - MS Virtual Academy](https://mva.microsoft.com/en-us/training-courses/getting-started-with-microsoft-powershell-8276?l=r54IrOWy_2304984382)
* [Weekend Scripter: The Best Ways to Learn PowerShell - technet](https://blogs.technet.microsoft.com/heyscriptingguy/2015/01/04/weekend-scripter-the-best-ways-to-learn-powershell/)
* [Powershell Tutorial Online](http://powershelltutorial.net/)
* [Dirty Powershell Webserver](http://obscuresecurity.blogspot.com/2014/05/dirty-powershell-webserver.html)
* [Useful Powershell scripts](https://github.com/clymb3r/PowerShell)


#### Reference

#### Tools
* [Pester](https://github.com/pester/Pester)
	* Pester provides a framework for running unit tests to execute and validate PowerShell commands from within PowerShell. Pester consists of a simple set of functions that expose a testing domain-specific language (DSL) for isolating, running, evaluating and reporting the results of PowerShell commands.

#### Other
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
### PHP
* [awesome-php](https://github.com/ziadoz/awesome-php)
	* A curated list of amazingly awesome PHP libraries, resources and shiny things.
* Documentation
	* [PHP Documentation](https://secure.php.net/docs.php)
* Educational
	* [PHP: a fractal of bad design](https://eev.ee/blog/2012/04/09/php-a-fractal-of-bad-design/)
	* [Reference — What does this symbol mean in PHP?](https://stackoverflow.com/questions/3737139/reference-what-does-this-symbol-mean-in-php)
* Tools
	* [Static analysis tools for PHP](https://github.com/exakat/php-static-analysis-tools)
	* A reviewed list of useful PHP static analysis tools











----------
### <a name="python">Python</a>
* [Python 3.6.2 documentation](https://docs.python.org/3/)
* [Python 2.7 documentation](https://docs.python.org/2.7/)
* Learn
	* [Learn Python the Hard Way](http://learnpythonthehardway.org/book/)
	* [Python For Beginners]()
		* Welcome! Are you completely new to programming? If not then we presume you will be looking for information about why and how to get started with Python. Fortunately an experienced programmer in any programming language (whatever it may be) can pick up Python very quickly. It's also easy for beginners to use and learn, so jump in!
	* [Obfuscating python](https://reverseengineering.stackexchange.com/questions/1943/what-are-the-techniques-and-tools-to-obfuscate-python-programs)
	* [Understanding Python Bytecode](http://security.coverity.com/blog/2014/Nov/understanding-python-bytecode.html)
	* [Reverse debugging for Python](https://morepypy.blogspot.com/2016/07/reverse-debugging-for-python.html?m=1)
	* [Python in a hacker's toolbox (PyConPl'15)](http://gynvael.coldwind.pl/?lang=en&id=572)
	* [Diving deep into Python – the not-so-obvious language parts](http://sebastianraschka.com/Articles/2014_deep_python.html)
	* [PEP: 551 Title: Security transparency in the Python runtime Version](https://github.com/python/peps/blob/cd795ec53c939e5b40808bb9d7a80c428c85dd52/pep-0551.rst)
	* [Build an API under 30 lines of code with Python and Flask](https://impythonist.wordpress.com/2015/07/12/build-an-api-under-30-lines-of-code-with-python-and-flask/)
	* [Diving deep into Python – the not-so-obvious language parts](http://sebastianraschka.com/Articles/2014_deep_python.html)
	* [Virtualenv](https://virtualenv.pypa.io/en/latest/userguide/)
		* [Python Static Analysis - Spencer J McIntyre - Derbycon7](https://www.youtube.com/watch?v=hWIiyOV4Wbk&index=45&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
			* Python is a popular language and that is true as well within the Security industry. This talk will outline how Python code can be statically analyzed using publicly available tools such as bandit. It will then take a more technical approach and outline how the abstract syntax tree (AST) can be processed and searched based on behavior clues to identify potential security issues. Many security tools search for vulnerabilities by analyzing the contents of static strings and examining their variable names. This alternative approach instead demonstrates how the AST can be analyzed to identify pieces of sensitive information such as encryption keys and passwords based on matching them with usage patterns. This will be a technical talk focused on using automated techniques to find security vulnerabilities in Python projects. The audience will leave with an understanding of these techniques and how they can be applied to the projects they are either developing themselves or using in their daily routines. This talk will end with a live demonstration of a forked version of the public Bandit scanner where these techniques have been implemented. 
	* [Python Static Analysis Spencer J McIntyre - Derbycon7](https://www.youtube.com/watch?v=hWIiyOV4Wbk&index=45&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
* Reference
	* [The Hitchhiker’s Guide to Python!](http://docs.python-guide.org/en/latest/)
* Libraries
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


----------
### <a name="ruby">Ruby</a>
* [Ruby Homepage](https://www.ruby-lang.org/en/)
* [Official Ruby Docs](https://ruby-doc.org/)
* [Ruby Gems](https://rubygems.org/)

#### Learn
* [Ruby - Tutorials Point](http://www.tutorialspoint.com/ruby/)
* [Ruby in 20 Minutes](https://www.ruby-lang.org/en/documentation/quickstart/)
* [rb2exe](https://github.com/loureirorg/rb2exe)
	* Ruby to EXE - Turn ruby scripts into portable executable apps


### Useful Libraries/programs/Frameworks
* [Shellpaste](https://github.com/andrew-morris/shellpaste)
	* Tiny snippet of code that pulls ASCII shellcode from pastebin and executes it. The purpose of this is to have a minimal amount of benign code so AV doesn't freak out, then it pulls down the evil stuff. People have been doing this kind of stuff for years so I take no credit for the concept. That being said, this code (or similar code) works surprisingly often during pentests when conventional malware fails. 
* [Ruby on Rails](http://rubyonrails.org/)



----------
### SQL
* [SafeSQL](https://github.com/stripe/safesql)
	* SafeSQL is a static analysis tool for Go that protects against SQL injections.
* [The Hitchhiker's Guide to SQL Injection prevention](https://phpdelusions.net/sql_injection)


----------
### UEFI Programming
* [Unified Extensible Firmware Interface Forum](http://www.uefi.org/)
* [Unified Extensible Firmware Interface](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface)



#### Learn

[Programming for EFI: Creating a "Hello, World" Program](http://www.rodsbooks.com/efi-programming/hello.html)

[UEFI Programming - First Steps](http://x86asm.net/articles/uefi-programming-first-steps/)

[Getting started with UEFI application development](https://lihashgnis.blogspot.com/2016/08/getting-started-with-uefi-application.html)

[Getting started with UEFI Development](https://lihashgnis.blogspot.com/2016/08/getting-started-with-uefi-application.html)


#### Reference

[UEFI - OSDev](http://wiki.osdev.org/UEFI)



#### Talks & Presentations
[Simple Made Easy](https://www.infoq.com/presentations/Simple-Made-Easy)
*  Rich Hickey emphasizes simplicity’s virtues over easiness’, showing that while many choose easiness they may end up with complexity, and the better way is to choose easiness along the simplicity path.




### Other

[A successful Git branching model](http://nvie.com/posts/a-successful-git-branching-model/)

[Mostly Adequate Guide](https://drboolean.gitbooks.io/mostly-adequate-guide/)
* This is a book on the functional paradigm in general. We'll use the world's most popular functional programming language: JavaScript. Some may feel this is a poor choice as it's against the grain of the current culture which, at the moment, feels predominately imperative.

[Reflective DLL Injection](http://www.harmonysecurity.com/files/HS-P005_ReflectiveDllInjection.pdf)

[Porting Windows Dynamic Link Libraries to Linux](https://github.com/taviso/loadlibrary)
