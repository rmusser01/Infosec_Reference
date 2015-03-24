Attacking Android Devices


TOC
Cull
Intro






[Hacking Your Way Up The Mobile Stack](http://vimeo.com/51270090)

[Secure Coding Standards - Android](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=111509535)

[csploit](http://www.csploit.org/docs.html)
* The most complete and advanced IT security professional toolkit on Android.(From their site)
* [Github](https://github.com/cSploit/android/tree/master/cSploit)

###Cull
[elsim - Elements Similarities](https://code.google.com/p/elsim/wiki/Similarity#Diffing_of_applications)
* Similarities/Differences of applications (aka rip-off indicator)
* This tool detects and reports: the identical methods; the similar methods; the deleted methods; the new methods; the skipped methods. 

[ARE - Virtual Machine for Android Reverse Engineering](https://redmine.honeynet.org/projects/are)

[APK Studio - Android Reverse Engineering](https://apkstudio.codeplex.com/)
* APK Studio is an IDE for decompiling/editing & then recompiling of android application binaries. Unlike initial release being Windows exclusive & also didn't support frameworks, this one is completely re-written using QT for cross-platform support. You can now have multiple frameworks installed & pick a particular one on a per project basis.


[Android Reverse Engineering Defenses](https://bluebox.com/wp-content/uploads/2013/05/AndroidREnDefenses201305.pdf)

[PatchDroid: Scalable Third-Party Security Patches for Android Devices](http://www.mulliner.org/collin/academic/publications/patchdroid.pdf)
* Android is currently the largest mobile platform with around 750 million devices worldwide. Unfortunately, more than 30% of all devices contain publicly known security vulnera- bilities and, in practice, cannot be updated through normal mechanisms since they are not longer supported by the man- ufacturer and mobile operator. This failure of traditional patch distribution systems has resulted in the creation of a large population of vulnerable mobile devices. In this paper, we present PatchDroid, a system to dis- tribute and apply third-party security patches for Android. Our system is designed for device-independent patch cre- ation, and uses in-memory patching techniques to address vulnerabilities in both native and managed code. We created a fully usable prototype of PatchDroid, including a number of patches for well-known vulnerabilities in Android devices. We evaluated our system on different devices from multiple manufacturers and show that we can effectively patch se- curity vulnerabilities on Android devices without impacting performance or usability. Therefore, PatchDroid represents a realistic path towards dramatically reducing the number of exploitable Android devices in the wild.

####Vulnerabilities
[List of Android Vulnerabilities](http://androidvulnerabilities.org/all)


####Exploits
[List of Android Exploits](https://github.com/droidsec/droidsec.github.io/wiki/Vuln-Exploit-List)



###Books

* Android hackers handbook


###Write-ups and Links

[ Inside the Android Play Service's magic OAuth flow ](http://sbktech.blogspot.com/2014/01/inside-android-play-services-magic.html)
* Owning google accounts on android devices

[Security enhancements in android through its versions](www.androidtamer.com)

 [Understanding the Android bytecode](https://mariokmk.github.io/programming/2015/03/06/learning-android-bytecode.html)
* Writeup on reversing/understanding Android Bytecode

[ClockLockingBeats](https://github.com/monk-dot/ClockLockingBeats)
* Repo for the DARPA CFT / Clock Locking Beats project. Exploring Android kernel and processor interactions to hide running threads


###Android Malware

[Rundown of Android Packers](http://www.fortiguard.com/uploads/general/Area41Public.pdf)

[APK File Infection on an Android System](https://www.youtube.com/watch?v=HZI1hCdqKjQ&amp;list=PLCDA5DF85AD6B4ABD)

[Manifesto](https://github.com/maldroid/manifesto)
* PoC framework for APK obfuscation, used to demonstrate some of the obfuscation examples from http://maldr0id.blogspot.com. It supports plugins (located in processing directory) that can do different obfuscation techniques. Main gist is that you run manifesto on the APK file and it produces an obfuscated APK file.
[Android Hacker Protection Level 0 - DEF CON 22 - Tim Strazzere and Jon Sawyer](https://www.youtube.com/watch?v=vLU92bNeIdI)
* Obfuscator here, packer there - the Android ecosystem is becoming a bit cramped with different protectors for developers to choose. With such limited resources online about attacking these protectors, what is a new reverse engineer to do? Have no fear, after drinking all the cheap wine two Android hackers have attacked all the protectors currently available for everyones enjoyment! Whether you've never reversed Android before or are a hardened veteran there will be something for you, along with all the glorious PoC tools and plugins for your little heart could ever desire.


###Security Analysis



###Device Analysis

[android-cluster-toolkit](https://github.com/jduck/android-cluster-toolkit)
* The Android Cluster Toolkit helps organize and manipulate a collection of Android devices. It was designed to work with a collection of devices connected to the same host machine, either directly or via one or more tiers of powered USB hubs. The tools within can operate on single devices, a selected subset, or all connected devices at once.


[privmap - android](https://github.com/jduck/privmap)
* A tool for enumerating the effective privileges of processes on an Android device. 


[canhazaxs](https://github.com/jduck/canhazaxs)
* A tool for enumerating the access to entries in the file system of an Android device. 


[Android Device Testing Framework(DTF)](https://github.com/jakev/dtf/tree/v1.0.3)
* The Android Device Testing Framework ("dtf") is a data collection and analysis framework to help individuals answer the question: "Where are the vulnerabilities on this mobile device?" Dtf provides a modular approach and built-in APIs that allows testers to quickly create scripts to interact with their Android devices. The default download of dtf comes with multiple modules that allow testers to obtain information from their Android device, process this information into databases, and then start searching for vulnerabilities (all without requiring root privileges). These modules help you focus on changes made to AOSP components such as applications, frameworks, system services, as well as lower-level components such as binaries, libraries, and device drivers. In addition, you'll be able to analyze new functionality implemented by the OEMs and other parties to find vulnerabilities.

[drozer](https://github.com/mwrlabs/drozer)
* drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.



##Application Analysis

[APK Studio - Android Reverse Engineering](https://apkstudio.codeplex.com/)
* APK Studio is an IDE for decompiling/editing & then recompiling of android application binaries. Unlike initial release being Windows exclusive & also didn't support frameworks, this one is completely re-written using QT for cross-platform support. You can now have multiple frameworks installed & pick a particular one on a per project basis

[Smali-CFGs](https://github.com/EugenioDelfa/Smali-CFGs)
* Smali Control-Flow-Graphs

[PID Cat](https://github.com/JakeWharton/pidcat)
* An update to Jeff Sharkey's excellent logcat color script which only shows log entries for processes from a specific application package. During application development you often want to only display log messages coming from your app. Unfortunately, because the process ID changes every time you deploy to the phone it becomes a challenge to grep for the right thing. This script solves that problem by filtering by application package. Supply the target package as the sole argument to the python script and enjoy a more convenient development process.

[AndBug - Scriptable Android Debugger](https://github.com/swdunlop/AndBug)
* AndBug is a debugger targeting the Android platform's Dalvik virtual machine intended for reverse engineers and developers. It uses the same interfaces as Android's Eclipse debugging plugin, the Java Debug Wire Protocol (JDWP) and Dalvik Debug Monitor (DDM) to permit users to hook Dalvik methods, examine process state, and even perform changes.

[android-lkms](https://github.com/strazzere/android-lkms)
* Android Loadable Kernel Modules - mostly used for reversing and debugging on controlled systems/emulators.

[Simplify - Simple Android Deobfuscator](https://github.com/CalebFenton/simplify)
* Simplify uses a virtual machine to understand what an app does. Then, it applies optimizations to create code that behaves identically, but is easier for a human to understand. Specifically, it takes Smali files as input and outputs a Dex file with (hopefully) identical semantics but less complicated structure.

###Dynamic Analysis
 
[APKinpsector](https://github.com/honeynet/apkinspector/)
* APKinspector is a powerful GUI tool for analysts to analyze the Android applications.

[Droidmap](https://code.google.com/p/droidbox/)
* DroidBox is developed to offer dynamic analysis of Android applications. The following information is shown in the results, generated when analysis is ended: 
Hashes for the analyzed package 
Incoming/outgoing network data 
File read and write operations 
Started services and loaded classes through DexClassLoader 
Information leaks via the network, file and SMS 
Circumvented permissions 
Cryptography operations performed using Android API 
Listing broadcast receivers 
Sent SMS and phone calls 
Additionally, two images are generated visualizing the behavior of the package. One showing the temporal order of the operations and the other one being a treemap that can be used to check similarity between analyzed packages. 

[ddi - Dynamic Dalvik Instrumentation Toolkit](https://github.com/crmulliner/ddi)
* Simple and easy to use toolkit for dynamic instrumentation of Dalvik code. Instrumentation is based on library injection and hooking method entry points (in-line hooking). The actual instrumentation code is written using the JNI interface. The DDI further supports loading additional dex classes into a process. This enables instrumentation code to be partially written in Java and thus simplifies interacting with the instrumented process and the Android framework.

[Hooker](https://github.com/AndroidHooker/hooker)
* Hooker is an opensource project for dynamic analyses of Android applications. This project provides various tools and applications that can be use to automaticaly intercept and modify any API calls made by a targeted application.  It leverages Android Substrate framework to intercept these calls and aggregate all their contextual information (parameters, returned values, ...). Collected information can either be stored in a distributed database (e.g. ElasticSearch) or in json files.  A set of python scripts is also provided to automatize the execution of an analysis to collect any API calls made by a set of applications.

[Android-SSL-TrustKiller](https://github.com/iSECPartners/Android-SSL-TrustKiller)
* Blackbox tool to bypass SSL certificate pinning for most applications running on a device.

[JustTrustMe - Cert Pinning using Xposed](https://github.com/fuzion24/justtrustme)
* An xposed module that disables SSL certificate checking. This is useful for auditing an appplication which does certificate pinning. You can read about the practice of cert pinning here(1). There also exists a nice framework built by @moxie to aid in pinning certs in your app: certificate pinning(2). 
[1](https://viaforensics.com/resources/reports/best-practices-ios-android-secure-mobile-development/41-certificate-pinning/)
[2](https://github.com/moxie0/AndroidPinning)



###Static Analysis

Androguard](https://code.google.com/p/androguard)
^ Androguard is mainly a tool written in python to play with: 
Dex/Odex (Dalvik virtual machine) (.dex) (disassemble, decompilation), 
APK (Android application) (.apk), 
Android's binary xml (.xml), 
Android Resources (.arsc). 
^ Androguard is available for Linux/OSX/Windows (python powered).
[Dexter](http://dexter.dexlabs.org/accounts/login/?next=/dashboard)
* Dexter is a static android application analysis tool.	
[Static Code Analysis of Major Android Web Browsers](http://opensecurity.in/research/security-analysis-of-android-browsers.html)

[Androwarn](https://github.com/maaaaz/androwarn)
* Androwarn is a tool whose main aim is to detect and warn the user about potential malicious behaviours developped by an Android application. The detection is performed with the static analysis of the application's Dalvik bytecode, represented as Smali. This analysis leads to the generation of a report, according to a technical detail level chosen from the user.

[Thresher](http://pl.cs.colorado.edu/projects/thresher/)
* Thresher is a static analysis tool that specializes in checking heap reachability properties. Its secret sauce is using a coarse up-front points-to analysis to focus a precise symbolic analysis on the alarms reported by the points-to analysis. 
* [Thresher: Precise Refutations for Heap Reachability](http://www.cs.colorado.edu/~sabl4745/papers/pldi13-thresher.pdf)

[lint - Static Analysis](https://developer.android.com/tools/help/lint.html)
* The Android lint tool is a static code analysis tool that checks your Android project source files for potential bugs and optimization improvements for correctness, security, performance, usability, accessibility, and internationalization.

[Flow Droid - Taint Analysis](http://sseblog.ec-spride.de/tools/flowdroid/)
* FlowDroid is a context-, flow-, field-, object-sensitive and lifecycle-aware static taint analysis tool for Android applications. U
* [Flow Droid Paper- FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps](http://www.bodden.de/pubs/far+14flowdroid.pdf)
* In this work we thus present F LOW D ROID , a novel and highly precise static taint analysis for Android applications. A precise model of Android’s lifecycle allows the analysis to properly handle callbacks invoked by the Android framework, while context, flow, field and object-sensitivity allows the analysis to reduce the number of false alarms. Novel on-demand algorithms help F LOW D ROID maintain high efficiency and precision at the same time

[dedex](https://github.com/mariokmk/dedex)
* Is a command line tool for disassembling Android DEX files.

[DexMac](https://github.com/mariokmk/DexMac)
* Is a native OSX application for disassembling Android DEX files.

[dexdissasembler](https://github.com/mariokmk/dexdisassembler)
* Is a GTK tool for disassembling Android DEX files.

[dex.Net](https://github.com/mariokmk/dex.net)
* A Mono/.NET library to parse Android DEX files. Its main purpose is to support utilities for disassembling and presenting the contents of DEX files.

[apk2gold](https://github.com/lxdvs/apk2gold)
* CLI tool for decompiling Android apps to Java. It does resources! It does Java! Its real easy! 

[Android Unpacker presented at Defcon 22: Android Hacker Protection Level 0](https://github.com/strazzere/android-unpacker)
* native-unpacker/ - Unpacker for APKProtect/Bangcle/LIAPP/Qihoo Packer that runs natively, no dependency on gdb
* hide-qemu/ - Small hacks for hiding the qemu/debuggers, specifically from APKProtect

[byte-code viewer](https://github.com/Konloch/bytecode-viewer)
* Bytecode Viewer is an Advanced Lightweight Java Bytecode Viewer, GUI Java Decompiler, GUI Bytecode Editor, GUI Smali, GUI Baksmali, GUI APK Editor, GUI Dex Editor, GUI APK Decompiler, GUI DEX Decompiler, GUI Procyon Java Decompiler, GUI Krakatau, GUI CFR Java Decompiler, GUI FernFlower Java Decompiler, GUI DEX2Jar, GUI Jar2DEX, GUI Jar-Jar, Hex Viewer, Code Searcher, Debugger and more. It's written completely in Java, and it's open sourced. It's currently being maintained and developed by Konloch.






###Online APK Analyzers

[Mobile Sandbox](http://mobilesandbox.org/)
* Provide an Android application file (apk-file) and the Mobile-Sandbox will analyze the file for any malicious behaviour.

[CopperDroid](http://copperdroid.isg.rhul.ac.uk/copperdroid/)
* Upload an .apk for static analysis

[Andrototal[(http://andrototal.org/)
* AndroTotal is a free service to scan suspicious APKs against multiple mobile antivirus apps.



###Attack Platforms

[drozer](https://github.com/mwrlabs/drozer)
* drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.

[Android Tamer](http://androidtamer.com/)
* Android Tamer is a one stop tool required to perform any kind of operations on Android devices / applications / network VM




###Securing Your Android Device

[Android (In)Security - Defcamp 2014](https://www.youtube.com/watch?v=2aeV1JXYvuQ&index=23&list=PLnwq8gv9MEKgSryzYIFhpmCcqnVzdUWfH)
* Good video on Android Security

[Android Forensics Class - Free](http://opensecuritytraining.info/AndroidForensics.html)
* This class serves as a foundation for mobile digital forensics, forensics of Android operating systems, and penetration testing of Android applications.


[Android Hardening Guide by the TOR developers](https://blog.torproject.org/blog/mission-impossible-hardening-android-security-and-privacy)
This blog post describes the installation and configuration of a prototype of a secure, full-featured, Android telecommunications device with full Tor support, individual application firewalling, true cell network baseband isolation, and optional ZRTP encrypted voice and video support. ZRTP does run over UDP which is not yet possible to send over Tor, but we are able to send SIP account login and call setup over Tor independently.
The SIP client we recommend also supports dialing normal telephone numbers if you have a SIP gateway that provides trunking service.
Aside from a handful of binary blobs to manage the device firmware and graphics acceleration, the entire system can be assembled (and recompiled) using only FOSS components. However, as an added bonus, we will describe how to handle the Google Play store as well, to mitigate the two infamous Google Play Backdoors.


[Android 4.0+ Hardening Guide/Checklist by University of Texas](https://wikis.utexas.edu/display/ISO/Google+Android+Hardening+Checklist)
	


####Applications

Firewall
	* [Android Firewall(Requires Root)](https://play.google.com/store/apps/details?id=com.jtschohl.androidfirewall&hl=en)
		
Xprivacy - The Ultimate Android Privacy Manager(Requires Root

	* [Github](https://github.com/M66B/XPrivacy)
	* [Google Play](https://play.google.com/store/apps/details?id=biz.bokhorst.xprivacy.installer&hl=en)

####Backups
[Titanium Backup](https://play.google.com/store/apps/details?id=com.keramidas.TitaniumBackup)
Personal favorite for making backups. Backups are stored locally or automatically to various cloud services.
[Helium Backup(Root Not Required)](https://play.google.com/store/apps/details?id=com.koushikdutta.backup&hl=en)
	* Backs up data locally or to various cloud services. Local client available for backups directly to PC.

###Encryption
Check the Encryption section of the overall guide for more information.





###Android Internals
[Dalvik opcodes](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html)

[Dalvik Bytecode Format docs](http://source.android.com/devices/tech/dalvik/dex-format.html)





###Interesting Android Papers

[Peeking into Your App without Actually Seeing It: UI State Inference and Novel Android Attacks](http://www.cs.ucr.edu/~zhiyunq/pub/sec14_android_activity_inference.pdf)
* Abstract: The security of smartphone GUI frameworks remains an important yet under-scrutinized topic. In this paper, we report that on the Android system (and likely other OSes), a weaker form of GUI confidentiality can be breached in the form of UI state (not the pixels) by a background app without requiring any permissions. Our finding leads to a class of attacks which we name UI state inference attack.

[List of important whitepapers](https://github.com/droidsec/droidsec.github.io/wiki/Android-Whitepapers)

[Execute This! Analyzing Unsafe and Malicious Dynamic Code Loading in Android Applications](https://anonymous-proxy servers.net/paper/android-remote-code-execution.pdf)
	
[Rage Against the Droid: Hindering Dynamic analysis of android malware](http://www.syssec-project.eu/m/page-media/3/petsas_rage_against_the_virtual_machine.pdf)

[APKLancet: Tumor Payload Diagnosis and Purification for Android Applications](http://loccs.sjtu.edu.cn/typecho/usr/uploads/2014/04/1396105336.pdf)

[DroidRay: A Security Evaluation System for CustomizedAndroid Firmwares](http://www.cs.cuhk.hk/~cslui/PUBLICATION/ASIACCS2014DROIDRAY.pdf)


[VirtualSwindle: An Automated Attack Against In-App Billing on Android](http://seclab.ccs.neu.edu/static/publications/asiaccs14virtualswindle.pdf)


[Evading Android Runtime Analysis via Sandbox Detection](https://www.andrew.cmu.edu/user/nicolasc/publications/VC-ASIACCS14.pdf)


[Enter Sandbox: Android Sandbox Comparison](http://www.mostconf.org/2014/papers/s3p1.pdf)

[Post-Mortem Memory Analysis of Cold-Booted Android Devices](http://www.homac.de/publications/Post-Mortem-Memory-Analysis-of-Cold-Booted-Android-Devices.pdf)

[Upgrading Your Android, Elevating My Malware: Privilege Escalation Through Mobile OS Updating](http://www.informatics.indiana.edu/xw7/papers/privilegescalationthroughandroidupdating.pdf)


(Exploring Android KitKat Runtime](http://www.haxpo.nl/wp-content/uploads/2014/02/D1T2-State-of-the-Art-Exploring-the-New-Android-KitKat-Runtime.pdf)

[Analyzing Inter-Application Communication in Android](https://www.eecs.berkeley.edu/~daw/papers/intents-mobisys11.pdf)

[Automatically Exploiting Potential Component Leaks in Android Applications](http://orbilu.uni.lu/bitstream/10993/16914/1/tr-pcLeaks.pdf)

[I know what leaked in your pocket: uncovering privacy leaks on Android Apps with Static Taint Analysis](http://arxiv.org/pdf/1404.7431v1.pdf)

[Bifocals: Analyzing WebView Vulnerabilities in Android Applications](http://www.eecs.berkeley.edu/~emc/papers/Chin-WISA-WebViews.pdf)

[Analyzing Android Browser Apps for file:// Vulnerabilities](http://arxiv.org/pdf/1404.4553v3.pdf)


[FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps](http://sseblog.ec-spride.de/wp-content/uploads/2013/05/pldi14submissionFlowdroid.pdf)

[Detecting privacy leaks in Android Apps](https://publications.uni.lu/bitstream/10993/16916/1/ESSoS-DS2014-Li.pdf)

[From Zygote to Morula: Fortifying Weakened ASLR on Android](http://www.cc.gatech.edu/~blee303/paper/morula.pdf)

[Apposcopy: Semantics-Based Detection of Android Malware through Static Analysis](http://www.cs.utexas.edu/~yufeng/papers/fse14.pdf)

[MAdFraud: Investigating Ad Fraud in Android Applications](http://www.cs.ucdavis.edu/~hchen/paper/mobisys2014.pdf)

[Why Eve and Mallory Love Android: An Analysis of Android SSL (In)Security](http://www2.dcsec.uni-hannover.de/files/android/p50-fahl.pdf)


[AsDroid: Detecting Stealthy Behaviors in Android Applications by User Interface and Program Behavior Contradiction](https://ece.uwaterloo.ca/~lintan/publications/asdroid-icse14.pdf)

[NativeGuard: Protecting Android Applications from Third-Party Native Libraries](http://www.cse.lehigh.edu/~gtan/paper/nativeguard.pdf)

[Into the Droid: Gaining Access to Android User Data - DEFCON](https://www.youtube.com/watch?v=MxhIo95VccI&amp;list=PLCDA5DF85AD6B4ABD)

[Android Packers](http://www.fortiguard.com/uploads/general/Area41Public.pdf)


[Xprivacy Android](https://github.com/M66B/XPrivacy#description)


[An Empirical Study of Cryptographic Misuse in Android Applications](https://www.cs.ucsb.edu/~chris/research/doc/ccs13_cryptolint.pdf)

[PowerSpy: Location Tracking using Mobile Device Power Analysis]http://arxiv.org/abs/1502.03182)

[Obfuscation in Android malware, and how to fight back](https://www.virusbtn.com/virusbulletin/archive/2014/07/vb201407-Android-obfuscation)





###Educational Material


[OWASP GoatDroid](https://www.owasp.org/index.php/Projects/OWASP_GoatDroid_Project)
* “OWASP GoatDroid is a fully functional and self-contained training environment for educating developers and testers on Android security. GoatDroid requires minimal dependencies and is ideal for both Android beginners as well as more advanced users. 
The project currently includes two applications: FourGoats, a location-based social network, and Herd Financial, a mobile banking application. There are also several feature that greatly simplify usage within a training environment or for absolute beginners who want a good introduction to working with the Android platform.”

[Insecure Bank v2](https://github.com/dineshshetty/Android-InsecureBankv2)
* This vulnerable Android application is named "InsecureBankv2" and is made for security enthusiasts and developers to learn the Android insecurities by testing this vulnerable application. Its back-end server component is written in python. The client component i.e. the Android InsecureBank.apk can be downloaded along with the source code. 
The list of vulnerabilities that are currently included in this release are: 
Insecure Logging mechanism
Vulnerable Activity Components
Content providers injection
Weak Broadcast Receiver permissions
Android Pasteboard vulnerability
Local Encryption issues
Android keyboard cache issues
Insecure Webview implementation
Insecure SDCard storage
Insecure HTTP connections
Weak Authorization mechanism
Parameter Manipulation
Weak Cryptography implementation
Hardcoded secrets
Username Enumeration issue
Developer Backdoors
Weak change password implementation
Weak Local storage issues
https://github.com/dineshshetty/Android-InsecureBankv2



###Reverse Engineering Android
[Android apk-tool](https://code.google.com/p/android-apktool/)
* It is a tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications; it makes possible to debug smali code step by step. Also it makes working with app easier because of project-like files structure and automation of some repetitive tasks like building apk, etc. 
[Reversing and Auditing Android’s Proprietary bits](http://www.slideshare.net/joshjdrake/reversing-and-auditing-androids-proprietary-bits)

[Smali](https://code.google.com/p/smali/)
* smali/baksmali is an assembler/disassembler for the dex format used by dalvik, Android's Java VM implementation. The syntax is loosely based on Jasmin's/dedexer's syntax, and supports the full functionality of the dex format (annotations, debug info, line info, etc.) 

[Dexter](http://dexter.dexlabs.org/accounts/login/?next=/dashboard)
* Dexter is a static android application analysis tool.

[APKinpsector](https://github.com/honeynet/apkinspector/)
APKinspector is a powerful GUI tool for analysts to analyze the Android applications. 

[Reversing Android Apps Slides](http://www.floyd.ch/download/Android_0sec.pdf)




###Other

 [Android-x86 Project - Run Android on Your PC](http://www.android-x86.org/)
* This is a project to port Android open source project to x86 platform, formerly known as "patch hosting for android x86 support". The original plan is to host different patches for android x86 support from open source community. A few months after we created the project, we found out that we could do much more than just hosting patches. So we decide to create our code base to provide support on different x86 platforms, and set up a git server to host it.


[Root Tools](https://github.com/Stericson/RootTools)	
* RootTools provides rooted developers a standardized set of tools for use in the development of rooted applications


