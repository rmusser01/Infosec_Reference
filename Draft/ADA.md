## Attacking Android Devices




### Table of Contents
* [Intro](#Intro)
* [Android Internals](#AInternals)
* [Securing Android](#SecAnd)
* [Android Apps](#Apps)
* [Vulnerabilities](#Vulns)
* [Exploits](#Exploits)
* [Device Analysis](#DAnalysis)
* [Application Analysis](#AppAnalysis)
	* Dynamic Analysis
	* Static Analysis
	* Online APK Analyzers
* [Online APK Analyzers](#OnlineAPK)
* [Attack Platforms](#APlatforms)
* [Android Malware](#Malware)
* [Reverse Engineering Android](#RE)
* [Interesting Papers](#Papers)
* [Write-ups](#Write)
* [Educational Materials](#Education)
* [Books](#Books)
* [Other](#Other)


#### Sort

* Redo formatting
https://github.com/sensepost/kwetza







https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/DEFCON-25-Slava-Makkaveev-and-Avi-Bashan-Unboxing-Android.pdf

https://github.com/ernw/AndroTickler
* [Dynamically Inject a Shared Library Into a Running Process on Android/ARM](https://www.evilsocket.net/2015/05/01/dynamically-inject-a-shared-library-into-a-running-process-on-androidarm/)
* [Android Native API Hooking With Library Injection and ELF Introspection](https://www.evilsocket.net/2015/05/04/android-native-api-hooking-with-library-injecto/)
* [ARM Inject](https://github.com/evilsocket/arminject)
	* An application to dynamically inject a shared object into a running process on ARM architectures and hook API calls.


* [apk-anal](https://github.com/mhelwig/apk-anal)
	* Android APK analyzer based on radare2 and others.
	
https://github.com/doridori/Android-Security-Reference
* [Android-Vulnerabilities-Overview](https://github.com/CHEF-KOCH/Android-Vulnerabilities-Overview)
	* Android Vulnerabilities Overview (AVO) is a databse of known security vulnerabilities in Android.

* [ATtention Spanned: Comprehensive Vulnerability Analysis of AT Commands Within the Android Ecosystem](https://atcommands.org/)

https://blog.gdssecurity.com/labs/2015/2/18/when-efbfbd-and-friends-come-knocking-observations-of-byte-a.html
* [Diggy](https://github.com/UltimateHackers/Diggy)
	* Diggy can extract endpoints/URLs from apk files. It saves the result into a txt file for further processing.
[Intercepting HTTPS traffic of Android Nougat Applications](https://serializethoughts.com/2016/09/10/905/)
* TL;DR To intercept network traffic for Android 7.0 targeted applications, introduce a res/xml/network_security_config.xml file.

http://nelenkov.blogspot.com

[Add Security Exception to APK](https://github.com/levyitay/AddSecurityExceptionAndroid)

[DonkeyGuard](https://github.com/CollegeDev/DonkeyGuard/)
* DonkeyGuard allows you a fine-grained tuning of access to your private data. It currently supports 41 restrictions which can be applied for every application. Specifically, it is a Privacy service provider which implements a set of modifications to the Android Framework to allow you to interact with applications which are trying to access your private data. 

[The Android boot process](https://thecyberfibre.com/android-boot-process/)

* [Untethered initroot (USENIX WOOT '17)](https://alephsecurity.com/2017/08/30/untethered-initroot/)


[Miroslav Stampar - Android: Practical Introduction into the (In)Security](https://www.youtube.com/watch?v=q1_rvrY4VHI)
* This presentation covers the user’s deadly sins of Android (In)Security, together with implied system security problems. Each topic could potentially introduce unrecoverable damage from security perspective. Both local and remote attacks are covered, along with accompanying practical demo of most interesting ones. 

#### End cull
 

### General

[Droidsec - Pretty much should be your first stop](http://www.droidsec.org/wiki/)

[Hacking Your Way Up The Mobile Stack](http://vimeo.com/51270090)
| **csploit** - "The most complete and advanced IT security professional toolkit on Android."(*From their site*) | http://www.csploit.org/docs.html -- [Github Link](https://github.com/cSploit/android/tree/master/cSploit)

[Mobile Application Penetration Testing Cheat Sheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)



### **<a name="AInternals">Android Internals</a>**
| Title     | Link |
| -------- | ------------------------ |
| **Dalvik opcodes** | http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html
| **Dalvik Bytecode Format docs** | http://source.android.com/devices/tech/dalvik/dex-format.html
| **The Android boot process from power on** | http://www.androidenea.com/2009/06/android-boot-process-from-power-on.html
| **Trustedt Execution Environments(and Android** | https://usmile.at/sites/default/files/androidsecuritysymposium/presentations/Ekberg_AndroidAndTrustedExecutionEnvironments.pdf





### **<a name="SecAnd">Securing Android</a>**
| Title     | Link |
| -------- | ------------------------ |
| **Android (In)Security** - Defcamp 2014 | https://www.youtube.com/watch?v=2aeV1JXYvuQ&index=23&list=PLnwq8gv9MEKgSryzYIFhpmCcqnVzdUWfH)
| **Android Forensics Class** - Free - This class serves as a foundation for mobile digital forensics, forensics of Android operating systems, and penetration testing of Android applications.| http://opensecuritytraining.info/AndroidForensics.html)
| **Android Hardening Guide by the TOR developers** - This blog post describes the installation and configuration of a prototype of a secure, full-featured, Android telecommunications device with full Tor support, individual application firewalling, true cell network baseband isolation, and optional ZRTP encrypted voice and video support. ZRTP does run over UDP which is not yet possible to send over Tor, but we are able to send SIP account login and call setup over Tor independently. The SIP client we recommend also supports dialing normal telephone numbers if you have a SIP gateway that provides trunking service. Aside from a handful of binary blobs to manage the device firmware and graphics acceleration, the entire system can be assembled (and recompiled) using only FOSS components. However, as an added bonus, we will describe how to handle the Google Play store as well, to mitigate the two infamous Google Play Backdoors.| https://blog.torproject.org/blog/mission-impossible-hardening-android-security-and-privacy)
| **Android 4.0+ Hardening Guide/Checklist by University of Texas** | https://wikis.utexas.edu/display/ISO/Google+Android+Hardening+Checklist)

[Mobile self-defense - Karsten Nohl](https://www.youtube.com/watch?v=GeCkO0fWWqc)

#### Applications
| Title     | Link |
| -------- | ------------------------ |
Firewall
	* [Android Firewall(Requires Root)](https://play.google.com/store/apps/details?id=com.jtschohl.androidfirewall&hl=en)
		
Xprivacy - The Ultimate Android Privacy Manager(Requires Root

	* [Github](https://github.com/M66B/XPrivacy)
	* [Google Play](https://play.google.com/store/apps/details?id=biz.bokhorst.xprivacy.installer&hl=en)

#### Backups
[Titanium Backup](https://play.google.com/store/apps/details?id=com.keramidas.TitaniumBackup)
Personal favorite for making backups. Backups are stored locally or automatically to various cloud services.
[Helium Backup(Root Not Required)](https://play.google.com/store/apps/details?id=com.koushikdutta.backup&hl=en)
	* Backs up data locally or to various cloud services. Local client available for backups directly to PC.

	[Stunneller](https://github.com/ultramancool/Stunneler)
* Android app for easy stunnel usage

### Encryption
Check the Encryption section of the overall guide for more information.

[Android Reverse Engineering Defenses](https://bluebox.com/wp-content/uploads/2013/05/AndroidREnDefenses201305.pdf)


#### **<a name="Vulns">Vulnerabilities</a>**
| Title     | Link |
| -------- | ------------------------ |
| **List of Android Vulnerabilities** |http://androidvulnerabilities.org/all

[AndroBugs Framework](https://github.com/AndroBugs/AndroBugs_Framework)
* AndroBugs Framework is an Android vulnerability analysis system that helps developers or hackers find potential security vulnerabilities in Android applications


#### **<a name="Exploits">Exploits</a>**
| Title     | Link |
| -------- | ------------------------ |
| **List of Android Exploits** | https://github.com/droidsec/droidsec.github.io/wiki/Vuln-Exploit-List)

[Android_Kernel_CVE_POC](https://github.com/ScottyBauer/Android_Kernel_CVE_POCs)

[plzdonthack.me](https://plzdonthack.me/)
* personal site of scotty bauer


### **<a name="DAnalysis">Device Analysis</a>**
| Title     | Link |
| -------- | ------------------------ |
| **android-cluster-toolkit** - The Android Cluster Toolkit helps organize and manipulate a collection of Android devices. It was designed to work with a collection of devices connected to the same host machine, either directly or via one or more tiers of powered USB hubs. The tools within can operate on single devices, a selected subset, or all connected devices at once. |https://github.com/jduck/android-cluster-toolkit
| **privmap - android** - A tool for enumerating the effective privileges of processes on an Android device.  |https://github.com/jduck/privmap
| **canhazaxs** - A tool for enumerating the access to entries in the file system of an Android device. |https://github.com/jduck/canhazaxs
| **Android Device Testing Framework(DTF)** - The Android Device Testing Framework ("dtf") is a data collection and analysis framework to help individuals answer the question: "Where are the vulnerabilities on this mobile device?" Dtf provides a modular approach and built-in APIs that allows testers to quickly create scripts to interact with their Android devices. The default download of dtf comes with multiple modules that allow testers to obtain information from their Android device, process this information into databases, and then start searching for vulnerabilities (all without requiring root privileges). These modules help you focus on changes made to AOSP components such as applications, frameworks, system services, as well as lower-level components such as binaries, libraries, and device drivers. In addition, you'll be able to analyze new functionality implemented by the OEMs and other parties to find vulnerabilities. |https://github.com/jakev/dtf/tree/v1.0.3
| **drozer** - drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.| https://github.com/mwrlabs/drozer



### **<a name="AppAnalysis">Application Analysis</a>**
| Title     | Link |
| -------- | ------------------------ |
| **APK Studio - Android Reverse Engineering** - APK Studio is an IDE for decompiling/editing & then recompiling of android application binaries. Unlike initial release being Windows exclusive & also didn't support frameworks, this one is completely re-written using QT for cross-platform support. You can now have multiple frameworks installed & pick a particular one on a per project basis|https://apkstudio.codeplex.com/
| **Smali-CFGs** - Smali Control-Flow-Graphs | https://github.com/EugenioDelfa/Smali-CFGs
| **PID Cat** - An update to Jeff Sharkey's excellent logcat color script which only shows log entries for processes from a specific application package. During application development you often want to only display log messages coming from your app. Unfortunately, because the process ID changes every time you deploy to the phone it becomes a challenge to grep for the right thing. This script solves that problem by filtering by application package. Supply the target package as the sole argument to the python script and enjoy a more convenient development process. | https://github.com/JakeWharton/pidcat
| **AndBug - Scriptable Android Debugger** - AndBug is a debugger targeting the Android platform's Dalvik virtual machine intended for reverse engineers and developers. It uses the same interfaces as Android's Eclipse debugging plugin, the Java Debug Wire Protocol (JDWP) and Dalvik Debug Monitor (DDM) to permit users to hook Dalvik methods, examine process state, and even perform changes.| https://github.com/swdunlop/AndBug
| **android-lkms** - Android Loadable Kernel Modules - mostly used for reversing and debugging on controlled systems/emulators.| https://github.com/strazzere/android-lkms
| **Simplify - Simple Android Deobfuscator** - Simplify uses a virtual machine to understand what an app does. Then, it applies optimizations to create code that behaves identically, but is easier for a human to understand. Specifically, it takes Smali files as input and outputs a Dex file with (hopefully) identical semantics but less complicated structure. | https://github.com/CalebFenton/simplify

[Cuckoo-Droid](https://github.com/i[danr1986/cuckoo-droid/blob/master/README.md)
* CuckooDroid is an extension of Cuckoo Sandbox the Open Source software for automating analysis of suspicious files, CuckooDroid brigs to cuckoo the capabilities of execution and analysis of android application.

[elsim - Elements Similarities](https://code.google.com/p/elsim/wiki/Similarity#Diffing_of_applications)
* Similarities/Differences of applications (aka rip-off indicator)
* This tool detects and reports: the identical methods; the similar methods; the deleted methods; the new methods; the skipped methods. 


### **<a name="Dynamic">Dynamic Analysis</a>**
 | Title     | Link |
| -------- | ------------------------ |
| **APKInspector** - APKinspector is a powerful GUI tool for analysts to analyze the Android applications.| https://github.com/honeynet/apkinspector/ 
| DroidBox** - DroidBox is developed to offer dynamic analysis of Android applications. Additionally, two images are generated visualizing the behavior of the package. One showing the temporal order of the operations and the other one being a treemap that can be used to check similarity between analyzed packages.| https://code.google.com/p/droidbox/)
 | **ddi - Dynamic Dalvik Instrumentation Toolkit** - Simple and easy to use toolkit for dynamic instrumentation of Dalvik code. Instrumentation is based on library injection and hooking method entry points (in-line hooking). The actual instrumentation code is written using the JNI interface. The DDI further supports loading additional dex classes into a process. This enables instrumentation code to be partially written in Java and thus simplifies interacting with the instrumented process and the Android framework.|https://github.com/crmulliner/ddi
| **Hooker** - Hooker is an opensource project for dynamic analyses of Android applications. This project provides various tools and applications that can be use to automaticaly intercept and modify any API calls made by a targeted application.  It leverages Android Substrate framework to intercept these calls and aggregate all their contextual information (parameters, returned values, ...). Collected information can either be stored in a distributed database (e.g. ElasticSearch) or in json files.  A set of python scripts is also provided to automatize the execution of an analysis to collect any API calls made by a set of applications.|https://github.com/AndroidHooker/hooker
| **Android-SSL-TrustKiller** - Blackbox tool to bypass SSL certificate pinning for most applications running on a device.|https://github.com/iSECPartners/Android-SSL-TrustKiller
| (**JustTrustMe - Cert Pinning using Xposed** - An xposed module that disables SSL certificate checking. This is useful for auditing an appplication which does certificate pinning. You can read about the practice of cert pinning here(1). There also exists a nice framework built by @moxie to aid in pinning certs in your app: certificate pinning|https://github.com/fuzion24/justtrustme
| **AndroidPinning** - AndroidPinning is a standalone Android library project that facilitates certificate pinning for SSL connections from Android apps, in order to minimize dependence on Certificate Authorities. | https://github.com/moxie0/AndroidPinning

[AndBug - A Scriptable Android Debugger](https://github.com/swdunlop/AndBug)
* AndBug is a debugger targeting the Android platform's Dalvik virtual machine intended for reverse engineers and developers. It uses the same interfaces as Android's Eclipse debugging plugin, the Java Debug Wire Protocol (JDWP) and Dalvik Debug Monitor (DDM) to permit users to hook Dalvik methods, examine process state, and even perform changes.

[android-gdb](https://github.com/darchons/android-gdb)
* GDB fork targetting Android/Fennec development

[How to avoid certificate pinning in the latest versions of Android](https://www.welivesecurity.com/2016/09/08/avoid-certificate-pinning-latest-versions-androidESET%20Blog:%20We%20Live%20Security)



### **<a name="Static">Static Analysis</a>**
 | Title     | Link |
| -------- | ------------------------ |
| **Disect Android APKs like a Pro - Static code analysis** |http://blog.dornea.nu/2014/07/07/disect-android-apks-like-a-pro-static-code-analysis/
| **Androguard** - Androguard is mainly a tool written in python to play with: Dex/Odex (Dalvik virtual machine) (.dex) (disassemble, decompilation), APK (Android application) (.apk), Android's binary xml (.xml), Android Resources (.arsc). Androguard is available for Linux/OSX/Windows (python powered).| https://code.google.com/p/androguard
| **Dexter** - Dexter is a static android application analysis tool. | http://dexter.dexlabs.org/accounts/login/?next=/dashboard)
| **Static Code Analysis of Major Android Web Browsers** |http://opensecurity.in/research/security-analysis-of-android-browsers.html
| **Androwarn** - Androwarn is a tool whose main aim is to detect and warn the user about potential malicious behaviours developped by an Android application. The detection is performed with the static analysis of the application's Dalvik bytecode, represented as Smali. This analysis leads to the generation of a report, according to a technical detail level chosen from the user.| https://github.com/maaaaz/androwarn
| **Thresher** - Thresher is a static analysis tool that specializes in checking heap reachability properties. Its secret sauce is using a coarse up-front points-to analysis to focus a precise symbolic analysis on the alarms reported by the points-to analysis.|http://pl.cs.colorado.edu/projects/thresher/)
| **[PAPER]Thresher: Precise Refutations for Heap Reachability** |http://www.cs.colorado.edu/~sabl4745/papers/pldi13-thresher.pdf
| **lint - Static Analysis** - The Android lint tool is a static code analysis tool that checks your Android project source files for potential bugs and optimization improvements for correctness, security, performance, usability, accessibility, and internationalization.|https://developer.android.com/tools/help/lint.html
| **Flow Droid - Taint Analysis** - FlowDroid is a context-, flow-, field-, object-sensitive and lifecycle-aware static taint analysis tool for Android applications. |http://sseblog.ec-spride.de/tools/flowdroid/
| **[PAPER]FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps** - In this work we thus present F LOW D ROID , a novel and highly precise static taint analysis for Android applications. A precise model of Android’s lifecycle allows the analysis to properly handle callbacks invoked by the Android framework, while context, flow, field and object-sensitivity allows the analysis to reduce the number of false alarms. Novel on-demand algorithms help F LOW D ROID maintain high efficiency and precision at the same time| http://www.bodden.de/pubs/far+14flowdroid.pdf
| **dedex** - Is a command line tool for disassembling Android DEX files.|https://github.com/mariokmk/dedex
| **DexMac** - Is a native OSX application for disassembling Android DEX files. | https://github.com/mariokmk/DexMac
| **dexdissasembler** - Is a GTK tool for disassembling Android DEX files. }https://github.com/mariokmk/dexdisassemble
| **dex.Net** - A Mono/.NET library to parse Android DEX files. Its main purpose is to support utilities for disassembling and presenting the contents of DEX files. | (https://github.com/mariokmk/dex.net
| **apk2gold** - CLI tool for decompiling Android apps to Java. It does resources! It does Java! Its real easy! | https://github.com/lxdvs/apk2gold
| **Android Unpacker presented at Defcon 22: Android Hacker Protection Level 0** |https://github.com/strazzere/android-unpacker
| **byte-code viewer** - Bytecode Viewer is an Advanced Lightweight Java Bytecode Viewer, GUI Java Decompiler, GUI Bytecode Editor, GUI Smali, GUI Baksmali, GUI APK Editor, GUI Dex Editor, GUI APK Decompiler, GUI DEX Decompiler, GUI Procyon Java Decompiler, GUI Krakatau, GUI CFR Java Decompiler, GUI FernFlower Java Decompiler, GUI DEX2Jar, GUI Jar2DEX, GUI Jar-Jar, Hex Viewer, Code Searcher, Debugger and more. It's written completely in Java, and it's open sourced. It's currently being maintained and developed by Konloch. | https://github.com/Konloch/bytecode-viewer

[Disect Android APKs like a Pro - Static code analysis](http://blog.dornea.nu/2014/07/07/disect-android-apks-like-a-pro-static-code-analysis/)





### **<a name="OnlineAPK">Online APK Analyzers</a>**
| Title     | Link |
| -------- | ------------------------ |
| **Mobile Sandbox** - Provide an Android application file (apk-file) and the Mobile-Sandbox will analyze the file for any malicious behaviour.|http://mobilesandbox.org/
| **CopperDroid** - Upload an .apk for static analysis|http://copperdroid.isg.rhul.ac.uk/copperdroid/
| **Andrototal** - AndroTotal is a free service to scan suspicious APKs against multiple mobile antivirus apps. | http://andrototal.org/



### **<a name="APlatforms">Attack Platforms</a>**
| Title     | Link |
| -------- | ------------------------ |
| **drozer** - drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.|https://github.com/mwrlabs/drozer
| **Android Tamer** - Android Tamer is a one stop tool required to perform any kind of operations on Android devices / applications / network VM| http://androidtamer.com/



### **<a name="Malware">Android Malware</a>**
| Title     | Link |
| -------- | ------------------------ |
| **Rundown of Android Packers** |http://www.fortiguard.com/uploads/general/Area41Public.pdf
| **APK File Infection on an Android System** | https://www.youtube.com/watch?v=HZI1hCdqKjQ&amp;list=PLCDA5DF85AD6B4ABD
| **Manifesto** - PoC framework for APK obfuscation, used to demonstrate some of the obfuscation examples from http://maldr0id.blogspot.com. It supports plugins (located in processing directory) that can do different obfuscation techniques. Main gist is that you run manifesto on the APK file and it produces an obfuscated APK file. |https://github.com/maldroid/manifesto
| **Android Hacker Protection Level 0** - DEF CON 22 - Tim Strazzere and Jon Sawyer - Obfuscator here, packer there - the Android ecosystem is becoming a bit cramped with different protectors for developers to choose. With such limited resources online about attacking these protectors, what is a new reverse engineer to do? Have no fear, after drinking all the cheap wine two Android hackers have attacked all the protectors currently available for everyones enjoyment! Whether you've never reversed Android before or are a hardened veteran there will be something for you, along with all the glorious PoC tools and plugins for your little heart could ever desire. | https://www.youtube.com/watch?v=vLU92bNeIdI

[kwetza](https://github.com/sensepost/kwetza)
* Python script to inject existing Android applications with a Meterpreter payload.



### **<a name="RE">Reverse Engineering Android</a>**
| Title     | Link |
| -------- | ------------------------ |
| **APK Studio - Android Reverse Engineering** - APK Studio is an IDE for decompiling/editing & then recompiling of android application binaries. Unlike initial release being Windows exclusive & also didn't support frameworks, this one is completely re-written using QT for cross-platform support. You can now have multiple frameworks installed & pick a particular one on a per project basis. |https://apkstudio.codeplex.com/
| **Android apk-tool** - It is a tool for reverse engineering 3rd party, closed, binary Android apps. It can decode resources to nearly original form and rebuild them after making some modifications; it makes possible to debug smali code step by step. Also it makes working with app easier because of project-like files structure and automation of some repetitive tasks like building apk, etc.  | https://code.google.com/p/android-apktool/
| **Reversing and Auditing Android’s Proprietary bits** |http://www.slideshare.net/joshjdrake/reversing-and-auditing-androids-proprietary-bits
| **Smali** - smali/baksmali is an assembler/disassembler for the dex format used by dalvik, Android's Java VM implementation. The syntax is loosely based on Jasmin's/dedexer's syntax, and supports the full functionality of the dex format (annotations, debug info, line info, etc.)  |https://code.google.com/p/smali/
| APKinpsector** - APKinspector is a powerful GUI tool for analysts to analyze the Android applications.| https://github.com/honeynet/apkinspector/
| **Dexter** - Dexter is a static android application analysis tool |http://dexter.dexlabs.org/accounts/login/?next=/dashboard
| **Reversing Android Apps Slides** | http://www.floyd.ch/download/Android_0sec.pdf

[AndroChef](http://androiddecompiler.com/)
* AndroChef Java Decompiler is Windows XP, Windows 2003, Windows Vista, Windows 7, Windows 8, 8.1 decompiler for Java that reconstructs the original source code from the compiled binary CLASS files. AndroChef Java Decompiler is able to decompile the most complex Java 6 applets and binaries, producing accurate source code.  AndroChef successfully decompiles obfuscated Java 6 and Java 7 .class and .jar files. Support Java language features like generics, enums and annotations. According to some studies, AndroChef Java Decompiler is able to decompile 98.04% of Java applications generated with traditional Java compilers- a very high recovery rate. It is simple but powerful tool that allows you to decompile Java and Dalvik bytecode (DEX, APK) into readable Java source. Easy to use.

[Instrumenting Android Applications with Frida](http://blog.mdsec.co.uk/2015/04/instrumenting-android-applications-with.html)

[smali_emulator](https://github.com/evilsocket/smali_emulator)
* This software will emulate a smali source file generated by apktool. 

[ARE - Virtual Machine for Android Reverse Engineering](https://redmine.honeynet.org/projects/are)

[Android Applications Reversing 101](https://www.evilsocket.net/2017/04/27/Android-Applications-Reversing-101)

[Android Crackmes](http://www.droidsec.org/wiki/#crack-mes)

[Hacking Android apps with FRIDA I](https://www.codemetrix.net/hacking-android-apps-with-frida-1/)

[Want to break some Android apps? - Android Crackmes- Carnal0wnage](http://carnal0wnage.attackresearch.com/2013/08/want-to-break-some-android-apps.html)

[Dex Education 201 - Anti-Emulation.pdf](https://github.com/strazzere/anti-emulator/blob/master/slides/Dex%20Education%20201%20-%20Anti-Emulation.pdf)

[List of Android Crackmes](https://forum.tuts4you.com/topic/33057-android-hackmes/)

[baredroid](https://github.com/ucsb-seclab/baredroid)
* BareDroid allows for bare-metal analysis on Android devices.
* [Paper](https://www.cs.ucsb.edu/%7Evigna/publications/2015_ACSAC_Baredroid.pdf)




### **<a name="Papers">Interesting Android Papers</a>**
| Title     | Link |
| -------- | ------------------------ |
| **List of important whitepapers** | https://github.com/droidsec/droidsec.github.io/wiki/Android-Whitepapers
| **Peeking into Your App without Actually Seeing It: UI State Inference and Novel Android Attacks** | http://www.cs.ucr.edu/~zhiyunq/pub/sec14_android_activity_inference.pdf|
| **Execute This! Analyzing Unsafe and Malicious Dynamic Code Loading in Android Applications** |https://anonymous-proxy-servers.net/paper/android-remote-code-execution.pdf
| **Rage Against the Droid: Hindering Dynamic analysis of android malware** | http://www.syssec-project.eu/m/page-media/3/petsas_rage_against_the_virtual_machine.pdf
| **APKLancet: Tumor Payload Diagnosis and Purification for Android Applications** | http://loccs.sjtu.edu.cn/typecho/usr/uploads/2014/04/1396105336.pdf
| **DroidRay: A Security Evaluation System for CustomizedAndroid Firmwares** | http://www.cs.cuhk.hk/~cslui/PUBLICATION/ASIACCS2014DROIDRAY.pdf
| **VirtualSwindle: An Automated Attack Against In-App Billing on Android** | http://seclab.ccs.neu.edu/static/publications/asiaccs14virtualswindle.pdf
| **Evading Android Runtime Analysis via Sandbox Detection** | https://www.andrew.cmu.edu/user/nicolasc/publications/VC-ASIACCS14.pdf
| **Enter Sandbox: Android Sandbox Comparison** | http://www.mostconf.org/2014/papers/s3p1.pdf
| **Post-Mortem Memory Analysis of Cold-Booted Android Devices** | http://www.homac.de/publications/Post-Mortem-Memory-Analysis-of-Cold-Booted-Android-Devices.pdf
| **Upgrading Your Android, Elevating My Malware: Privilege Escalation Through Mobile OS Updating** | http://www.informatics.indiana.edu/xw7/papers/privilegescalationthroughandroidupdating.pdf
| **Exploring Android KitKat Runtime** | http://www.haxpo.nl/wp-content/uploads/2014/02/D1T2-State-of-the-Art-Exploring-the-New-Android-KitKat-Runtime.pdf
| **Analyzing Inter-Application Communication in Android** | https://www.eecs.berkeley.edu/~daw/papers/intents-mobisys11.pdf
| **Automatically Exploiting Potential Component Leaks in Android Applications** | http://orbilu.uni.lu/bitstream/10993/16914/1/tr-pcLeaks.pdf
| **I know what leaked in your pocket: uncovering privacy leaks on Android Apps with Static Taint Analysis** | http://arxiv.org/pdf/1404.7431v1.pdf
| **Bifocals: Analyzing WebView Vulnerabilities in Android Applications** | http://www.eecs.berkeley.edu/~emc/papers/Chin-WISA-WebViews.pdf
| **Analyzing Android Browser Apps for file:// Vulnerabilities** | http://arxiv.org/pdf/1404.4553v3.pdf
| **FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps** | http://sseblog.ec-spride.de/wp-content/uploads/2013/05/pldi14submissionFlowdroid.pdf
| **Detecting privacy leaks in Android Apps** | https://publications.uni.lu/bitstream/10993/16916/1/ESSoS-DS2014-Li.pdf
| **From Zygote to Morula: Fortifying Weakened ASLR on Android** | http://www.cc.gatech.edu/~blee303/paper/morula.pdf
| **Apposcopy: Semantics-Based Detection of Android Malware through Static Analysis](http://www.cs.utexas.edu/~yufeng/papers/fse14.pdf
| **MAdFraud: Investigating Ad Fraud in Android Applications](http://www.cs.ucdavis.edu/~hchen/paper/mobisys2014.pdf
| **Why Eve and Mallory Love Android: An Analysis of Android SSL (In)Security** | http://www2.dcsec.uni-hannover.de/files/android/p50-fahl.pdf
| **AsDroid: Detecting Stealthy Behaviors in Android Applications by User Interface and Program Behavior Contradiction** | https://ece.uwaterloo.ca/~lintan/publications/asdroid-icse14.pdf
| **NativeGuard: Protecting Android Applications from Third-Party Native Libraries**|http://www.cse.lehigh.edu/~gtan/paper/nativeguard.pdf
| **Into the Droid: Gaining Access to Android User Data** - DEFCON |https://www.youtube.com/watch?v=MxhIo95VccI&amp;list=PLCDA5DF85AD6B4ABD)
| **Android Packers** | http://www.fortiguard.com/uploads/general/Area41Public.pdf
| **Xprivacy Android** | https://github.com/M66B/XPrivacy#description
| **An Empirical Study of Cryptographic Misuse in Android Applications** | https://www.cs.ucsb.edu/~chris/research/doc/ccs13_cryptolint.pdf
| **PowerSpy: Location Tracking using Mobile Device Power Analysis** | http://arxiv.org/abs/1502.03182
| **Obfuscation in Android malware, and how to fight back** | https://www.virusbtn.com/virusbulletin/archive/2014/07/vb201407-Android-obfuscation)

[PatchDroid: Scalable Third-Party Security Patches for Android Devices](http://www.mulliner.org/collin/academic/publications/patchdroid.pdf)
* Android is currently the largest mobile platform with around 750 million devices worldwide. Unfortunately, more than 30% of all devices contain publicly known security vulnera- bilities and, in practice, cannot be updated through normal mechanisms since they are not longer supported by the man- ufacturer and mobile operator. This failure of traditional patch distribution systems has resulted in the creation of a large population of vulnerable mobile devices. In this paper, we present PatchDroid, a system to dis- tribute and apply third-party security patches for Android. Our system is designed for device-independent patch cre- ation, and uses in-memory patching techniques to address vulnerabilities in both native and managed code. We created a fully usable prototype of PatchDroid, including a number of patches for well-known vulnerabilities in Android devices. We evaluated our system on different devices from multiple manufacturers and show that we can effectively patch se- curity vulnerabilities on Android devices without impacting performance or usability. Therefore, PatchDroid represents a realistic path towards dramatically reducing the number of exploitable Android devices in the wild.

[Dissecting the Android Bouncer](https://www.duosecurity.com/blog/duo-tech-talks-dissecting-the-android-bouncer)



### **<a name="Education">Educational Material</a>**
| Title     | Link |
| -------- | ------------------------ |
| **OWASP GoatDroid** - “OWASP GoatDroid is a fully functional and self-contained training environment for educating developers and testers on Android security. GoatDroid requires minimal dependencies and is ideal for both Android beginners as well as more advanced users. The project currently includes two applications: FourGoats, a location-based social network, and Herd Financial, a mobile banking application. There are also several feature that greatly simplify usage within a training environment or for absolute beginners who want a good introduction to working with the Android platform.” |https://www.owasp.org/index.php/Projects/OWASP_GoatDroid_Project
| **Insecure Bank v2** - This vulnerable Android application is named "InsecureBankv2" and is made for security enthusiasts and developers to learn the Android insecurities by testing this vulnerable application. Its back-end server component is written in python. The client component i.e. the Android InsecureBank.apk can be downloaded along with the source code.  |https://github.com/dineshshetty/Android-InsecureBankv2


[Put a Sock(et) in it: Understanding and Attacking Sockets on Android](http://www.irongeek.com/i.php?page=videos/bsidesnashville2016/r04-put-a-socket-in-it-understanding-and-attacking-sockets-on-android-jake-valletta)
* You're probably wondering how someone could possibly fill a 45 minute slot talking about the security implications of sockets (after all, there are only TCP and UDP sockets, right?). In reality, there are several unique types of sockets used by an Android device. These range from network sockets (the ones we are all familiar with), to local sockets, and even kernel-level sockets. When used improperly, these sockets can have devastating effects on the overall security of a device. In this talk, I'll discuss several types of Linux-based sockets found on Android devices and how these sockets have historically been used to compromise devices. I'll also provide the tools and techniques necessary to enumerate and interact with these sockets on your own device.

[Android apps in sheep's clothing](http://www.modzero.ch/modlog/archives/2015/04/01/android_apps_in_sheeps_clothing/index.html)
* We identified a security weakness in Android's approach of handling UI elements, circumventing parts of Android's sandboxing approach. While this attack is simple from a technical point of view, the impact of exploiting such a vulnerability is significant. It affects Android based devices as well as Blackberry mobile devices running the Android runtime environment.





### **<a name="Write">Write-ups</a>**
 | Title     | Link |
| -------- | ------------------------ |
| **Inside the Android Play Service's magic OAuth flow** - Owning google accounts on android devices | http://sbktech.blogspot.com/2014/01/inside-android-play-services-magic.html
| **Security enhancements in android through its versions** | www.androidtamer.com
| **Understanding the Android bytecode** - Writeup on reversing/understanding Android Bytecode| https://mariokmk.github.io/programming/2015/03/06/learning-android-bytecode.html
| **ClockLockingBeats** - Repo for the DARPA CFT / Clock Locking Beats project. Exploring Android kernel and processor interactions to hide running threads |https://github.com/monk-dot/ClockLockingBeats

[Hacking Android phone. How deep the rabbit hole goes.](https://hackernoon.com/hacking-android-phone-how-deep-the-rabbit-hole-goes-18b62ad65727#.txib8od0m)

[Android Bytecode Obfuscation - Patrick Schulz 2012](http://dexlabs.org/blog/bytecode-obfuscation)
[Android Pattern Lock Cracker](https://github.com/sch3m4/androidpatternlock) 
*  A little Python tool to crack the Pattern Lock on Android devices


### **<a name="Books">Books</a>**
 | Title     | 
| -------- |
| Android Hackers Handbook
| Android System Security Internals


### **<a name="Other">Other</a>**
 | Title     | Link |
| -------- | ------------------------ |
 | **Android-x86 Project - Run Android on Your PC** - This is a project to port Android open source project to x86 platform, formerly known as "patch hosting for android x86 support". The original plan is to host different patches for android x86 support from open source community. A few months after we created the project, we found out that we could do much more than just hosting patches. So we decide to create our code base to provide support on different x86 platforms, and set up a git server to host it.|http://www.android-x86.org/
| **Root Tools** - RootTools provides rooted developers a standardized set of tools for use in the development of rooted applications | https://github.com/Stericson/RootTools


[Protect Your Java Code — Through Obfuscators And Beyond](https://www.excelsior-usa.com/articles/java-obfuscators.html)
[fdroidcl](https://github.com/mvdan/fdroidcl#advantages-over-the-android-clientx)
* F-Droid desktop client.


[Heimdall](https://github.com/Benjamin-Dobell/Heimdall)
* Heimdall is a cross-platform open-source tool suite used to flash firmware (aka ROMs) onto Samsung Galaxy S devices.


[hbootdbg](https://github.com/sogeti-esec-lab/hbootdbg/)
* Debugger for HTC phones bootloader (HBOOT). 

[playdrone](https://github.com/nviennot/playdrone)
* Google Play Crawler


| Title     | Link |
| -------- | ------------------------ |