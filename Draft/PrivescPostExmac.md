# macOS Privilege Escalation & Post-Exploitation
-----------------------------------------------------------------------------------------------------------------------------------
## Table of Contents
- [General Stuff](#general)
- [AppleScript, Objective-C & Swift](#maclangs)
- [macOS Code Injection](#mict)
- [macOS Post Exploitation](#osxpost)
	- [Execution](#osxexecute)
	- [Persistence](#osxpersist)
	- [Privilege Escalation](#osxprivesc)
	- [Defense Evasion](#osxdefev)
	- [Credential Access](#osxcredac)
	- [Discovery](#osxdisco)
	- [Lateral Movement](#osxlat)
	- [Collection](#osxcollect)
	- [macOS Defense Evasion](#macdefev)
		- [Application Whitelistng](#whitelist)
		- [Endpoint Security Framework](#esf)
		- [Gatekeeper](#gatekeeper)
		- [System Integrity Protection](#sip)
		- [XProtect](#xprotect)
		- 
- [macOS Specific Technologies](#mactech)
	- [Code Signing](#osxsign)
	- [Endpoint Security Framework](#osxesf)
	- [GateKeeper](#osxgk)
	- [System Integrity Protection](#osxsip)
	- [Transparency, Consent, and Control](#osxtcc)
	- [XProtect](#osxxprotect)
	- 
-----------------------------------------------------------------------------------------------------------------------------------






--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
## Begin Unsorted Section

macOS sort
	https://github.com/cedowens/Spotlight-Enum-Kit
	https://themittenmac.com/the-esf-playground/
	https://www.microsoft.com/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/
	https://developer.apple.com/videos/play/wwdc2019/701/
	https://www.slideshare.net/JustinBui5/red-teaming-macos-environments-with-hermes-the-swift-messenger
	https://objective-see.com/blog/blog_0x63.html
	https://objective-see.com/blog/blog_0x64.html
	https://objective-see.com/blog/blog_0x65.html
	https://cedowens.medium.com/spotlighting-your-tcc-access-permissions-ec6628d7a876
	https://book.hacktricks.xyz/macos/macos-security-and-privilege-escalation
	https://theevilbit.github.io/posts/gatekeeper_not_a_bypass/
	https://ssd-disclosure.com/ssd-advisory-macos-finder-rce/
	https://cedowens.medium.com/interesting-macos-chrome-browser-files-4fd162d2561f
	https://github.com/Homebrew/brew/blob/bf7fe45e8998e56e6690347a0192c454b8cb203b/Library/Homebrew/cask/quarantine.rb
	https://medium.com/tenable-techblog/attacking-unattended-installs-on-macos-dfc1f57984e0
	https://github.com/KhaosT/SimpleVM
	https://m1racles.com/
	* [Disclosure: Another macOS privacy protections bypass - Jeff Johnson(2020)](https://lapcatsoftware.com/articles/disclosure2.html)
	https://labs.sentinelone.com/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/
	https://github.com/create-dmg/create-dmg
	https://www.cdfinder.de/guide/blog/apple_hell.html
	https://github.com/0xmachos/CVE-2019-8561
	https://www.youtube.com/watch?v=5nOxznrOK48
	https://conference.hitb.org/hitbsecconf2021ams/materials/D1T1%20-%20MacOS%20Local%20Security%20-%20Escaping%20the%20Sandbox%20and%20Bypassing%20TCC%20-%20Thijs%20Alkemade%20&%20Daan%20Keuper.pdf
	https://posts.specterops.io/introducing-mystikal-4fbd2f7ae520
	https://github.com/D00MFist/Mystikal
	https://www.kaspersky.com/blog/is-txt-file-safe/39256/
	https://www.youtube.com/watch?v=Xvg3Ve8a_BM
	https://theevilbit.github.io/beyond/beyond_0019/
	https://developer.apple.com/documentation/virtualization
	https://objective-see.com/blog/blog_0x5F.html
	https://github.com/ZecOps/public/blob/master/CVE-2021-30714/obts4_keynote.pdf
	https://labs.f-secure.com/blog/analysis-of-cve-2021-1810-gatekeeper-bypass/
	https://www.sentinelone.com/labs/defeating-macos-malware-anti-analysis-tricks-with-radare2/
	https://github.com/wangtielei/Slides
	https://github.com/antman1p/JXA_Proc_Tree
	https://theevilbit.github.io/beyond/beyond_0020/
	https://github.com/cedowens/Add-To-TCC-DB
	https://github.com/antman1p/PrintTCCdb
	https://wojciechregula.blog/post/learn-xpc-exploitation-part-1-broken-cryptography/
	https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/
	https://wojciechregula.blog/post/learn-xpc-exploitation-part-3-code-injections/
	https://fliphtml5.com/mnts/yttd/basic
	https://www.synacktiv.com/publications/macos-xpc-exploitation-sandbox-share-case-study.html
	https://github.com/badd1e/Proof-of-Concept/tree/main/prl_not0day
	https://web.archive.org/web/20210430174716/https://zerodayengineering.com/blog/dont-share-your-home.html
	https://research.nccgroup.com/2020/05/28/exploring-macos-calendar-alerts-part-2-exfiltrating-data-cve-2020-3882/
	https://wojciechregula.blog/post/when-vulnerable-library-is-actually-your-physical-book/
	https://blog.chichou.me/2021/01/16/see-no-eval-runtime-code-execution-objc/
	https://github.com/kendfinger/MacHack#profiles
	https://github.com/its-a-feature/loginItemManipulator
	https://github.com/its-a-feature/macOSCameraCapture
	https://securityboulevard.com/2021/04/making-macos-universal-apps-in-swift-with-universal-golang-static-libraries/
	https://holdmybeersecurity.com/2020/01/03/poc-mail-app-the-boomerang-of-reverse-shells-on-macos/
	https://labs.f-secure.com/blog/jamfing-for-joy-attacking-macos-in-enterprise
	https://www.trendmicro.com/en_us/research/20/h/xcsset-mac-malware--infects-xcode-projects--uses-0-days.html
	https://theevilbit.github.io/beyond/beyond_0001/
	https://theevilbit.github.io/beyond/beyond_0002/
	https://theevilbit.github.io/beyond/beyond_0003/
	https://www.youtube.com/playlist?list=PLliknDIoYszujuE2j5YRJ3vLce39UlhSf
	https://github.com/hrbrmstr/extractor
	https://gist.github.com/monoxgas/c0b0f086fc7aa057a8256b42c66761c8
	https://github.com/impost0r/Rotten-Apples
	https://github.com/create-dmg/create-dmg
	https://developer.apple.com/documentation/hypervisor
	https://github.com/cedowens/JXA-RemoveQuarantine
	https://github.com/cedowens/Add-To-TCC-DB
	https://lapcatsoftware.com/articles/sandbox-escape.html
	https://www.mdsec.co.uk/2021/01/macos-post-exploitation-shenanigans-with-vscode-extensions/
Slides
	https://themittenmac.com/publication_docs/OBTS_v1_Bradley.pdf
	https://www.slideshare.net/CodyThomas6/bashing-brittle-indicators-red-teaming-macos-without-bash-or-python
	https://www.slideshare.net/CodyThomas6/ready-player-2-multiplayer-red-teaming-against-macos
	https://www.slideshare.net/CodyThomas6/walking-the-bifrost-an-operators-guide-to-heimdal-kerberos-on-macos
	https://www.slideshare.net/CsabaFitzl/20-ways-to-bypass-your-mac-os-privacy-mechanisms
Talks
	https://www.youtube.com/watch?v=5nOxznrOK48&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=5
		https://themittenmac.com/publication_docs/OBTS_v2_Bradley.pdf
	https://github.com/opensource-apple/dyld/tree/master/unit-tests/test-cases/bundle-memory-load
	https://papers.put.as/
	https://www.youtube.com/watch?v=UAkC-brF6iQ
	https://github.com/xorrior/macOSTools
	https://lockboxx.blogspot.com/2020/06/macos-post-summary.html
	https://github.com/LinusHenze/Unrootless-Kext
	https://theevilbit.github.io/posts/vmware_fusion_11_guest_vm_rce_cve-2019-5514/
	https://blog.confiant.com/new-macos-bundlore-loader-analysis-ca16d19c058c
	https://www.mdsec.co.uk/2019/12/macos-filename-homoglyphs-revisited/
	https://www.fireeye.com/blog/threat-research/2019/04/triton-actor-ttp-profile-custom-attack-tools-detections.html
		* https://twitter.com/Agarri_FR/status/1130736756431761408
		* CVE-2019-5514 is a cool RCE in VMware Fusion 11, abusing an unauthenticated REST endpoint running on localhost
	https://objective-see.com/blog/blog_0x56.html
	* [Offensive MacOS](https://github.com/its-a-feature/offensive_macos)
		* This is a collection of macOS specific tooling, blogs, and other related information for offensive macOS assessments
	Stuff
		* [XcodeGhost - Wikipedia](https://en.wikipedia.org/wiki/XcodeGhost)
		* [XCSSET Mac Malware: Infects Xcode Projects, Performs UXSS Attack on Safari, Other Browsers, Leverages Zero-day Exploits - Trend Micro(2020)](https://blog.trendmicro.com/trendlabs-security-intelligence/xcsset-mac-malware-infects-xcode-projects-performs-uxss-attack-on-safari-other-browsers-leverages-zero-day-exploits/)
	3rd Party
		DruvaSync
			https://medium.com/tenable-techblog/getting-root-on-macos-via-3rd-party-backup-software-b804085f0c9
	APFS
		https://www.irongeek.com/i.php?page=videos/bsidescharm2018/track-2-01-getting-saucy-with-apfs-the-state-of-apples-new-file-system-sarah-edwards
	Carbon
	Cred Attacks
		https://gist.github.com/teddziuba/3ff08bdda120d1f7822f3baf52e606c2
		* **Articles**
			https://www.sprocketsecurity.com/blog/how-to-hijack-slack-sessions-on-macos
		* **Tools**
			* [KeytabParser](https://github.com/its-a-feature/KeytabParser)
				* Python script to parse macOS's Heimdal Keytab file (typically /etc/krb5.keytab)
	Code Injection
		https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/
		https://blog.xpnsec.com/macos-injection-via-third-party-frameworks/
		https://knight.sc/malware/2019/03/15/code-injection-on-macos.html
		https://www.youtube.com/watch?v=1LSvGZCoAVc&list=PLLvAhAn5sGfiZKg9GTUzljNmuRupA8igX&index=6
		* [insert_dylib](https://github.com/Tyilo/insert_dylib)
			* Command line utility for inserting a dylib load command into a Mach-O binary
	Collection
		* **Articles/Blogposts/Writeups**
		* **Tools**
	Defense Evasion
		* []()
		* [Exploiting XPC in AntiVirus - Csaba Fitz(NullCon2021)](https://www.slideshare.net/CsabaFitzl/exploiting-xpc-in-antivirus)
			* In this talk we will publish our research we conducted on 28 different AntiVirus products on macOS through 2020. Our focus was to assess the XPC services these products expose and if they presented any security vulnerabilities. We will talk about the typical issues, and demonstrate plenty of vulnerabilities, which typically led to full control of the given product or local privilege escalation on the system. At the end we will give advice to developers how to write secure XPC services.
		* [Mojave’s security “hardening” 

User protections could be bypassed - Phil Stokes(2018)]
			* Apple Events are blocked depending on origination, could be bypassed using SSH.
	Disco
		* **Articles/Blogposts/Writeups**
		* [Always Watching: macOS Eavesdropping – Justin Bui (SO-CON 2020)](https://www.youtube.com/watch?v=hAiKh2o2_Zs&list=PLJK0fZNGiFU-2vFpjnt96j_VSuQVTkAnO&index=6)
			* As macOS becomes more prevalent in modern enterprise environments, red teamers have had to adapt their tradecraft. Input monitoring and screenshots can provide a wealth of information for attacker on any operating system. In this talk, we’ll discuss macOS internals and dive into the various API calls necessary for keylogging, clipboard monitoring, and screenshots. The accompanying source code will be released to GitHub!
		* **Tools**
	DMG
		http://newosxbook.com/DMG.html
	DylibHijack
		https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x
		https://malwareunicorn.org/workshops/macos_dylib_injection.html#0
		* [Dylib-Hijack-Scanner](https://github.com/D00MFist/Dylib-Hijack-Scanner)
			* JavaScript for Automation (JXA) version of Patrick Wardle's tool that searches applications for dylib hijacking opportunities
	DYLD
		http://newosxbook.com/articles/DYLD.html
	Entitlements
		https://secret.club/2020/08/14/macos-entitlements.html
	Evasion
		* **Articles/Blogposts/Writeups**
		* **Tools**
	Execution
		https://github.com/CylanceVulnResearch/osx_runbin
		https://github.com/cedowens/JXA-Runner
		* **101**
		* **Articles/Blogposts/Writeups**
			https://antman1p-30185.medium.com/macos-native-api-calls-in-electron-d297d9a960af
		* **Talks/Presentations/Videos**
		* **Tools**
		* **Bring-Your-Own-`*`**
			https://blog.xpnsec.com/bring-your-own-vm-mac-edition/
	Gatekeeper
		https://bouj33boy.com/gatekeeper-symlink-automount-bypass/
	Hooking
		* [subhook](https://github.com/Zeex/subhook)
			* SubHook is a super-simple hooking library for C and C++ that works on Windows, Linux and macOS. It supports x86 only (32-bit and 64-bit).
		* [Function Hooking for Mac OSX and Linux - ](https://media.defcon.org/DEF%20CON%2018/DEF%20CON%2018%20video%20and%20slides/DEF%20CON%2018%20Hacking%20Conference%20Presentation%20By%20Joe%20Damato%20-%20Function%20Hooking%20for%20Mac%20OSX%20and%20Linux%20-%20Video%20and%20Slides.m4v)
			* [Slides](https://www.defcon.org/images/defcon-18/dc-18-presentations/Damato/DEFCON-18-Damato-Function-Hooking.pdf)
	Injection
		https://en.wikipedia.org/wiki/Rpath
		https://github.com/djhohnstein/macos_shell_memory
		* [InjectCheck](https://github.com/D00MFist/InjectCheck)
			* The tool enumerates the Hardened Runtime, Entitlements, and presence of Electron files to determine possible injection opportunities
	JAMF
		* [An Attacker's Perpsective on JAMF Configurations - Luke Roberts, Calum Hall(ObjectiveByTheSeav3)](https://objectivebythesea.com/v3/talks/OBTS_v3_cHall_lRoberts.pdf)
		* [Jamfing for Joy: Attacking macOS in Enterprise - Calum Hall, Luke Roberts(2020)](https://labs.f-secure.com/blog/jamfing-for-joy-attacking-macos-in-enterprise/)
	JXA
		https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5
		* [PersistentJXA](https://github.com/D00MFist/PersistentJXA)
			* Collection of macOS persistence methods and miscellaneous tools in JXA
		https://news.ycombinator.com/item?id=21803874
		https://forum.keyboardmaestro.com/t/jxa-javascript-for-automation-from-the-start/4522
		https://stackoverflow.com/questions/47940322/cant-find-jxa-documentation
		https://medium.com/@SteveBarbera/automating-chrome-with-jxa-javascript-application-scripting-6f9bc433216a
		https://pragli.com/blog/manage-macos-windows-with-jxa/
		https://computers.tutsplus.com/tutorials/a-beginners-guide-to-javascript-application-scripting-jxa--cms-27171
		https://wiki.nikitavoloboev.xyz/macos/jxa
		https://github.com/JXA-Cookbook/JXA-Cookbook
	LoLbins
		https://labs.sentinelone.com/20-common-tools-techniques-used-by-macos-threat-actors-malware/
	Mach-O
		* [So You Want To Be A Mach-O Man? - symbolcrash(2019)](https://www.symbolcrash.com/2019/02/25/so-you-want-to-be-a-mach-o-man/)
		* [Mach-O Universal / Fat Binaries - symbolcrash(2019)](https://www.symbolcrash.com/2019/02/26/mach-o-universal-fat-binaries/)
	Malware
		https://objective-see.com/blog/blog_0x4E.html
		https://objective-see.com/blog/blog_0x4D.html
		https://www.irongeek.com/i.php?page=videos/derbycon6/104-macs-get-sick-too-tyler-halfpop-jacob-soo
		https://www.sentinelone.com/blog/2020/01/29/scripting-macs-with-malice-how-shlayer-and-other-malware-installers-infect-macos/
		https://labs.sentinelone.com/apt32-multi-stage-macos-trojan-innovates-on-crimeware-scripting-technique/
		https://objective-see.com/blog/blog_0x5C.html
	Objective-C
	Payloads
		https://posts.specterops.io/sparkling-payloads-a2bd017095c
		https://posts.specterops.io/sparkling-payloads-a2bd017095c
	Persistence
		https://topic.alibabacloud.com/a/how-to-implement-persistent-access-on-macos-through-emond_3_75_32777033.html
		https://posts.specterops.io/are-you-docking-kidding-me-9aa79c24bdc1
		https://posts.specterops.io/saving-your-access-d562bf5bf90b
		https://posts.specterops.io/leveraging-emond-on-macos-for-persistence-a040a2785124
		https://theevilbit.github.io/posts/macos_persistence_spotlight_importers/
		https://theevilbit.github.io/posts/macos_persisting_through-application_script_files/
		https://github.com/cedowens/Persistent-Swift
		https://github.com/CyborgSecurity/PoisonApple
		* [Persistent JXA - Leo Pitt(2020)](https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5)
		* [Operationalising Calendar Alerts: Persistence on macOS - Luke Roberts(2020)](https://labs.f-secure.com/blog/operationalising-calendar-alerts-persistence-on-macos/)
			* Throughout the following blog post we provide insights into calendar alerts, a method of persisting on macOS. Building on the work of Andy Grant over at NCC (https://research.nccgroup.com/2020/05/05/exploring-macos-calendar-alerts-part-1-attempting-to-execute-code/), this post takes deeper look into weaponising the feature for use in offensive operations. This includes reversing Automator.app to find an undocumented API that enables the technique.
		* [Hey, I'm Still In Here: An Overview of macOS Persistence Techniques – Leo Pitt (SO-CON 2020)](https://www.youtube.com/watch?v=OFQYTJiAmxs&list=PLJK0fZNGiFU-2vFpjnt96j_VSuQVTkAnO&index=9)
			* There is more to macOS persistence than Launch Agents. This talk goes over some lesser utilized macOS persistence methods. We will walk through how these methods work, how automation can be leveraged to quickly execute these from an offensive perspective, and how defenders can leverage indicators of these methods to assist in detection efforts.
		* Finder plugins
			https://github.com/D00MFist/InSync
		* **Tools**
			* [CalendarPersist](https://github.com/FSecureLABS/CalendarPersist)
				* JXA script to allow programmatic persistence via macOS Calendar.app alerts. 
	plist
	Pkgs
		Unpacking Pkgs: A Look Inside Macos Installer Packages And Common Security Flaws - Andy Grant
	PkgInfo
	PopUps
		https://github.com/its-a-feature/macos-popups
	PostEx
		https://www.irongeek.com/i.php?page=videos/nolacon2018/nolacon-2018-107-your-mac-defenestrated-post-osxploitation-elevated-fuzzynop-noncetonic
		* [macos_execute_from_memory](https://github.com/its-a-feature/macos_execute_from_memory)
	Privileged Helper Tools
		https://www.offensivecon.org/speakers/2019/tyler-bohan.html
		https://github.com/blankwall/Offensive-Con
		https://theevilbit.github.io/posts/secure_coding_privilegedhelpertools_part1/
		https://theevilbit.github.io/posts/secure_coding_privilegedhelpertools_part2/
	PrivEsc
		https://xlab.tencent.com/en/2021/01/11/cve-2020-9971-abusing-xpc-service-to-elevate-privilege/
		https://www.rapid7.com/db/vulnerabilities/apple-osx-systempreferences-cve-2020-9839
		https://packetstormsecurity.com/files/159084/macOS-cfprefsd-Arbitrary-File-Write-Local-Privilege-Escalation.html
		https://book.hacktricks.xyz/linux-unix/privilege-escalation
		https://bradleyjkemp.dev/post/launchdaemon-hijacking/
		https://research.nccgroup.com/2021/06/04/ios-user-enrollment-and-trusted-certificates/
		https://github.com/djhohnstein/macos_shell_memory
		https://blogs.blackberry.com/en/2017/02/running-executables-on-macos-from-memory
		https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8
		https://www.offensive-security.com/offsec/macos-preferences-priv-escalation/
		https://themittenmac.com/publication_docs/OBTS_v2_Bradley.pdf
		* [Unauthd - Logic bugs FTW - A2nkF(2020)](https://a2nkf.github.io/unauthd_Logic_bugs_FTW/)
		* [Privilege Escalation 

macOS Malware & The Path to Root Part 2 - Phil Stokes(2019)](https://www.sentinelone.com/blog/privilege-escalation-macos-malware-the-path-to-root-part-2/)
		https://www.criticalstart.com/local-privilege-escalation-vulnerability-discovered-in-vmware-fusion/
	Shellcode
				* **101**
					* [Creating OSX shellcodes  - theevilbit(2015)](https://theevilbit.blogspot.com/2015/09/creating-osx-shellcodes.html)
					* [Shellcode: Mac OSX amd64 - odzhan(2017)](https://modexp.wordpress.com/2017/01/21/shellcode-osx/)
				* **Techniques**
				* **Talks/Presentations/Videos**
				* **Tools**
				* **Samples**
					* [OSX/x64 - execve(/bin/sh) + Null-Free Shellcode (34 bytes)](https://www.exploit-db.com/exploits/38065)
					* [OSX/x64 - Bind (4444/TCP) Shell (/bin/sh) + Null-Free Shellcode (144 bytes)](https://www.exploit-db.com/exploits/38126)
	TCC
		https://blog.fleetsmith.com/tcc-a-quick-primer/
		https://lapcatsoftware.com/articles/disclosure3.html
		https://eclecticlight.co/2018/10/10/watching-mojaves-privacy-protection-at-work/
		https://eclecticlight.co/2020/11/25/macos-has-checked-app-signatures-online-for-over-2-years/
		https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy
		https://www.macobserver.com/link/about-macos-transparency-consent-and-control-system/
		https://www.theregister.com/2020/07/01/apple_macos_privacy_bypass/
		https://lockboxx.blogspot.com/2019/04/macos-red-teaming-205-tcc-transparency.html
		https://blog.xpnsec.com/bypassing-macos-privacy-controls/
		https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8
		https://eclecticlight.co/2019/07/22/mojaves-privacy-consent-works-behind-your-back/
		https://lapcatsoftware.com/articles/disclosure2.html
		https://mjtsai.com/blog/tag/transparency-consent-and-control-tcc/
		https://fpf.org/2020/07/06/ios-privacy-advances/
		https://github.com/slyd0g/SwiftParseTCC
		https://developer.apple.com/documentation/devicemanagement/privacypreferencespolicycontrol
		https://www.jamf.com/jamf-nation/articles/553/preparing-your-organization-for-user-data-protections-on-macos-10-14
		https://eclecticlight.co/2018/10/10/watching-mojaves-privacy-protection-at-work/
		https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8
		https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8
	URL Schemes
		* [Custom_URL_Scheme](https://github.com/D00MFist/Custom_URL_Scheme)
	Workflows
		https://support.apple.com/guide/automator/use-quick-action-workflows-aut73234890a/mac
	XPC
		https://www.youtube.com/watch?v=KPzhTqwf0bA&list=PLYvhPWR_XYJmwgLkZbjoEOnf2I1zkylz8&index=7






## End Unsorted Section
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------






-----------------------------------------------------------------------------------------------------------------------------------
### macOS Post-Exploitation General Notes<a name="general"></a>
- **F**
	- 
-----------------------------------------------------------------------------------------------------------------------------------























-----------------------------------------------------------------------------------------------------------------------------------
### AppleScript, Objective-C & Swift<a name="maclangs"></a>
- **F**
	- 
-----------------------------------------------------------------------------------------------------------------------------------

















-----------------------------------------------------------------------------------------------------------------------------------
### <a name="osxpost"></a>Post-Exploitation OS X
* **Educational**<a name="osxedu"></a>
	* **Articles/Blogposts/Writeups**
		* [The ‘app’ you can’t trash: how SIP is broken in High Sierra](https://eclecticlight.co/2018/01/02/the-app-you-cant-trash-how-sip-is-broken-in-high-sierra/)
		* [I can be Apple, and so can you - A Public Disclosure of Issues Around Third Party Code Signing Checks - Josh Pitts](https://www.okta.com/security-blog/2018/06/issues-around-third-party-apple-code-signing-checks/)
		* [Targeting a macOS Application? Update Your Path Traversal Lists - James Sebree](https://medium.com/tenable-techblog/targeting-a-macos-application-update-your-path-traversal-lists-a1055959a75a)
		* [The Mac Malware of 2019 👾 a comprehensive analysis of the year's new malware - Patrick Wardle(2020)](https://objective-see.com/blog/blog_0x53.html)
	* **Talks/Presentations/Videos**
		* [The Mouse is Mightier than the Sword - Patrick Wardle](https://speakerdeck.com/patrickwardle/the-mouse-is-mightier-than-the-sword)
			* In this talk we'll discuss a vulnerability (CVE-2017-7150) found in all recent versions of macOS that allowed unprivileged code to interact with any UI component including 'protected' security dialogues. Armed with the bug, it was trivial to programmatically bypass Apple's touted 'User-Approved Kext' security feature, dump all passwords from the keychain, bypass 3rd-party security tools, and much more! And as Apple's patch was incomplete (surprise surprise) we'll drop an 0day that (still) allows unprivileged code to post synthetic events and bypass various security mechanisms on a fully patched macOS box!
		* [Fire & Ice; Making and Breaking macOS firewalls - Patrick Wardle(Rootcon12)](https://www.youtube.com/watch?v=zmIt9ags3Cg)
			* [Slides](https://speakerdeck.com/patrickwardle/fire-and-ice-making-and-breaking-macos-firewalls)
		* [When Macs Come Under ATT&CK - Richie Cyrus(Derbycon2018)](http://www.irongeek.com/i.php?page=videos/derbycon8/track-3-01-when-macs-come-under-attck-richie-cyrus)
			* Macs are becoming commonplace in corporate environments as a alternative to Windows systems. Developers, security teams, and executives alike favor the ease of use and full administrative control Macs provide. However, their systems are often joined to an active directory domain and ripe for attackers to leverage for initial access and lateral movement. Mac malware is evolving as Mac computers continue to grow in popularity. As a result, there is a need for proactive detection of attacks targeting MacOS systems in a enterprise environment. Despite advancements in MacOS security tooling for a single user/endpoint, little is known and discussed regarding detection at a enterprise level. This talk will discuss common tactics, techniques and procedures used by attackers on MacOS systems, as well as methods to detect adversary activity. We will take a look at known malware, mapping the techniques utilized to the MITRE ATT&CK framework. Attendees will leave equipped to begin hunting for evil lurking within their MacOS fleet.
		* [Harnessing Weapons of Mac Destruction - Patrick Wardle](https://speakerdeck.com/patrickwardle/harnessing-weapons-of-mac-destruction)
		* [Herding cattle in the desert: How malware actors have adjusted to new security enhancements in Mojave - Omer Zohar](https://www.youtube.com/watch?v=ZztuWe6sv18&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=3)
		    * [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Zohar.pdf)
    		* In this talk, we’ll deep dive into recent security changes in MacOS Mojave & Safari and examine how these updates impacted actors of highly distributed malware in terms of number of infections, and more importantly - monetization. We’ll take a look at malware actors currently infecting machines in the wild (Bundlore and Genio to name a few) - and investigate how their tactics evolved after the update: From vectors of infection that bypass Gatekeeper, getting around the new TCC dialogs, hijacking search in a SIP protected Safari, to persistency and reinfection mechanisms that ultimately turn these ‘annoying PUPs’ into a fully fledged backdoored botnet. 
		* [Never Before Had Stierlitz Been So Close To Failure (Sergei Shevchenko(OBTS v2.0)](https://www.youtube.com/watch?v=0zL0RWjzFFU&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=16)
	    	* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Shevchenko.pdf)
			* In this research, we'll dive into the installer's Mach-O binary to demonstrate how it piggy-backs on 'non-lazy' Objective-C classes, the way it dynamically unpacks its code section in memory and decrypts its config. An in-depth analysis will reveal the structure of its engine and a full scope of its hidden backdoor capabilities, anti-debugging, VM evasion techniques and other interesting tricks that are so typical to the Windows malware scene but aren’t commonly found in the unwanted apps that claim to be clean, particularly on the Mac platform. This talk reveals practical hands-on tricks used in Mach-O binary analysis under a Hackintosh VM guest, using LLDB debugger and IDA Pro disassembler, along with a very interesting marker found during such analysis. Curious to learn what that marker was? Willing to see how far the Mac-specific techniques evolved in relation to Windows malware? 
		* [Bash-ing Brittle Indicators: Red Teaming macOS without Bash or Python - Cody Thomas(ObjectiveByTheSea v2.0)](https://www.youtube.com/watch?v=E-QEsGsq3uI)
			* Objective by the Sea 354 subscribers On macOS, defenders are watching shell scripts, a few common binaries, and python usage as easy tell-tale signs of red teamers. After all, it's very anomalous for HR to start running Python, Perl, or Ruby, and Marketing employees never run shell commands. As EDR products and defenders start to get more adept at looking into macOS, it's time for red teamers to start adapting as well. The question becomes: what should you use for an agent? If only macOS had a native scripting capability geared towards automating tasks common across all disciplines that is meant to be accessible even to non-programmers.   In this talk, I'll go into the research, development, and usage of a new kind of agent based on JavaScript for Automation (JXA) and how it can be used in modern red teaming operations. This agent is incorporated into a broader open source project designed for collaborative red teaming I created called Apfell. I will discuss TTPs for doing reconnaissance, persistence, injection, and some keylogging all without using a shell command or spawning another scripting language. I will go into details of how JXA can be used to create an agent complete with encrypted key exchange for secure communications, domain fronting C2, and modular design to load or change key functionality on the fly. I will also cover the defensive considerations of these TTPs and how Apple is starting to secure these capabilities going forward.
		* [An 0day in macOS - Patrick Wardle(OBTSv2.0)](https://www.youtube.com/watch?v=yWyxJla6xPo&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=18)
		    * [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Wardle.pdf)
		    * Let's talk about a powerful 0day in macOS Mojave.
		* [Yin and Yang: The Art of Attack and Defense on macOS - Patrick Wardle(JNUC2019)](https://www.youtube.com/watch?v=i_NVEDWpCSQ)
			* This session will begin by looking at recent malware infections targeting macOS and how (interactive) attackers can further penetrate the macOS enterprise. We'll then switch gears to talk about Apple's recent macOS security improvements, then wrap up by discussing security solutions today that are able to detect advanced macOS threats that may bypass Apple’s built-in security mechanisms.

		* [Offensive Ops In macOS Environments by Cedric Owens(Greyhat2020)](https://www.youtube.com/watch?v=aXluq8M1u5Q&feature=youtu.be)
			* [Slides](https://github.com/cedowens/Presentations/blob/master/GrayHat2020-CedOwens.pdf)
	* **Tools**
		* [Jamf-Attack-Toolkit](https://github.com/FSecureLABS/Jamf-Attack-Toolkit)
			* Suite of tools to facilitate attacks against the Jamf macOS management platform. These tools compliment the talk given by Calum Hall and Luke Roberts at Objective By The Sea V3, slides and video can be found [here](https://objectivebythesea.com/v3/talks/OBTS_v3_cHall_lRoberts.pdf) and [here](https://youtu.be/ZDJsag2Za8w?t=16737).
	* **Writeups that didn't fit elsewhere**
		* [The XCSSET Malware: Inserts Malicious Code Into Xcode Projects, Performs UXSS Backdoor Planting in Safari, and Leverages Two Zero-day Exploits - TrendMicro](https://documents.trendmicro.com/assets/pdf/XCSSET_Technical_Brief.pdf)
* **Execution**<a name="osxexecute"></a>
	* **General**
		* [Apple Silicon Macs to Require Signed Code - @mjtsai(2020)](https://mjtsai.com/blog/2020/08/19/apple-silicon-macs-to-require-signed-code/)
		* [macOS Pop-Ups](https://github.com/its-a-feature/macos-popups)
			* This repo serves as a collection of Red Team techniques and administrative tasks for various macOS versions that cause popups, what those popups look like, what permissions are being requested, where they're stored, and hopefully how to check for them before causing popups.
	* **Unsorted**
		* [macOS Research Outtakes - File Extensions - Adam Chester(2018)](https://blog.xpnsec.com/macos-phishing-tricks/)
		* [Launching Apfell Programmatically - Cedric Owens(2019)](https://medium.com/red-teaming-with-a-blue-team-mentaility/launching-apfell-programmatically-c90fe54cad89)
		* [No Place Like Chrome - Christopher Ross(2019)](https://posts.specterops.io/no-place-like-chrome-122e500e421f)
		* [Sparkling Payloads - Christopher Ross(2020)](https://posts.specterops.io/sparkling-payloads-a2bd017095c)
		* [Exploring macOS Calendar Alerts: Part 1 – Attempting to execute code - Andy Grant(2020)](https://research.nccgroup.com/2020/05/05/exploring-macos-calendar-alerts-part-1-attempting-to-execute-code/)
		* [Audio Unit Plug-ins - Christopher Ross(2020)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
		* [Abusing MacOS Entitlements for code execution - impost0r(2020)](https://secret.club/2020/08/14/macos-entitlements.html)
		* [Lazarus Group Goes 'Fileless' an implant w/ remote download & in-memory execution - Patrick Wardle(2019)](https://objective-see.com/blog/blog_0x51.html)
		* [Weaponizing a Lazarus Group Implant - Patrick Wardle(2020)](https://objective-see.com/blog/blog_0x54.html)
			* repurposing a 1st-stage loader, to execute custom 'fileless' payloads
		* [Using macOS Internals for Post Exploitation - Cedric Owens(2019)](https://medium.com/red-teaming-with-a-blue-team-mentaility/using-macos-internals-for-post-exploitation-b5faaa11e121)
	* **Command and Scripting Interpreter**
		* **AppleScript**<a name="osxa"></a>
			* **101**
				* [AppleScript Language Guide - developer.apple](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/introduction/ASLR_intro.html#//apple_ref/doc/uid/TP40000983-CH208-SW1)
				* [AppleScript Fundamentals - developer.apple](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/conceptual/ASLR_fundamentals.html)
					* Section from the Language Guide
				* [AppleScript - William R. Cook(2006)](https://www.cs.utexas.edu/users/wcook/Drafts/2006/ashopl.pdf)
				* [Scripting with AppleScript - developer.apple](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptX/Concepts/work_with_as.html#//apple_ref/doc/uid/TP40001568)
					* The following is a brief introduction to AppleScript scripts, tools for working with them, and information on using AppleScript scripts together with other scripting systems. For related documents, see the learning paths in Getting Started with AppleScript.
				* [AppleScript: The Definitive Guide, 2nd Edition - Matt Neuburg](http://books.gigatux.nl/mirror/applescriptdefinitiveguide/toc.html)
				* [AppleScript Reference Library](https://applescriptlibrary.wordpress.com/)
				* [AppleScriptLanguageGuide - Apple](https://applescriptlibrary.files.wordpress.com/2013/11/applescriptlanguageguide-2013.pdf)
				* [Open Scripting Architecture - developer.apple.com](https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptX/Concepts/osa.html)
			* **Articles/Blogposts/Writeups**
				* [How Offensive Actors Use AppleScript for Attackign macOS - Phil Stokes(2020)](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
				* [macOS Red Team: Spoofing Privileged Helpers (and Others) to Gain Root - Phil Stokes](https://www.sentinelone.com/blog/macos-red-team-spoofing-privileged-helpers-and-others-to-gain-root/)
				* [macOS Red Team: Calling Apple APIs Without Building Binaries - Phil Stokes](https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/)
				* [Launch Scripts from Webpage Links - macosxautomation.com](https://www.macosxautomation.com/applescript/linktrigger/)
				* [Using NSAppleScript - appscript.sourceforge](http://appscript.sourceforge.net/nsapplescript.html)
				* [hello, applescript 2: user in, user out - philastokes(applehelpwriter.com 2018)](https://applehelpwriter.com/2018/09/03/hello-applescript-2-user-in-user-out/)
				* [hello, applescript 3: (don’t?) tell me to run - philastokes(appplehelpwriter 2018)](https://applehelpwriter.com/2018/09/14/hello-applescript-3-dont-tell-me-to-run/)
			* **Tools**
				* [Orchard](https://github.com/its-a-feature/Orchard)
					* Live off the land for macOS. This program allows users to do Active Directory enumeration via macOS JXA (JavaScript for Automation) code. This is the newest version of AppleScript, and thus has very poor documentation on the web.
		* **Javascript for Automation(JXA)**
			* **Talks/Presentations/Videos**
				* [Bash-ing Brittle Indicators: Red Teaming macOS without Bash or Python - Cody Thomas(Objective by the Sea v2.0)](https://www.youtube.com/watch?v=E-QEsGsq3uI&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=17)
				    * [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf)
		    		*  In this talk, I'll go into the research, development, and usage of a new kind of agent based on JavaScript for Automation (JXA) and how it can be used in modern red teaming operations. This agent is incorporated into a broader open source project designed for collaborative red teaming I created called Apfell. I will discuss TTPs for doing reconnaissance, persistence, injection, and some keylogging all without using a shell command or spawning another scripting language. I will go into details of how JXA can be used to create an agent complete with encrypted key exchange for secure communications, domain fronting C2, and modular design to load or change key functionality on the fly. I will also cover the defensive considerations of these TTPs and how Apple is starting to secure these capabilities going forward. 
		* **Objective-C**
			* **Articles/Blogposts/Writeups**
				* [Making Objective C Calls From Python Standard Libraries (Red Team Edition) - Cedric Owens(2020)](https://medium.com/red-teaming-with-a-blue-team-mentaility/making-objective-c-calls-from-python-standard-libraries-550ed3a30a30)
		* **Swift**
			* **Articles/Blogposts/Writeups**
				* [Making Objective C Calls From Python Standard Libraries (Red Team Edition) - Cedric Owens(2020)](https://medium.com/@clowens0716)
				* [Loading Python Runtimes in Swift - Cedric Owens(2020)](https://medium.com/red-teaming-with-a-blue-team-mentaility/loading-python-runtimes-in-swift-20648890489c)
			* **Tools**
				* [ShellOut](https://github.com/JohnSundell/ShellOut)
					* Easily run shell commands from a Swift script or command line tool
	* **In-Memory Execution**
		* **Articles/Blogposts/Writeups**
		* **Tools**
			* [macos_execute_from_memory](https://github.com/its-a-feature/macos_execute_from_memory)
				* PoC of macho loading from memory
	* **Office Macros**
		* **Articles/Blogposts/Writeups**
				* [Running JXA Payloads from macOS Office Macros - Cedric Owens(2020)](https://medium.com/red-teaming-with-a-blue-team-mentaility/a-look-at-python-less-office-macros-for-macos-b1bf5c1488f1)
		* **Talks/Presentations/Videos**
			* [Office Drama on macOS - Patrick Wardle(DefconSafemode2020)](https://www.youtube.com/watch?v=Y7IJjnLGqTQ)
				* On the Windows platform, macro-based Office attacks are well understood (and frankly are rather old news). However on macOS, though such attacks are growing in popularity and are quite en vogue, they have received far less attention from the research and security community.  In this talk, we will begin by analyzing recent documents that contain macro-based attacks targeting Apple's desktop OS, highlighting the macOS-specific exploit code and payloads. Though sophisticated APT groups are behind several of these attacks, (luckily) these malicious documents and their payloads are constrained by recent application and OS-level security mechanisms.  However, things could be far worse! To illustrate this claim, we'll detail the creation of a powerful exploit chain, that begins with CVE-2019-1457, leveraged a new sandbox escape and ended with a full bypass of Apple's stringent notarization requirements. Triggered by simply opening a malicious (macro-laced) Office document, no other user interaction was required in order to persistently infect even a fully-patched macOS Catalina system!  To end the talk, we'll discuss various prevention and detection mechanisms that could thwart each stage of the exploit chain, as well as that aim to generically provide protection against future attacks!
	* **URL Handlers**
		* **Articles/Blogposts/Writeups**
			* [Few click RCE via GitHub Desktop macOS client with Gatekeeper bypass and custom URL handlers - theevilbit(2019)](https://theevilbit.github.io/posts/few_click_rce_via_github_desktop_macos_client_with_gatekeeper_bypass_and_custom_url_handlers/)
	* **User Execution**
		* **Malicious Link**
			* **Articles/Blogposts/Writeups**
				* [URL Routing on macOS - Florian Schliep](https://medium.com/@floschliep/url-routing-on-macos-c53a06f0a984)
				* [Remote Mac Exploitation Via Custom URL Schemes - Patrick Wardle(2018)](https://objective-see.com/blog/blog_0x38.html)
		* **Malicious File**
			* **Articles/Blogposts/Writeups**
				* [Native Mac OS X Application / Mach-O Backdoors for Pentesters](https://lockboxx.blogspot.com/2014/11/native-mac-os-x-application-mach-o.html)
			* **Tools**
				* [HappyMac](https://github.com/laffra/happymac)
					* A Python Mac app to suspend background processes 
				* [Platypus](https://github.com/sveinbjornt/Platypus)
					* Platypus is a developer tool that creates native Mac applications from command line scripts such as shell scripts or Python, Perl, Ruby, Tcl, JavaScript and PHP programs. This is done by wrapping the script in an application bundle along with a slim app binary that runs the script.
	* **Tools**
		* [Mouse](https://github.com/entynetproject/mouse)
			* Mouse Framework is an iOS and macOS post-exploitation framework that gives you  a command line session with extra functionality between you and a target machine  using only a simple Mouse Payload. Mouse gives you the power and convenience of  uploading and downloading files, tab completion, taking pictures, location tracking,  shell command execution, escalating privileges, password retrieval, and much more.
		* [Appfell](https://github.com/its-a-feature/Apfell)
			* A collaborative, multi-platform, red teaming framework
		* [MacShell Post Exploitation Tool - Cedric Owens](https://medium.com/red-teaming-with-a-blue-team-mentaility/macshell-post-exploitation-tool-41696be9d826)
		* [MacShell](https://github.com/cedowens/MacShell)
			* MacShell is a macOS post exploitation tool written in python using encrypted sockets. I wrote this tool as a way for defenders and offensive security researchers to more easily understand the inner workings of python-based post exploitation tools on macOS.
		* [MacShellSwift](https://github.com/cedowens/MacShellSwift/tree/master/MacShellSwift)
			* MacShellSwift is a proof of concept MacOS post exploitation tool written in Swift using encrypted sockets. I rewrote a prior tool of mine MacShell (one of my repos) and changed the client to Swift intstead of python. This tool consists of two parts: a server script and a client binary. I wrote this tool to help blue teamers proactively guage detections against macOS post exploitation methods that use macOS internal calls. Red teams can also find this of use for getting ideas around using Swift for macOS post exploitation.
		* [Parasite](https://github.com/ParasiteTeam/documentation)
			* Parasite is a powerful code insertion platform for OS X. It enables developers to easily create extensions which change the original behavior of functions. For users Parasite provides an easy way to install these extensions and tweak their OS.
		* [EvilOSX](https://github.com/Marten4n6/EvilOSX)
			* A pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX.
* **Persistence**<a name="osxpersist"></a>
	* **General**
		* **Articles/Blogposts/Writeups**
			* [Methods Of Malware Persistence On Mac OS X](https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf)
			* [How Malware Persists on macOS - Phil Stokes](https://www.sentinelone.com/blog/how-malware-persists-on-macos/)
			* [What's the easiest way to have a script run at boot time in OS X? - Stack Overflow](https://superuser.com/questions/245713/whats-the-easiest-way-to-have-a-script-run-at-boot-time-in-os-x)
			* [OSX.EvilQuest Uncovered - Patrick Wardle(2020)](https://objective-see.com/blog/blog_0x59.html)
	* **Presentations/Talks/Videos**
		* [Userland Persistence On Mac Os X "It Just Works"  -  Shmoocon 2015](http://www.securitytube.net/video/12428?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed:%20SecurityTube%20%28SecurityTube.Net%29)
			* Got root on OSX? Do you want to persist between reboots and have access whenever you need it? You do not need plists, new binaries, scripts, or other easily noticeable techniques. Kext programming and kernel patching can be troublesome! Leverage already running daemon processes to guarantee your access.  As the presentation will show, if given userland administrative access (read: root), how easy it is to persist between reboots without plists, non-native binaries, scripting, and kexts or kernel patching using the Backdoor Factory.
	* **Boot or Logon Initialization Scripts**
		* **Logon Script (Mac)**
			* [Adding Login Items - developer.apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLoginItems.html)
			* [Open items automatically when you log in on Mac - developer.apple](https://support.apple.com/en-gb/guide/mac-help/mh15189/mac)
	* **Compromise Client Software Binary**
		* **Mail.app**
			* [Using email for persistence on OS X - n00py](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
	* **Folder Actions**
		* [Folder Actions for Persistence on macOS - Cody Thomas(2019)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)	
	* **Xcode**
		* [Running and disguising programs through XCode shims on OS X](https://randomtechnicalstuff.blogspot.com.au/2016/05/os-x-and-xcode-doing-it-apple-way.html)
	* **Tools**
		* [p0st-ex](https://github.com/n00py/pOSt-eX)
			* Post-exploitation scripts for OosxpostS X persistence and privesc
		* [iMessagesBackdoor](https://github.com/checkymander/iMessagesBackdoor)
			* A script to help set up an event handler in order to install a persistent backdoor that can be activated by sending a message.
* **Privilege Escalation**<a name="osxprivesc"></a>
	* **General**
		* **Articles/Blogposts/Writeups**
			* [Hidden backdoor API to root privileges in Apple OS X](https://truesecdev.wordpress.com/2015/04/09/hidden-backdoor-api-to-root-privileges-in-apple-os-x/)
				* The Admin framework in Apple OS X contains a hidden backdoor API to root privileges. It’s been there for several years (at least since 2011), I found it in October 2014 and it can be exploited to escalate privileges to root from any user account in the system. The intention was probably to serve the “System Preferences” app and systemsetup (command-line tool), but any user process can use the same functionality. Apple has now released OS X 10.10.3 where the issue is resolved. OS X 10.9.x and older remain vulnerable, since Apple decided not to patch these versions. We recommend that all users upgrade to 10.10.3.
				* Works on 10.7 -> 10.10.2
		* **Presentations/Talks/Videos**
			* [Hacking Exposed: Hacking Macs - RSA Keynote, George Kurtz and Dmitri Alperovitch, Part 1 "Delivery"(2019)](https://www.youtube.com/watch?v=DMT_vYVoM4k&feature=emb_title)
				* CrowdStrike Co-founders, CEO George Kurtz and CTO Dmitri Alperovitch, and Falcon OverWatch Senior Engineer Jaron Bradley demonstrate a “Delivery” stage attack against a MacOS system. This demo is from their RSA 2019 keynote address titled, “Hacking Exposed: Hacking Macs.”
			* [Hacking Macs from RSA- George Kurtz and Dmitri Alperovitch, Part 2 "Privilege Escalation"](https://www.youtube.com/watch?v=Dh-XMkYOdE8&feature=emb_title)
				* CrowdStrike Co-founders, CEO George Kurtz and CTO Dmitri Alperovitch, and Falcon OverWatch Senior Engineer Jaron Bradley demonstrate a “Privilege Escalation” stage attack against a MacOS system. This demo is from their RSA 2019 keynote address titled, “Hacking Exposed: Hacking Macs.”
			* [OSX XPC Revisited - 3rd Party Application Flaws - Tyler Bohan(OffensiveCon2020)](https://www.youtube.com/watch?v=KPzhTqwf0bA&list=PLYvhPWR_XYJmwgLkZbjoEOnf2I1zkylz8&index=8&t=0s)
				* XPC or cross process communication is a way for OSX and iOS processes to communicate with one another and share information. One use for this is to elevate privileges using a daemon who listens as a XPC service. While Apple has released a coding guideline it is all to often ignored or incorrectly implemented in third-party applications. One striking example of this is the Privileged Helper Tool. In this talk I am going to dive into what a Privileged Helper Tool is and why you should care about it. I will show the viewers how to locate these on an OSX computer and walk through the reverse engineering steps needed to identify if the service is vulnerable. We will then set up communications via Objective-C to deliver a privilege escalation attack. I will be showcasing twenty plus vulnerabilities in at least five products. All tooling and code will be released with the talk!
	* **Dylib Hijacking**
		* **Articles/Blogposts/Writeups**
			* [DylibHijack](https://github.com/synack/DylibHijack)
				* python utilities related to dylib hijacking on OS X
		* **Talks/Presentations/Videos**
			* [Gaining Root with Harmless AppStore Apps - Csaba Fitzi](https://www.youtube.com/watch?v=sOtcM-dryF4&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=8)
	    		* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Fitzl.pdf)
			    * This talk is about my journey from trying to find dylib hijacking vulnerability in a particular application to finding a privilege escalation vulnerability in macOS. During the talk I will try to show the research process, how did I moved from one finding to the next and I will also show many of the failures / dead ends I had during the exploit development.First I will briefly cover what is a dylib hijacking, and what is the current state of various application regarding this type of vulnerability. We will see how hard is to exploit these in many cases due to the fact that root access is required. Second I will cover two seemingly harmless bugs affecting the installation process of AppStore apps, and we will see how can we chain these together in order to gain root privileges - for this we will utilise a completely benign app from the macOS App Store. Part of this I will cover how can we submit apps to the store, and what are the difficulties with that process.In the last part I will cover how we can infect and include our malicious file in an App installer without breaking the App’s signature.
			* [Automated Dylib Hijacking - Jimi Sebree(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/stable-11-automated-dylib-hijacking-jimi-sebree)
				* Applications on macOS use a common and flawed method of loading dynamic libraries (dylib), which leaves them vulnerable to a post-exploitation technique known as dylib hijacking. Dylib hijacking is a technique used to exploit this flawed loading method in order to achieve privilege escalation, persistence, or the ability to run arbitrary code. This talk provides an overview of the attack vector and the process involved in exploiting vulnerable applications. Additionally, the process of automating the exploitation of vulnerable applications will be demonstrated and discussed in depth. The tools developed and used for this demonstration will be made publicly available.
		* **Tools**
			* [boko](https://github.com/bashexplode/boko)
				* boko.py is an application scanner for macOS that searches for and identifies potential dylib hijacking and weak dylib vulnerabilities for application executables, as well as scripts an application may use that have the potential to be backdoored. The tool also calls out interesting files and lists them instead of manually browsing the file system for analysis. With the active discovery function, there's no more guess work if an executable is vulnerable to dylib hijacking!
	* **Elevated Execution with Prompt**
		* **Articles/Blogposts/Writeups**
			* [Elevating Privileges Safely - developer.apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Articles/AccessControl.html)
			* [macOS Red Team: Spoofing Privileged Helpers (and Others) to Gain Root - Phil Stokes](https://www.sentinelone.com/blog/macos-red-team-spoofing-privileged-helpers-and-others-to-gain-root/)
			* [Privilege escalation on OS X – without exploits - n00py.io](https://www.n00py.io/2016/10/privilege-escalation-on-os-x-without-exploits/)
	* **Emond**
	* **Exploitation for Privilege Escalation**
		* [CVE-2019-8805 - A macOS Catalina privilege escalation - Scott Knight](https://knight.sc/reverse%20engineering/2019/10/31/macos-catalina-privilege-escalation.html)
		* [Sniffing Authentication References on macOS - Patrick Wardle(2018)](https://objective-see.com/blog/blog_0x55.html)
			* details of a privilege-escalation vulnerability (CVE-2017-7170)
			* `The Ugly: for last ~13 years (OSX 10.4+) anybody could locally sniff 'auth tokens' then replay to stealthy & reliably elevate to r00t 🍎🤒☠️ The Bad: reported to Apple -they silently patched it (10.13.1) 🤬 The Good: when confronted they finally assigned CVE + updated docs 😋 [pic.twitter.com/RlNBT1DBvK](pic.twitter.com/RlNBT1DBvK)`
		* [Mac OS X local privilege escalation (IOBluetoothFamily)](http://randomthoughts.greyhats.it/2014/10/osx-local-privilege-escalation.html)
		* [How to gain root with CVE-2018-4193 in < 10s - Eloi Benoist-Vanderbeken](https://www.synacktiv.com/ressources/OffensiveCon_2019_macOS_how_to_gain_root_with_CVE-2018-4193_in_10s.pdf)
		* [CVE-2018-4193](https://github.com/Synacktiv-contrib/CVE-2018-4193)
			* exploit for CVE-2018-4193
		* **Rootpipe**	
			* [Rootpipe Reborn (Part I) - codecolorist](https://medium.com/0xcc/rootpipe-reborn-part-i-cve-2019-8513-timemachine-root-command-injection-47e056b3cb43)
    			* CVE-2019-8513 TimeMachine root command injection
			* [Rootpipe Reborn (Part II) - codecolorist](https://medium.com/0xcc/rootpipe-reborn-part-ii-e5a1ffff6afe)
	    		* CVE-2019-8565 Feedback Assistant race condition leads to root LPE
			* [Stick That In Your (root)Pipe & Smoke It - Patrick Wardle(Defcon23)](https://www.slideshare.net/Synack/stick-that-in-your-rootpipe-smoke-it)
				* [Talk](https://www.youtube.com/watch?v=pbpaUuGLS5g)
	* **Launch Daemon**
	* **Permissions Misconfiguration**
		* **Articles/Blogposts/Writeups**
			* [Exploiting directory permissions on macOS - theevilbit](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
				*  In the following post I will first go over the permission model of the macOS filesystem, with focus on the POSIX part, discuss some of the non trivial cases it can produce, and also give a brief overview how it is extended. I won’t cover every single detail of the permission model, as it would be a topic in itself, but rather what I found interesting from the exploitation perspective. Then I will cover how to find these bugs, and finally I will go through in detail all of the bugs I found. Some of these are very interesting as we will see, as exploitation of them involves “writing” to files owned by root, while we are not root, which is not trivial, and can be very tricky.
		* **Talks/Presentations/Videos**
			* [Root Canal - Samuel Keeley(OBTSv2.0)](https://www.youtube.com/watch?v=sFxz3akCNsg&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=11)
	    		* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Keeley.pdf)
   			 	* Apple released System Integrity Protection/rootless with OS X El Capitan almost four years ago.The root account is still there, and many common pieces of software open the Mac up to simple root escalations - including common macOS management tools. How can we detect these vulnerabilities across our Mac fleets? What can root still be abused for in 2019?	
	* **Plist Modification**
	* **Privileged File Operations**
		* **Articles/Blogposts/Writeups**
			* [An introduction to privileged file operation abuse on Windows - @clavoillotte(2019)](https://offsec.almond.consulting/intro-to-file-operation-abuse-on-Windows.html)
			* [](https://raw.githubusercontent.com/v-p-b/kaspy_toolz/master/S2_EUSKALHACK_Self-defenseless.pdf)
		* **Talks/Presentations/Videos**
			* [Job(s) Bless Us!Privileged Operations on macOS - Julia Vaschenko(OBTSv3.0)](https://objectivebythesea.com/v3/talks/OBTS_v3_jVashchenko.pdf)
	* **Process Injection**
		* **Articles/Blogposts/Writeups**
			* [Privilege Escalation on OS X below 10.0](https://bugs.chromium.org/p/project-zero/issues/detail?id=121)
				* CVE-2014-8835
		* **Tools**
			* [osxinj](https://github.com/scen/osxinj)
				* Another dylib injector. Uses a bootstrapping module since mach_inject doesn't fully emulate library loading and crashes when loading complex modules.
	* **Setuid and Setgid**
	* **Startup Items**
	* **Sudo**
	* **Sudo Caching**
		* [tty_tickets option now on by default for macOS Sierra’s sudo tool - rtrouton](https://derflounder.wordpress.com/2016/09/21/tty_tickets-option-now-on-by-default-for-macos-sierras-sudo-tool/)
		* [Privilege escalation on OS X – without exploits - n00py.io](https://www.n00py.io/2016/10/privilege-escalation-on-os-x-without-exploits/)
	* **Valid Accounts**
	* **Web Shell**
	* **SIP Bypass**
		* [abusing the local upgrade process to bypass SIP - Objective-see](https://objective-see.com/blog/blog_0x14.html)
	* **Exploits**
		* [Why `<blank>` Gets You Root- Patrick Wardle(2017)](https://objective-see.com/blog/blog_0x24.html)
			*  In case you haven't heard the news, there is a massive security flaw which affects the latest version of macOS (High Sierra). The bug allows anybody to log into the root account with a blank, or password of their choosing. Yikes! 
		* [macOS 10.13.x SIP bypass (kernel privilege escalation)](https://github.com/ChiChou/sploits/tree/master/ModJack)
			* "Works only on High Sierra, and requires root privilege. It can be chained with my previous local root exploits."
			* [Slides](https://conference.hitb.org/hitbsecconf2019ams/materials/D2T2%20-%20ModJack%20-%20Hijacking%20the%20MacOS%20Kernel%20-%20Zhi%20Zhou.pdf)
		* [IOHIDeous(2017)](https://siguza.github.io/IOHIDeous/)
			* [Code](https://github.com/Siguza/IOHIDeous/)
			* A macOS kernel exploit based on an IOHIDFamily 0day.
		* [Issue 1102196: Security: Keystone for macOS should use auditToken to validate incoming XPC message - Project0](https://bugs.chromium.org/p/chromium/issues/detail?id=1102196)
			* PrivEsc through Chrome installer.
	* **Talks/Presentations/Videos**
		* [Death By 1000 Installers on macOS and it's all broken! - Patrick Wardle(Defcon25)](https://www.youtube.com/watch?v=mBwXkqJ4Z6c)
		    * [Slides](https://speakerdeck.com/patrickwardle/defcon-2017-death-by-1000-installers-its-all-broken)
		* [Attacking OSX for fun and profit tool set limiations frustration and table flipping Dan Tentler - ShowMeCon](https://www.youtube.com/watch?v=9T_2KYox9Us)
			* 'I was approached by Fusion to be part of their 'Real Future' documentary - specifically, and I quote, to 'see how badly I could fuck his life up, while having control of his laptop'. They wanted me to approach this scenario from how a typical attacker wou'
	* **Tools**
		* [BigPhish](https://github.com/Psychotrope37/bigphish)
			* This issue has been resolved by Apple in MacOS Sierra by enabling tty_tickets by default. NOTE: All other MacOS operation system (El Capitan, Yosemite, Mavericks etc...) still remain vulnerable to this exploit.
* **Defense Evasion**<a name="osxdefev"></a>
	* **101**
		* [App security overview - support.apple](https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/1/web/1)
		* [Protecting against malware - support.apple](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/1/web/1)
		* [Gatekeeper and runtime protection - support.apple](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/1/web/1)
	* **Articles/Blogposts/Writeups**
		* [Creating undetected malware for OS X - Erik Pistelli(2013)](https://ntcore.com/?p=436)
		* [The vulnerability in Remote Login (ssh) persists - hoakley(2020)](https://eclecticlight.co/2020/08/20/the-vulnerability-in-remote-login-ssh-persists/)
	* **Talks/Presentations/Videos**
		* [Bypassing MacOS Detections With Swift - Cedric Owens(Derbycon2019)](https://www.irongeek.com/i.php?page=videos/derbycon9/stable-00-bypassing-macos-detections-with-swift-cedric-owens)
			* This talk is centered around red teaming in MacOS environments. Traditionally, MacOS post exploitation has largely been done in python with a heavy reliance on command line utilities. However, as defender tradecraft continues to evolve with detecting suspicious python usage on MacOS, we (as red teamers) should consider migrating to different post exploitation methods. In this talk, I will share why the Swift language can be beneficial for red teaming macOS environments. I will also share some macOS post exploitation code I have written using the Swift programming language and contrast detection techniques between python and Swift based post exploitation.
	* **Tools**
		* [appencryptor](https://github.com/AlanQuatermain/appencryptor)
			* A command-line tool to apply or remove Apple Binary Protection from an application. 
	* **Application Whitelisting**<a name="whitelist"></a>
		* **Articles/Blogposts/Writeups**
				* [Bypassing Google's Santa Application Whitelisting on macOS (Part 1 of 2) - Adam Crosser](https://www.praetorian.com/blog/bypassing-google-santa-application-whitelisting-on-macos-part-1)
				* [Bypassing Google's Santa Application Whitelisting on macOS (Part 2 of 2) - Adam Crosser](https://www.praetorian.com/blog/bypassing-google-santa-application-whitelisting-on-macos-part-2)
	* **Endpoint Security**<a name="esf"></a>
		* **101**
			* [EndpointSecurity - developer.apple](https://developer.apple.com/documentation/endpointsecurity)
				* Endpoint Security is a C API for monitoring system events for potentially malicious activity. Your client, which you can write in any language supporting native calls, registers with Endpoint Security to authorize pending events, or receive notifications of events that have already occurred. These events include process executions, mounting file systems, forking processes, and raising signals. Develop your system extension with Endpoint Security and package it in an app that uses the SystemExtensions framework to install and upgrade the extension on the user’s Mac.
		* **Articles/Blogposts/Writeups**
	* **Gatekeeper**<a name="gatekeeper"></a>
		* **101**
			* [Gatekeeper - Wikipedia](https://en.wikipedia.org/wiki/Gatekeeper_(macOS))
			* [Gatekeeper Bypass - ATT&CK](https://attack.mitre.org/techniques/T1144/)
			* [Safely open apps on your Mac - support.apple](https://support.apple.com/en-us/HT202491)
    			* 'macOS includes a technology called Gatekeeper, that's designed to ensure that only trusted software runs on your Mac.'
			* [Launch Service Keys - `LSFileQuarantineEnabled`](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/LaunchServicesKeys.html#//apple_ref/doc/uid/TP40009250-SW10)
			* [macOS Code Signing In Depth - developer.apple](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
		* **Articles/Blogposts/Writeups**
			* [GateKeeper - Bypass or not bypass? - theevilbit(2019)](https://theevilbit.github.io/posts/gatekeeper_bypass_or_not_bypass/)
			* [How WindTail and Other Malware Bypass macOS Gatekeeper Settings - Phil Stokes](https://www.sentinelone.com/blog/how-malware-bypass-macos-gatekeeper/)
			* [MacOS X GateKeeper Bypass - Filippo Cavallarin(2019)](https://www.fcvl.net/vulnerabilities/macosx-gatekeeper-bypass)
	* **System Integrity Protection(SIP)**<a name="sip"></a>
		* **101**
			* [System Integrity Protection - Wikipedia](https://en.wikipedia.org/wiki/System_Integrity_Protection)
			* [About System Integrity Protection on your Mac - support.apple.com](https://support.apple.com/en-us/HT204899)
			* [Configuring System Integrity Protection - developer.apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html#//apple_ref/doc/uid/TP40016462-CH5-SW1)
		* **Articles/Blogposts/Writeups**
			* [Bypassing Apple's System Integrity Protection - Patrick Wardle](https://objective-see.com/blog/blog_0x14.html)
				* abusing the local upgrade process to bypass SIP]
		* **Talks/Presentations/Videos**
			* [Bad Things in Small Packages - Jaron Bradley](https://www.youtube.com/watch?v=5nOxznrOK48&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=5)
    			* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Bradley.pdf)
   				* This talk will primarily focus on the work that went into discovering CVE-2019-8561. The vulnerability exists within PackageKit that could lead to privilege escalation, signature bypassing, and ultimately the bypassing of Apple's System Integrity Protection (SIP). This vulnerability was patched in macOS 10.14.4, but the details behind this exploit have not been documented anywhere prior to this conference! 
	* **XProtect**<a name="xprotect"></a>
		* **101**
			* [XProtect Explained: How Your Mac’s Built-in Anti-malware Software Works - Chris Hoffman(2015)](https://www.howtogeek.com/217043/xprotect-explained-how-your-macs-built-in-anti-malware-works/)
			* [How the “antimalware” XProtect for MacOS works and why it detects poorly and badly - ElevenPaths(2019)](https://business.blogthinkbig.com/antimalware-xprotect-macos/)
		* **Articles/Blogposts/Writeups**
			* [How To Bypass XProtect on Catalina - Phil Stokes](https://www.sentinelone.com/blog/macos-malware-researchers-how-to-bypass-xprotect-on-catalina/)
			* [XProtect](https://github.com/knightsc/XProtect)
				* This repo contains historical releases of the XProtect configuration data.
* **Credential Access**<a name="osxcredac"></a>
	* **Cracking Password Hashes**
		* **Articles/Blogposts/Writeups**
			* [How to extract hashes and crack Mac OS X Passwords - onlinehashcrack.com](https://www.onlinehashcrack.com/how-to-extract-hashes-crack-mac-osx-passwords.php)
			* [How to Hack a Mac Password Without Changing It - Tokyoneon](https://null-byte.wonderhowto.com/how-to/hacking-macos-hack-mac-password-without-changing-0189001/)
			* [Mac OSX Password Cracking - mcontino(2017)](http://hackersvanguard.com/mac-osx-password-cracking/)
			* [What type of hash are a Mac's password stored in? - AskDifferent](https://apple.stackexchange.com/questions/220729/what-type-of-hash-are-a-macs-password-stored-in)
				* Check the first answer
			* [Cracking Mac OS Lion Passwords - frameloss.org(2011)](https://www.frameloss.org/2011/09/05/cracking-macos-lion-passwords/)
		* **Tools**	
			* [DaveGrohl 3.01 alpha](https://github.com/octomagon/davegrohl)
				* A Password Cracker for OS X
	* **Bash History**
		* **Articles/Blogposts/Writeups**
	* **Brute Force**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Credential Dumping**
		* **Articles/Blogposts/Writeups**
			* [Getting What You’re Entitled To: A Journey Into MacOS Stored Credentials - MDSec(2020)](https://www.mdsec.co.uk/2020/02/getting-what-youre-entitled-to-a-journey-in-to-macos-stored-credentials/)
				* In this blog post we will explore how an operator can gain access to credentials stored within MacOS third party apps by abusing surrogate applications for code injection, including a case study of Microsoft Remote Desktop and Google Drive.
			* [Bypassing MacOS Privacy Controls - Adam Chester(2020)](https://blog.xpnsec.com/bypassing-macos-privacy-controls/)
		* **Talks/Presentations/Videos**
		* **Tools**
	* **Credentials from Web Browsers**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**
		* **Tools**
	* **Credentials in Files**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**		
		* **Tools**
	* **Exploitation for Credential Access**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**		
		* **Tools**
	* **Input Capture**
		* **Articles/Blogposts/Writeups**
			* [How to Dump 1Password, KeePassX & LastPass Passwords in Plaintext - Tokyoneon](https://null-byte.wonderhowto.com/how-to/hacking-macos-dump-1password-keepassx-lastpass-passwords-plaintext-0198550/)
			* [Fun With Frida - James(2019)](https://web.archive.org/web/20190622025723/https://medium.com/@two06/fun-with-frida-5d0f55dd331a)
	* In this post, we’re going to take a quick look at Frida and use it to steal credentials from KeePass.
		* **Talks/Presentations/Videos**
		* **Tools**
			* [kcap](https://github.com/scriptjunkie/kcap)
				* This program simply uses screen captures and programmatically generated key and mouse events to locally and graphically man-in-the-middle an OS X password prompt to escalate privileges.
	* **Input Prompt**
		* **Articles/Blogposts/Writeups**
			* [osascript: for local phishing - fuzzynop](https://fuzzynop.blogspot.com/2014/10/osascript-for-local-phishing.html)
		* **Talks/Presentations/Videos**		
		* **Tools**
			* [Empire propmt.py](https://github.com/BC-SECURITY/Empire/blob/master/lib/modules/python/collection/osx/prompt.py)
			* [FiveOnceinYourlife](https://github.com/fuzzynop/FiveOnceInYourLife)
				* Local osx dialog box phishing using osascript. Easier than keylogging on osx. Simply ask for the passwords you want.
	* **Keychain**
		* **Articles/Blogposts/Writeups**
			* [Keychain Services - developer.apple.com](https://developer.apple.com/documentation/security/keychain_services)
			* [Security Flaw in OS X displays all keychain passwords in plain text - Brenton Henry(2016)](https://medium.com/@brentonhenry/security-flaw-in-os-x-displays-all-keychain-passwords-in-plain-text-a530b246e960)
	    		* There is a method in OS X that will allow any user to export your keychain, without sudo privileges or any system dialogs, to a text file, with the username and passwords displayed in plain text. As of this writing(2016), this method works in at least 10.10 and 10.11.5, and presumably at the least all iterations in between.
			* [Stealing macOS apps' Keychain entries - Wojciech Reguła(2020)](https://wojciechregula.blog/post/stealing-macos-apps-keychain-entries/)
		* **Talks/Presentations/Videos**
			* [OBTS v2.0 "KeySteal: A Vulnerability in Apple's Keychain" (Linus Henze)](https://www.youtube.com/watch?v=wPd6rMk8-gg&list=PLliknDIoYszvTDaWyTh6SYiTccmwOsws8&index=9)
    			* [Slides](https://objectivebythesea.com/v2/talks/OBTS_v2_Henze.pdf)
    			* What do your iCloud, Slack, MS Office, etc. credentials have in common? Correct, they're all stored inside your Mac's Keychain. While the Keychain is great because it prevents all those annoying password prompts from disturbing you, the ultimate question is: Is it really safe? Does it prevent malicious Apps from stealing all my passwords?In this talk I will try to answer those questions, showing you how the Keychain works and how it can be exploited by showing you the full details of my KeySteal exploit for the first time. The complete exploit code will be available online after the talk.
		* **Tools**
			* [Mac OS X Keychain Forensic Tool](https://github.com/n0fate/chainbreaker)
				* The chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner. Master Key candidates can be extracted from volafox or volatility keychaindump module. Supports: Snow Leopard, Lion, Mountain Lion, Mavericks, Yosemite, El Capitan, (High) Sierra. This branch contains a quick patch for chainbreaker to dump non-exportable keys on High Sierra, see README-keydump.txt for more details.
			* [KeySteal](https://github.com/LinusHenze/Keysteal)
				* KeySteal is a macOS <= 10.14.3 Keychain exploit that allows you to access passwords inside the Keychain without a user prompt. The vulnerability has been assigned CVE-2019-8526 number.
			* [OSX Key Chain Dumper](https://github.com/lancerushing/osx-keychain-dumper)
				* 'Scripts to dump the values out of OSX Keychain. Tested on OS X El Capitan ver 10.11.6'
			* [keychaindump(2015)](https://github.com/x43x61x69/Keychain-Dump)
				* Keychaindump is a proof-of-concept tool for reading OS X keychain passwords as root. It hunts for unlocked keychain master keys located in the memory space of the securityd process, and uses them to decrypt keychain files.
			* [osx-hash-dumper](https://github.com/cedowens/osx-hash-dumper)
				* Bash script to dump OSX user hashes in crackable format. Author: Cedric Owens
			* [retrieve-osxhash.py](https://github.com/highmeh/pentest_scripts/blob/master/retrieve-osxhash.py)
			* [Chainbreaker2 - Luke Gaddie](https://github.com/gaddie-3/chainbreaker)
	* **Network Sniffing**
		* **Articles/Blogposts/Writeups**
		* **Talks/Presentations/Videos**		
		* **Tools**	
	* **Private Keys**
		* **Articles/Blogposts/Writeups**
	* **Securityd Memory**
		* **Articles/Blogposts/Writeups**			
		* **Tools**
	* **Steal Web Session Cookie**
		* **Articles/Blogposts/Writeups**
		* **Tools**
	* **Two-Factor Authentication Interception**
		* **Articles/Blogposts/Writeups**
		* **Tools**
* **Discovery**<a name="osxdisco"></a>
	* [Mac Quarantine Event Database - menial.co.uk(2011)](http://menial.co.uk/blog/2011/06/16/mac-quarantine-event-database/)
		* After all the fuss surrounding the iPhone location log, you may be interested to know that there is a file on Macs running Snow Leopard or higher that keeps a record of files you've downloaded. This record is not purged when you clear Safari downloads, caches or even reset Safari completely.
	* **General/Unsorted**
		* [A Brief Look At macOS Detections and Post Infection Analysis - Cedric Owens(2019)](https://medium.com/red-teaming-with-a-blue-team-mentaility/a-brief-look-at-macos-detections-and-post-infection-analysis-b0ede7ecfeb9)
		* [Low-Level Process Hunting on macos - themittenmac](https://themittenmac.com/low-level-process-hunting-on-macos/)
		* [Leveraging OSQuery for macOS Post-Exploitation - Cedric Owens(2020)](https://medium.com/red-teaming-with-a-blue-team-mentaility/leveraging-osquery-for-macos-post-exploitation-cff0e735643b)
		* [Leveraging OSQuery for macOS Post-Exploitation - Cedric Owens(2020)](https://medium.com/red-teaming-with-a-blue-team-mentaility/leveraging-osquery-for-macos-post-exploitation-cff0e735643b)
	* **Process Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
			* [Kemon](https://github.com/didi/kemon)
				* An Open-Source Pre and Post Callback-Based Framework for macOS Kernel Monitoring. 
			* [Sinter](https://github.com/trailofbits/sinter)
				* Sinter is a 100% user-mode endpoint security agent for macOS 10.15 and above, written in Swift.  Sinter uses the user-mode EndpointSecurity API to subscribe to and receive authorization callbacks from the macOS kernel, for a set of security-relevant event types. The current version of Sinter supports allowing/denying process executions; in future versions we intend to support other types of events such as file, socket, and kernel events.
	* **Remote System Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Security Software Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
			* [AV_Enum_JXA](https://github.com/cedowens/AV_Enum_JXA)
				* JXA code to enumerate security software on a macOS host
	* **Software Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **System Information Discovery**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
			* [SwiftBelt](https://github.com/cedowens/SwiftBelt)
				* SwiftBelt is a macOS enumerator inspired by @harmjoy's Windows-based Seatbelt enumeration tool. SwiftBelt does not utilize any command line utilities and instead uses Swift code (leveraging the Cocoa Framework, Foundation libraries, OSAKit libraries, etc.) to perform system enumeration. This can be leveraged on the offensive side to perform enumeration once you gain access to a macOS host. I intentionally did not include any functions that cause pop-ups (ex: keychain enumeration).
			* [HealthInspector](https://github.com/its-a-feature/HealthInspector)
				* JXA situational awareness helper by simply reading specific files on a filesystem
	* **Tools**
    	* [forgetmenot](https://github.com/eavalenzuela/forgetmenot)
        	* local looting script in python
		* [APOLLO - Apple Pattern of Life Lazy Output'er](https://github.com/mac4n6/APOLLO)
			* APOLLO stands for Apple Pattern of Life Lazy Output’er. I wanted to create this tool to be able to easily correlate multiple databases with hundreds of thousands of records into a timeline that would make the analyst (me, mostly) be able to tell what has happened on the device. iOS (and MacOS) have these absolutely fantastic databases that I’ve been using for years with my own personal collection of SQL queries to do what I need to get done. This is also a way for me to share my own research and queries with the community. Many of these queries have taken hours, even days to research and compile into something useful. My goal with this script is to put the analysis function the SQL query itself. Each query will output a different part of the puzzle. The script itself just compiles the data into a CSV or SQLite database for viewing and filtering. While this database/spreadsheet can get very large, it is still more efficient that running queries on multiple databases and compiling the data into a timeline manually.	
* **Lateral Movement**<a name="osxlat"></a>
	* **AppleScript**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Application Deployment Software**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Exploitation of Remote Services**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Internal Spearphishing**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Logon Scripts**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Remote File Copy**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **Remote Services**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
	* **SSH Hijacking**
		* **Articles/Blogposts/Writeups**
			* [Interacting with MacOS terminal windows for lateral movement - Steve Borosh](https://medium.com/rvrsh3ll/interacting-with-macos-terminal-windows-for-lateral-movement-ec8710413e29)
		* **Tools**	
	* **Third-party Software**
		* **Articles/Blogposts/Writeups**
		* **Tools**	
* **Collection**<a name="osxcollect"></a>
	* **101**
	* **Articles/Blogposts/Writeups**
		* [Breaking macOS Mojave Beta: does apple adequately protect the webcam and mic? ...no - Patrick Wardle(2018)](https://objective-see.com/blog/blog_0x2F.html)
	* **Audio Capture**
	* **Automated Collection**
	* **Browser-Data**
		* **Articles/Blogposts/Writeups**
		* **Tools**
			* [Chlonium](https://github.com/rxwx/chlonium)
				* Chlonium is an application designed for cloning Chromium Cookies.
	* **Clipboard Data**
	* **Data from Information Repositories**
	* **Data from Local System**
		* **Articles/Blogposts/Writeups**
			* [Stealing local files using Safari Web Share API - Pawel Wylecial(2020)](https://blog.redteam.pl/2020/08/stealing-local-files-using-safari-web.html)
		* **Tools**
			* [PICT - Post-Infection Collection Toolkit](https://github.com/thomasareed/pict)
				* This set of scripts is designed to collect a variety of data from an endpoint thought to be infected, to facilitate the incident response process. This data should not be considered to be a full forensic data collection, but does capture a lot of useful forensic information.
			* [PICT-Swift (Post Infection Collection Toolkit)](https://github.com/cedowens/PICT-Swift/tree/master/pict-Swift)
				* This is a Swift (and slightly modified) version of Thomas Reed's PICT (Post Infection Collection Toolkit: https://github.com/thomasareed/pict). Thomas Reed is the brains behind the awesome PICT concept. I just simply wrote a Swift version of it and added an additional collector.
			* [macOS-browserhist-parser](https://github.com/cedowens/macOS-browserhist-parser)
				* Swift code to parse the quarantine history database, Chrome history database, Safari history database, and Firefox history database on macOS.
	* **Data from Network Shared Drive**
	* **Data from Removable Media**
	* **Data Staged**
	* **Input Capture**
		* **Articles/Blogposts/Writeups**
			* [Using IOHIDManager to Get Modifier Key Events - StackOverflow](https://stackoverflow.com/questions/7190852/using-iohidmanager-to-get-modifier-key-events)
			* [OSX HID Filter for Secondary Keyboard? - StackOverflow](https://stackoverflow.com/questions/8676135/osx-hid-filter-for-secondary-keyboard)
		* **Tools**
			* [SwiftSpy](https://github.com/slyd0g/SwiftSpy)
				* macOS keylogger, clipboard monitor, and screenshotter written in Swift
			* [Swift-Keylogger](https://github.com/SkrewEverything/Swift-Keylogger)
				*  Keylogger for mac written in Swift using HID
	* **Screen Capture**
		* **Articles/Blogposts/Writeups**
			* [Programmatically Screenshot 

	Swift 3, macOS - StackOverflow](https://stackoverflow.com/questions/39691106/programmatically-screenshot-swift-3-macos)
		* **Tools**
	* **Video Capture**
* **MacOS Red Teaming Blogpost Series by Action Dan(2019)**
	* [MacOS Red Teaming 201: Introduction - Action Dan](https://lockboxx.blogspot.com/2019/03/macos-red-teaming-201-introduction.html)
	* [MacOS Red Teaming 202: Profiles - Action Dan](https://lockboxx.blogspot.com/2019/03/macos-red-teaming-202-profiles.html)
	* [MacOS Red Teaming 203: MDM (Mobile Device Managment - Action Dan)](https://lockboxx.blogspot.com/2019/04/macos-red-teaming-203-mdm-mobile-device.html)
	* [MacOS Red Teaming 204: Munki Business - Action Dan](https://lockboxx.blogspot.com/2019/04/macos-red-teaming-204-munki-business.html)
	* [MacOS Red Teaming 205: TCC (Transparency, Consent, and Control - Action Dan)](https://lockboxx.blogspot.com/2019/04/macos-red-teaming-205-tcc-transparency.html)
	* [MacOS Red Teaming 206: ARD (Apple Remote Desktop Protocol - Action Dan)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
	* [MacOS Red Teaming 207: Remote Apple Events (RAE) - Action Dan](https://lockboxx.blogspot.com/2019/08/macos-red-teaming-207-remote-apple.html)
	* [MacOS Red Teaming 208: macOS ATT&CK Techniques - Action Dan](https://lockboxx.blogspot.com/2019/09/macos-red-teaming-208-macos-att.html)
	* [MacOS Red Teaming 209: macOS Frameworks for Command and Control - Action Dan](https://lockboxx.blogspot.com/2019/09/macos-red-teaming-209-macos-frameworks.html)
	* [MacOS Red Teaming 210: Abusing Pkgs for Privilege Escalation - Action Dan](https://lockboxx.blogspot.com/2019/10/macos-red-teaming-210-abusing-pkgs-for.html)
	* [MacOS Red Teaming 211: Dylib Hijacking - Action Dan](https://lockboxx.blogspot.com/2019/10/macos-red-teaming-211-dylib-hijacking.html)
-----------------------------------------------------------------------------------------------------------------------------------











------------------------------------------------------------------------------------------------------------------------------------
#### macOS Technologies<a name="osxtech"></a>
* **Code Signing**<a name="osxsign"></a>
	* [macOS Code Signing In Depth](https://developer.apple.com/library/content/technotes/tn2206/_index.html)
	* [Launch Service Keys - `LSFileQuarantineEnabled`](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/LaunchServicesKeys.html#//apple_ref/doc/uid/TP40009250-SW10)
* **Endpoint Security Framework**<a name="osxesf"></a>
	* [EndpointSecurity - developer.apple](https://developer.apple.com/documentation/endpointsecurity)
		* Endpoint Security is a C API for monitoring system events for potentially malicious activity. Your client, which you can write in any language supporting native calls, registers with Endpoint Security to authorize pending events, or receive notifications of events that have already occurred. These events include process executions, mounting file systems, forking processes, and raising signals. Develop your system extension with Endpoint Security and package it in an app that uses the SystemExtensions framework to install and upgrade the extension on the user’s Mac.
* **GateKeeper**<a name="osxgk"></a>
	* [App security overview - support.apple](https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/1/web/1)
	* [Protecting against malware - support.apple](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/1/web/1)
	* [Gatekeeper and runtime protection - support.apple](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/1/web/1)
	* [Gatekeeper - Wikipedia](https://en.wikipedia.org/wiki/Gatekeeper_(macOS))
    	* 'macOS includes a technology called Gatekeeper, that's designed to ensure that only trusted software runs on your Mac.'
	* [Safely open apps on your Mac - support.apple](https://support.apple.com/en-us/HT202491)
* **Mach-O Binaries**<a name="macho"></a>
	* **101**
* **System Integrity Protection**<a name="osxsip"></a>
	* [System Integrity Protection - Wikipedia](https://en.wikipedia.org/wiki/System_Integrity_Protection)
	* [About System Integrity Protection on your Mac - support.apple.com](https://support.apple.com/en-us/HT204899)
	* [Configuring System Integrity Protection - developer.apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html#//apple_ref/doc/uid/TP40016462-CH5-SW1)
* **Transparency, Consent, and Control**<a name="osxtcc"></a>
	* []()
* **XProtect**<a name="osxxprotect"></a>
	* [XProtect Explained: How Your Mac’s Built-in Anti-malware Software Works - Chris Hoffman(2015)](https://www.howtogeek.com/217043/xprotect-explained-how-your-macs-built-in-anti-malware-works/)
	* [How the “antimalware” XProtect for MacOS works and why it detects poorly and badly - ElevenPaths(2019)](https://business.blogthinkbig.com/antimalware-xprotect-macos/)
-----------------------------------------------------------------------------------------------------------------------------------






































-----------------------------------------------------------------------------------------------------------------------------------
### <a name="mict"></a>macOS Code Injection
* **101**
* **General Information**
* **Articles/Blogposts/Writeups**
* **Techniques**
-----------------------------------------------------------------------------------------------------------------------------------