Attacking Android Devices




#CULL

####[Hacking Your Way Up The Mobile Stack](http://vimeo.com/51270090)
[APKinpsector](https://github.com/honeynet/apkinspector/)
* APKinspector is a powerful GUI tool for analysts to analyze the Android applications. 


[ Inside the Android Play Service's magic OAuth flow ](http://sbktech.blogspot.com/2014/01/inside-android-play-services-magic.html)
* Owning google accounts on android devices
[Manifesto](https://github.com/maldroid/manifesto)
* PoC framework for APK obfuscation, used to demonstrate some of the obfuscation examples from http://maldr0id.blogspot.com. It supports plugins (located in processing directory) that can do different obfuscation techniques. Main gist is that you run manifesto on the APK file and it produces an obfuscated APK file.

[Android Hooker](https://github.com/AndroidHooker/hooker)
* Hooker is an opensource project for dynamic analyses of Android applications. This project provides various tools and applications that can be use to automaticaly intercept and modify any API calls made by a targeted application.


[Dexter](http://dexter.dexlabs.org/accounts/login/?next=/dashboard)
* Dexter is a static android application analysis tool. 

[android-cluster-toolkit](https://github.com/jduck/android-cluster-toolkit)
* The Android Cluster Toolkit helps organize and manipulate a collection of Android devices. It was designed to work with a collection of devices connected to the same host machine, either directly or via one or more tiers of powered USB hubs. The tools within can operate on single devices, a selected subset, or all connected devices at once.

[canhazaxs](https://github.com/jduck/canhazaxs)
* A tool for enumerating the access to entries in the file system of an Android device. 

[android-cluster-toolkit](https://github.com/jduck/android-cluster-toolkit)
* The Android Cluster Toolkit helps organize and manipulate a collection of Android devices. It was designed to work with a collection of devices connected to the same host machine, either directly or via one or more tiers of powered USB hubs. The tools within can operate on single devices, a selected subset, or all connected devices at once.

[APK Studio - Android Reverse Engineering](https://apkstudio.codeplex.com/)
* APK Studio is an IDE for decompiling/editing & then recompiling of android application binaries. Unlike initial release being Windows exclusive & also didn't support frameworks, this one is completely re-written using QT for cross-platform support. You can now have multiple frameworks installed & pick a particular one on a per project basis.

[privmap - android](https://github.com/jduck/privmap)
* A tool for enumerating the effective privileges of processes on an Android device. 






[List of Android Vulnerabilities](http://androidvulnerabilities.org/all)


[List of Android Exploits](https://github.com/droidsec/droidsec.github.io/wiki/Vuln-Exploit-List)



Books
Android hackers handbook








[Rundown of Android Packers](http://www.fortiguard.com/uploads/general/Area41Public.pdf)






Security Analysis

Santoku Linux


Android Tamer
http://androidtamer.com/
Android Tamer is a one stop tool required to perform any kind of operations on Android devices / applications / network
VM

Android Device Testing Framework(DTF)
From: https://github.com/jakev/dtf/tree/v1.0.3

The Android Device Testing Framework ("dtf") is a data collection and analysis framework to help individuals answer the question: "Where are the vulnerabilities on this mobile device?" Dtf provides a modular approach and built-in APIs that allows testers to quickly create scripts to interact with their Android devices. The default download of dtf comes with multiple modules that allow testers to obtain information from their Android device, process this information into databases, and then start searching for vulnerabilities (all without requiring root privileges). These modules help you focus on changes made to AOSP components such as applications, frameworks, system services, as well as lower-level components such as binaries, libraries, and device drivers. In addition, you'll be able to analyze new functionality implemented by the OEMs and other parties to find vulnerabilities.

drozer
From their site: 
drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.
https://github.com/mwrlabs/drozer


APK Studio - Android Reverse Engineering
APK Studio is an IDE for decompiling/editing & then recompiling of android application binaries. Unlike initial release being Windows exclusive & also didn't support frameworks, this one is completely re-written using QT for cross-platform support. You can now have multiple frameworks installed & pick a particular one on a per project basis.
https://apkstudio.codeplex.com/

Application Analysis

Androguard
From their site:
Androguard is mainly a tool written in python to play with: 
Dex/Odex (Dalvik virtual machine) (.dex) (disassemble, decompilation), 
APK (Android application) (.apk), 
Android's binary xml (.xml), 
Android Resources (.arsc). 
Androguard is available for Linux/OSX/Windows (python powered).
https://code.google.com/p/androguard 

Droidmap	
From their site:
DroidBox is developed to offer dynamic analysis of Android applications. The following information is shown in the results, generated when analysis is ended: 
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
		https://code.google.com/p/droidbox/
	

Links:
Security enhancements in android through its versions
	www.androidtamer.com


Attack Platforms

drozer
From their site: 
drozer allows you to search for security vulnerabilities in apps and devices by assuming the role of an app and interacting with the Dalvik VM, other apps' IPC endpoints and the underlying OS.
https://github.com/mwrlabs/drozer








Notes:


Defeating the bootloader
(HTC Devices)
-secuflag - security flag in radio firmware - modify radio

-gold card - specially formatted MicroSD card that can bypass carrier id check when flashing roms

-white card - special sim card used to bypass bootsec
     Emulate white card with hardware, combine with gold card to enter diagnostics and clear S-ON


White card not needd for cdma

Once S-OFF, can RAM load a custom boot iamge

Technique wipes most devices, but not all

Try it yourself: XTC clip


Forensics boot image

-Start early in the boot chain before the main system loads
-Provide ADB root shell over USB
-Do not mount anything, including cache to prevent any writes
-Devices with raw NAND flash and wear leveling implemented in software(YAFFS2) can be prevented from overwriting deleted data

Build boot image

upload adbd, busybox, nanddump to /sbin
default.prop (enable root shell, ro.secure=0)
init.rc (do not mount partitions, just start adb)

Flash and RAM load

Samsung
-Dump partitions using ODIN(maybe. probably not)
-Flash with ODIN or HEIMDALL
     heimdall flash --recovery recovery.bin
     heimdall flash --kernel zImage
HTC
-fastboot boot recovery.img (Ram loading)
-fastboot flash recovery recovery.img (flash partition)

Motorola
-sbf_flash image name.sbf (make sure it only contains recovery)

JTAG
-Flasher Box
     -ORT
     -RiffBox
     -Medusa Box
-Allows you to dump nandflash directly


Some devices have debug access via serial cables
-Use a Bus Pirate and MicroUSB breakout board
     -set bus pirate to 115200 bps, 8-N-1
     -Output type is normal, not open drain
     -Plug in device to MicroUSB and you will see it boot the Primitive Boot Loader followed by the Secondary Boot Loader
     -Hold down enter key on terminal while plugging in device to stop SBL from booting and get to the SBL prompt

Crack Pin/Password
-Salt - stored in /data/data/com.android.providers.settings/databases/settings.db

     -SELECT * FROM secure WHERE name = 'lockscreen.password_salt'

-Pin/Password
     -/data/system/password.key
     -Salted SHA1 of password concatenated with salted MD5

-Calculate the value of the salt in lowercase hex with no padding
$python -c 'print '%x' % salt_number_here'

-Copy the last 32 bytes of password.key(MD5 hash in hex), add a colon and then add the salt

-Crack with software such as oclHashcat

Android Encryption:
Implemented differently by manufacturers

-Encrypted Master key + salt stored in footer
-footer stored at end of partition or in a footer file on another partition or as a partition itself
-Image device and locate footer + encrypted user data partition

-Parse footer
-Locate Salt/master key
-Run a password guess through PBKDF2 with salt, use resulting key and IV to decrypt master key to decrypt first sector of encrypted image, if password is correct, plaintext revealed

-Cracking PINs takes seconds. Passwords are usually short or follow patterns due to being the same as the lock screen password

Evil maid attack
-Load app onto system partition, wait for user to boot phone, get remote access to decrypted user data
-Rootkits - compile kernel module
-Evil usb charger


Desperate Techniques
-Hard reset - some devices prior to 3.0 don't wipe data properly
-Chip-off - de-solder NAND chips
-Screen Smudges

More Techniques
-Custom update.zip - can you get one signed? stock needs sig
-Race condition on updates via SD cards
-Own a CA? MITM connetion, push app, update/exploit
-Entry via Google Play, if credentials cached on desktop
     -Screen Lock bypass - Doesn't work on 4.0 ->

Santoku Linux
-Free/open bootable linux distro
-project is collab with pros
-Mobile Forensics
-Mobile App Sec Testing
-Mobile Malware Analysis






##Securing Your Android Device




[Android (In)Security - Defcamp 2014](https://www.youtube.com/watch?v=2aeV1JXYvuQ&index=23&list=PLnwq8gv9MEKgSryzYIFhpmCcqnVzdUWfH)
* Good video on Android Security



[Android Forensics Class - Free](http://opensecuritytraining.info/AndroidForensics.html)
* This class serves as a foundation for mobile digital forensics, forensics of Android operating systems, and penetration testing of Android applications. 


###Hardening Guides


[Android Hardening Guide by the TOR developers](https://blog.torproject.org/blog/mission-impossible-hardening-android-security-and-privacy	
)
This blog post describes the installation and configuration of a prototype of a secure, full-featured, Android telecommunications device with full Tor support, individual application firewalling, true cell network baseband isolation, and optional ZRTP encrypted voice and video support. ZRTP does run over UDP which is not yet possible to send over Tor, but we are able to send SIP account login and call setup over Tor independently.
The SIP client we recommend also supports dialing normal telephone numbers if you have a SIP gateway that provides trunking service.
Aside from a handful of binary blobs to manage the device firmware and graphics acceleration, the entire system can be assembled (and recompiled) using only FOSS components. However, as an added bonus, we will describe how to handle the Google Play store as well, to mitigate the two infamous Google Play Backdoors.


[Android 4.0+ Hardening Guide/Checklist by University of Texas](https://wikis.utexas.edu/display/ISO/Google+Android+Hardening+Checklist)
	


###Applications

Firewall
	* [Android Firewall(Requires Root)](https://play.google.com/store/apps/details?id=com.jtschohl.androidfirewall&hl=en)
		
Xprivacy - The Ultimate Android Privacy Manager(Requires Root

	* [Github](https://github.com/M66B/XPrivacy)
	* [Google Play](https://play.google.com/store/apps/details?id=biz.bokhorst.xprivacy.installer&hl=en)

Backups
	Titanium Backup
		https://play.google.com/store/apps/details?id=com.keramidas.TitaniumBackup
Personal favorite for making backups. Backups are stored locally or automatically to various cloud services.
	Helium Backup(Root Not Required)
		https://play.google.com/store/apps/details?id=com.koushikdutta.backup&hl=en
		Backs up data locally or to various cloud services. Local client available for backups directly to PC.

Analyzing the Attack Surface of your device

Resources



Encryption
Check the Encryption section of the overall guide for more information.










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

[Upgrading Your Android, Elevating My Malware:
Privilege Escalation Through Mobile OS Updating](http://www.informatics.indiana.edu/xw7/papers/privilegescalationthroughandroidupdating.pdf)


(Exploring Android KitKat Runtime](http://www.haxpo.nl/wp-content/uploads/2014/02/D1T2-State-of-the-Art-Exploring-the-New-Android-KitKat-Runtime.pdf)

[Analyzing Inter-Application Communication in Android](https://www.eecs.berkeley.edu/~daw/papers/intents-mobisys11.pdf)

[Automatically Exploiting Potential Component Leaks in Android Applications](http://orbilu.uni.lu/bitstream/10993/16914/1/tr-pcLeaks.pdf)

[I know what leaked in your pocket: uncovering privacy leaks on Android Apps with Static Taint Analysis](http://arxiv.org/pdf/1404.7431v1.pdf)

[Bifocals: Analyzing WebView Vulnerabilities in Android Applications](http://www.eecs.berkeley.edu/~emc/papers/Chin-WISA-WebViews.pdf)

[Analyzing Android Browser Apps for file:// Vulnerabilities](http://arxiv.org/pdf/1404.4553v3.pdf)


[FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps](http://sseblog.ec-spride.de/wp-content/uploads/2013/05/pldi14submissionFlowdroid.pdf)

[Detecting privacy leaks in Android Apps](https://publications.uni.lu/bitstream/10993/16916/1/ESSoS-DS2014-Li.pdf)

[From Zygote to Morula:
Fortifying Weakened ASLR on Android](http://www.cc.gatech.edu/~blee303/paper/morula.pdf)

[Apposcopy: Semantics-Based Detection of Android Malware through Static Analysis](http://www.cs.utexas.edu/~yufeng/papers/fse14.pdf)

[MAdFraud: Investigating Ad Fraud in Android Applications](http://www.cs.ucdavis.edu/~hchen/paper/mobisys2014.pdf)

[Why Eve and Mallory Love Android: An Analysis of Android SSL (In)Security](http://www2.dcsec.uni-hannover.de/files/android/p50-fahl.pdf)


[AsDroid: Detecting Stealthy Behaviors in Android Applications by User Interface and Program Behavior Contradiction](https://ece.uwaterloo.ca/~lintan/publications/asdroid-icse14.pdf)

[NativeGuard: Protecting Android Applications from Third-Party Native Libraries](http://www.cse.lehigh.edu/~gtan/paper/nativeguard.pdf)

[Into the Droid: Gaining Access to Android User Data - DEFCON](https://www.youtube.com/watch?v=MxhIo95VccI&amp;list=PLCDA5DF85AD6B4ABD)

[Android Packers](http://www.fortiguard.com/uploads/general/Area41Public.pdf)


[Xprivacy Android](https://github.com/M66B/XPrivacy#description)


[An Empirical Study of Cryptographic Misuse
in Android Applications](https://www.cs.ucsb.edu/~chris/research/doc/ccs13_cryptolint.pdf)


Obfuscation in Android malware, and how to fight back
https://www.virusbtn.com/virusbulletin/archive/2014/07/vb201407-Android-obfuscation


###Educational Material



OWASP GoatDroid
From their site: 
“OWASP GoatDroid is a fully functional and self-contained training environment for educating developers and testers on Android security. GoatDroid requires minimal dependencies and is ideal for both Android beginners as well as more advanced users. 
The project currently includes two applications: FourGoats, a location-based social network, and Herd Financial, a mobile banking application. There are also several feature that greatly simplify usage within a training environment or for absolute beginners who want a good introduction to working with the Android platform.”
https://www.owasp.org/index.php/Projects/OWASP_GoatDroid_Project


Insecure Bank v2
Taken from: https://github.com/dineshshetty/Android-InsecureBankv2
This vulnerable Android application is named "InsecureBankv2" and is made for security enthusiasts and developers to learn the Android insecurities by testing this vulnerable application. Its back-end server component is written in python. The client component i.e. the Android InsecureBank.apk can be downloaded along with the source code. 
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




