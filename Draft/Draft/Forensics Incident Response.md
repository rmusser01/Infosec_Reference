##Forensics & Incident Response


applexaminer.com


[Firmware Forensics: Diffs, Timelines, ELFs and Backdoors](http://w00tsec.blogspot.com/2015/02/firmware-forensics-diffs-timelines-elfs.html)




###Anti-Forensics


Secure Deletion of Data from Magnetic and Solid-State Memory
http://static.usenix.org/publications/library/proceedings/sec96/full_papers/gutmann/index.html





###Mobile Device Forensics
####Android Forensics
[Android Forensics class - OpenSecurity Training](http://opensecuritytraining.info/AndroidForensics.html)
* This class serves as a foundation for mobile digital forensics, forensics of Android operating systems, and penetration testing of Android applications. 

[Androick](https://github.com/Flo354/Androick)
* Androick is a python tool to help in forensics analysis on android. Put the package name, some options and the program will download automatically apk, datas, files permissions, manifest, databases and logs. It is easy to use and avoid all repetitive tasks!


####iOS Forensics

http://www.forensicswiki.org/wiki/Apple_iPhone

http://www.iosresearch.org/

[iOSForensic](https://github.com/Flo354/iOSForensic)
* iosForensic is a python tool to help in forensics analysis on iOS. It get files, logs, extract sqlite3 databases and uncompress .plist files in xml.


[iOS Forensics Analyis(2012) SANS Whitepaper](https://www.sans.org/reading-room/whitepapers/forensics/forensic-analysis-ios-devices-34092)


[iOS Forensic Investigative Methods Guide](http://www.zdziarski.com/blog/wp-content/uploads/2013/05/iOS-Forensic-Investigative-Methods.pdf)




###PDF Forensics

http://countuponsecurity.com/2014/09/22/malicious-documents-pdf-analysis-in-5-steps/


###Photo Forensics





[jhead](http://www.sentex.net/~mwandel/jhead/)
* Exif Jpeg header manipulation tool


###Tools:

Ghiro 




[StegExpose](https://github.com/b3dk7/StegExpose)
* StegExpose is a steganalysis tool specialized in detecting LSB (least significant bit) steganography in lossless images such as PNG and BMP. It has a command line interface and is designed to analyse images in bulk while providing reporting capabilities and customization which is comprehensible for non forensic experts. StegExpose rating algorithm is derived from an intelligent and thoroughly tested combination of pre-existing pixel based staganalysis methods including Sample Pairs by Dumitrescu (2003), RS Analysis by Fridrich (2001), Chi Square Attack by Westfeld (2000) and Primary Sets by Dumitrescu (2002). In addition to detecting the presence of steganography, StegExpose also features the quantitative steganalysis (determining the length of the hidden message). StegExpose is part of my MSc of a project at the School of Computing of the University of Kent, in Canterbury, UK.




###Windows Forensics


[Collection of Windows Autostart locations](http://gladiator-antivirus.com/forum/index.php?showtopic=24610)


[Techniques for fast windows forensics investigations](https://www.youtube.com/watch?v=eI4ceLgO_CE)
* Look at sniper forensics, skip around, 18min has resources you want to grab for snapshots



###OS X Forensics Tools

https://github.com/jipegit/OSXAuditor
OS X Auditor is a free Mac OS X computer forensics tool.
OS X Auditor parses and hashes the following artifacts on the running system or a copy of a system you want to analyze: 
the kernel extensions
the system agents and daemons
the third party's agents and daemons
the old and deprecated system and third party's startup items
the users' agents
the users' downloaded files
the installed applications
It extracts: 
the users' quarantined files
the users' Safari history, downloads, topsites, LastSession, HTML5 databases and localstore
the users' Firefox cookies, downloads, formhistory, permissions, places and signons
the users' Chrome history and archives history, cookies, login data, top sites, web data, HTML5 databases and local storage
the users' social and email accounts
the WiFi access points the audited system has been connected to (and tries to geolocate them)
It also looks for suspicious keywords in the .plist themselves. 
It can verify the reputation of each file on: 
Team Cymru's MHR
VirusTotal
Malware.lu
your own local database
It can aggregate all logs from the following directories into a zipball: 
/var/log (-> /private/var/log)
/Library/logs
the user's ~/Library/logs
Finally, the results can be: 
rendered as a simple txt log file (so you can cat-pipe-grep in them… or just grep)
rendered as a HTML log file
sent to a Syslog server



















