## Mac Defense Evasion



------------------------------- 
## Binary Padding
* [Binary Padding - ATT&CK](https://attack.mitre.org/wiki/Technique/T1009)
	* Some security tools inspect files with static signatures to determine if they are known malicious. Adversaries may add data to files to increase the size beyond what security tools are capable of handling or to change the file hash to avoid hash-based blacklists. 




------------------------------- 
## Clear Command History
* [Clear Command History - ATT&CK](https://attack.mitre.org/wiki/Technique/T1146)
	* macOS and Linux both keep track of the commands users type in their terminal so that users can easily remember what they've done. These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable HISTFILE. When a user logs off a system, this information is flushed to a file in the user's home directory called ~/.bash_history. The benefit of this is that it allows users to go back to commands they've used before in different sessions. Since everything typed on the command-line is saved, passwords passed in on the command line are also saved. Adversaries can abuse this by searching these files for cleartext passwords. Additionally, adversaries can use a variety of methods to prevent their own commands from appear in these logs such as unset HISTFILE, export HISTFILESIZE=0, history -c, rm ~/.bash_history. 




------------------------------- 
## Code Signing
* [Code Signing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1116)
	* Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. However, adversaries are known to use code signing certificates to masquerade malware and tools as legitimate binaries. The certificates used during an operation may be created, forged, or stolen by the adversary.34
	* Code signing to verify software on first run can be used on modern Windows and MacOS/OS X systems. It is not used on Linux due to the decentralized nature of the platform.
	* Code signing certificates may be used to bypass security policies that require signed code to execute on a system. 
* [macOS Code Signing In Depth - dev.apple](https://developer.apple.com/library/content/technotes/tn2206/_index.html)
* [High Sierra's 'Secure Kernel Extension Loading' is Broken](https://objective-see.com/blog/blog_0x21.html)


------------------------------- 
## Disabling Security Tools
* [Disabling Security Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1089)
	* Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security scanning or event reporting. 







------------------------------- 
## Exploitation of Vulnerability
* [Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)
	* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.





------------------------------- 
## File Deletion
* [File Deletion - ATT&CK](https://attack.mitre.org/wiki/Technique/T1107)
	* Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
	* There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples include native cmd functions such as DEL, secure deletion tools such as Windows Sysinternals SDelete, or other third-party file deletion tools.





----------------------------- 
## Gatekeeper Bypass
* [Gatekeeper Bypass- ATT&CK](https://attack.mitre.org/wiki/Technique/T1144)
	* In macOS and OS X, when applications or programs are downloaded from the internet, there is a special attribute set on the file called com.apple.quarantine. This attribute is read by Apple's Gatekeeper defense program at execution time and provides a prompt to the user to allow or deny execution.
	* Apps loaded onto the system from USB flash drive, optical disk, external hard drive, or even from a drive shared over the local network won’t set this flag. Additionally, other utilities or events like drive-by downloads don’t necessarily set it either. This completely bypasses the built-in Gatekeeper check1. The presence of the quarantine flag can be checked by the xattr command xattr /path/to/MyApp.app for com.apple.quarantine. Similarly, given sudo access or elevated permission, this attribute can be removed with xattr as well, sudo xattr -r -d com.apple.quarantine /path/to/MyApp.app.
	* In typical operation, a file will be downloaded from the internet and given a quarantine flag before being saved to disk. When the user tries to open the file or application, macOS’s gatekeeper will step in and check for the presence of this flag. If it exists, then macOS will then prompt the user to confirmation that they want to run the program and will even provide the url where the application came from. However, this is all based on the file being downloaded from a quarantine-savvy application . 
* [OS X: About Gatekeeper](https://support.apple.com/en-us/HT202491)
* [Last-minute paper: Exposing Gatekeeper - Patrick Wardle](https://www.virusbulletin.com/conference/vb2015/abstracts/exposing-gatekeeper)
* ['Untranslocating' an App >apple broke some of my apps - let's show how to fix them!](https://objective-see.com/blog/blog_0x15.html)
* [OS X Gatekeeper Bypass Vulnerability - Amplia Security2015](http://www.ampliasecurity.com/advisories/os-x-gatekeeper-bypass-vulnerability.html)


------------------------------- 
## HISTCONTROL
* [HISTCONTROL - ATT&CK](https://attack.mitre.org/wiki/Technique/T1148)
	* The HISTCONTROL environment variable keeps track of what should be saved by the history command and eventually into the ~/.bash_history file when a user logs out. This setting can be configured to ignore commands that start with a space by simply setting it to "ignorespace". HISTCONTROL can also be set to ignore duplicate commands by setting it to "ignoredups". In some Linux systems, this is set by default to "ignoreboth" which covers both of the previous examples. This means that “ ls” will not be saved, but “ls” would be saved by history. HISTCONTROL does not exist by default on macOS, but can be set by the user and will be respected. Adversaries can use this to operate without leaving traces by simply prepending a space to all of their terminal commands. 







------------------------------- 
## Hidden Files and Directories
* [Hidden Files and Directories - ATT&CK](https://attack.mitre.org/wiki/Technique/T1158)
	* To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (dir /a for Windows and ls –a for Linux and macOS). 
* Files and Folders with a `.` in front of them will remain hidden by default; Can use `Shift+CMD+.` to enable/disable.
* [chflags - SS64](https://ss64.com/osx/chflags.html)





------------------------------- 
## Hidden Users
* [Hidden Users - ATT&CK](https://attack.mitre.org/wiki/Technique/T1147)
	* Every user account in macOS has a userID associated with it. When creating a user, you can specify the userID for that account. There is a property value in /Library/Preferences/com.apple.loginwindow called Hide500Users that prevents users with userIDs 500 and lower from appearing at the login screen. By using the Create Account technique with a userID under 500 and enabling this property (setting it to Yes), an adversary can hide their user accounts much more easily: sudo dscl . -create /Users/username UniqueID 401. 
* [Hide a user account in macOS - support.apple](https://support.apple.com/en-us/HT203998)
* [How to add hidden user - StackOverflow](https://apple.stackexchange.com/questions/174433/how-to-add-hidden-user)
* `sudo dscl . create /Users/USERNAME IsHidden 1`




------------------------------- 
## Hidden Window
* [Hidden Window - ATT&CK](https://attack.mitre.org/wiki/Technique/T1143)
	* The configurations for how applications run on macOS and OS X are listed in property list (plist) files. One of the tags in these files can be apple.awt.UIElement, which allows for Java applications to prevent the application's icon from appearing in the Dock. A common use for this is when applications run in the system tray, but don't also want to show up in the Dock. However, adversaries can abuse this feature and hide their running window.












------------------------------- 
## Indicator Removal from Tools
* [Indicator Removal from Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1066)
	* If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.
	* A good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may use Software Packing or otherwise modify the file so it has a different signature, and then re-use the malware. 





------------------------------- 
## Indicator Removal on Host
* [Indicator Removal on Host - ATT&CK](https://attack.mitre.org/wiki/Technique/T1070)
	* Adversaries may delete or alter generated event files on a host system, including potentially captured files such as quarantined malware. This may compromise the integrity of the security solution, causing events to go unreported, or make forensic analysis and incident response more difficult due to lack of sufficient data to determine what occurred. 





------------------------------- 
## LC_MAIN Hijacking
* [LC_MAIN Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1149)
	* As of OS X 10.8, mach-O binaries introduced a new header called LC_MAIN that points to the binary’s entry point for execution. Previously, there were two headers to achieve this same effect: LC_THREAD and LC_UNIXTHREAD. The entry point for a binary can be hijacked so that initial execution flows to a malicious addition (either another section or a code cave) and then goes back to the initial entry point so that the victim doesn’t know anything was different 2. By modifying a binary in this way, application whitelisting can be bypassed because the file name or application path is still the same. 
* [Methods Of Malware Persistence On Mac OS X](https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf)






------------------------------- 
## Launchctl
* [Launchctl - ATT&CK](https://attack.mitre.org/wiki/Technique/T1152)
	* Launchctl controls the macOS launchd process which handles things like launch agents and launch daemons, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input. By loading or reloading launch agents or launch daemons, adversaries can install persistence or execute changes they made 1. Running a command from launchctl is as simple as launchctl submit -l <labelName> -- /Path/to/thing/to/execute "arg" "arg" "arg". Loading, unloading, or reloading launch agents or launch daemons can require elevated privileges. 
* [launchd tutorial](http://www.launchd.info/)
* [Creating Launch Daemons and Agents - developer.apple](https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
* []()








------------------------------- 
## Masquerading
* [Masquerading - ATT&CK](https://attack.mitre.org/wiki/Technique/T1036)
	* Masquerading occurs when an executable, legitimate or malicious, is placed in a commonly trusted location (such as C:\Windows\System32) or named with a common name (such as "explorer.exe" or "svchost.exe") to bypass tools that trust executables by relying on file name or path. An adversary may even use a renamed copy of a legitimate utility, such as rundll32.exe. Masquerading also may be done to deceive defenders and system administrators into thinking a file is benign by associating the name with something that is thought to be legitimate. 
* [Platypus](http://www.sveinbjorn.org/platypus)
	* Platypus is a Mac OS X developer tool that creates native Mac applications from interpreted scripts such as shell scripts or Perl, Ruby and Python programs. This is done by wrapping the script in an application bundle along with a native executable binary that runs the script.






------------------------------- 
## Plist Modification
* [Plist Modification - ATT&CK](https://attack.mitre.org/wiki/Technique/T1150)
	* Property list (plist) files contain all of the information that macOS and OS X uses to configure applications and services. These files are UT-8 encoded and formatted like XML documents via a series of keys surrounded by < >. They detail when programs should execute, file paths to the executables, program arguments, required OS permissions, and many others. plists are located in certain locations depending on their purpose such as /Library/Preferences (which execute with elevated privileges) and ~/Library/Preferences (which execute with a user's privileges). Adversaries can modify these plist files to point to their own code, can use them to execute their code in the context of another user, bypass whitelisting procedures, or even use them as a persistence mechanism1. 






------------------------------ 
## Redundant Access
* [Redundant Access - ATT&CK](https://attack.mitre.org/wiki/Technique/T1108)
	* Adversaries may use more than one remote access tool with varying command and control protocols as a hedge against detection. If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to Valid Accounts to use External Remote Services such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.1 










------------------------------- 
## Scripting
* [Scripting - ATT&CK](https://attack.mitre.org/wiki/Technique/T1064)
	* Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and PowerShell but could also be in the form of command-line batch scripts.
	* Many popular offensive frameworks exist which use forms of scripting for security testers and adversaries alike. Metasploit1, Veil, and PowerSploit are three examples that are popular among penetration testers for exploit and post-compromise operations and include many features for evading defenses. Some adversaries are known to use PowerShell.
* [Introduction to AppleScript Language Guide](https://developer.apple.com/library/content/documentation/AppleScript/Conceptual/AppleScriptLangGuide/introduction/ASLR_intro.html)
* [osascript - SS64](https://ss64.com/osx/osascript.html)


------------------------------- 
## Space after Filename
[Space after Filename - ATT&CK](https://attack.mitre.org/wiki/Technique/T1151)
* Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system. For example, if there is a Mach-O executable file called evil.bin, when it is double clicked by a user, it will launch Terminal.app and execute. If this file is renamed to evil.txt, then when double clicked by a user, it will launch with the default text editing application (not executing the binary). However, if the file is renamed to "evil.txt " (note the space at the end), then when double clicked by a user, the true file type is determined by the OS and handled appropriately and the binary will be executed.







------------------------------- 
## Valid Accounts
* [Valid Accounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)
	* Adversaries may steal the credentials of a specific user or service account using Credential Access techniques. Compromised credentials may be used to bypass access controls placed on various resources on hosts and within the network and may even be used for persistent access to remote systems. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.
	* Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful.
	* The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.
* `dscl . list /Users`


