# Windows Collection







## Audio Capture
-------------------------------
#### Windows
* [Audio Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1123)
	* An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information. 
* [The forgotten spying feature: Metasploit's Mic Recording Command - Rapid7](https://blog.rapid7.com/2013/01/23/the-forgotten-spying-feature-metasploits-mic-recording-command/)
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)
* [Get-MicrophoneAudio.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Exfiltration/Get-MicrophoneAudio.ps1)




## Automated Collection
-------------------------------
#### Windows
* [Automated Collection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1119)
	* Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of Scripting to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. 
* [LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
	* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.
* [BrowserGatherer](https://github.com/sekirkity/BrowserGather)
	* Fileless Extraction of Sensitive Browser Information with PowerShell
* [SessionGopher](https://github.com/fireeye/SessionGopher)
	* SessionGopher is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally.
* [KeeFarce](https://github.com/denandz/KeeFarce)
	* Extracts passwords from a KeePass 2.x database, directly from memory.
* [KeeThief](https://github.com/HarmJ0y/KeeThief)
	* Methods for attacking KeePass 2.X databases, including extracting of encryption key material from memory.

#### Linux
* [LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
	* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.

#### Mac
* [Lazagne](https://github.com/AlessandroZ/LaZagne)
	* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.






## Clipboard Data
-------------------------------
#### Windows
* [Clipboard Data - ATT&CK](https://attack.mitre.org/wiki/Technique/T1115)
	* Adversaries may collect data stored in the Windows clipboard from users copying information within or between applications. 
* [About the Clipboard - msdn](https://msdn.microsoft.com/en-us/library/ms649012)
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)
* [clipboard.rb - metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/post/meterpreter/ui/console/command_dispatcher/extapi/clipboard.rb)

#### Linux
* [Access Unix Clipboard - StackOverflow](https://unix.stackexchange.com/questions/44204/access-unix-clipboard)
* If xclip is available: [Accessing clipboard in Linux terminal](http://www.nurkiewicz.com/2012/09/accessing-clipboard-in-linux-terminal.html)

#### Mac
* OSX provides a native command, pbpaste, to grab clipboard contents
* [pbcopy & pbpaste: Manipulating the Clipboard from the Command Line](http://osxdaily.com/2007/03/05/manipulating-the-clipboard-from-the-command-line/)




## Data Staged 
-------------------------------
Windows
* [Data Staged - ATT&CK](https://attack.mitre.org/wiki/Technique/T1074)
	* Collected data is staged in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Data Compressed or Data Encrypted. 





## Data from Local System
-------------------------------
#### Windows
* [Data from Local System - ATT&CK](https://attack.mitre.org/wiki/Technique/T1005)
* [SearchForCC](https://github.com/eelsivart/SearchForCC)
	* A collection of open source/common tools/scripts to perform a system memory dump and/or process memory dump on Windows-based PoS systems and search for unencrypted credit card track data.

#### Linux
* List:
	* /etc/passwd : Contains local Linux users.
	* /etc/shadow : Contains local account password hashes.
	* /etc/group : Contains local account groups.
	* /etc/init.d/ : Contains service init script - worth a look to see whats installed.
	* /etc/hostname : System hostname.
	* /etc/network/interfaces : Network interfaces.
	* /etc/resolv.conf : System DNS servers.
	* /etc/profile : System environment variables.
	* ~/.ssh/ : SSH keys.
	* ~/.bash_history : Users bash history log.
	* /var/log/ : Linux system log files are typically stored here.
	* /var/adm/ : UNIX system log files are typically stored here.
	* /var/log/apache2/access.log & /var/log/httpd/access.log : Apache access log file typical path.
	* /etc/fstab : File system mounts. 
		* [From: highoncoffee](https://highon.coffee/blog/linux-commands-cheat-sheet/#linux-interesting-files--dirs)







## Data from Network Shared Drive
-------------------------------
#### Windows
* [Data from Network Shared Drive - ATT&CK](https://attack.mitre.org/wiki/Technique/T1039)
	* Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. 





## Data from Removable Media
-------------------------------
#### Windows
* [Data from Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1025)






## Email Collection
-------------------------------
#### Windows
* [Email Collection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1114)
	* Adversaries may target user email to collect sensitive information from a target.  Files containing email data can be acquired from a user's system, such as Outlook storage or cache files .pst and .ost.
* [Pillaging .pst Files](https://warroom.securestate.com/pillaging-pst-files/)
* [Pillage Exchange](https://warroom.securestate.com/pillage-exchange/)





## Input Capture
-------------------------------
#### Windows
* [Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
	* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception.
* [Windows Interactive Logon Architecture - technet](https://technet.microsoft.com/en-us/library/ff404303(v=ws.10))
* [The Adventures of a KeyStroke: An in-depth look into Keyloggers on Windows](http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf)
* [Capturing Windows 7 Credentials at Logon Using Custom Credential Provider](https://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/)
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)

#### Linux
* [How to Monitor Keyboard Keystrokes Using ‘LogKeys’ in Linux](https://www.tecmint.com/how-to-monitor-keyboard-keystrokes-using-logkeys-in-linux/)
* [logkeys - a GNU/Linux keylogger](https://github.com/kernc/logkeys)
	* logkeys is a linux keylogger. It is no more advanced than other available linux keyloggers, notably lkl and uberkey, but is a bit newer, more up to date, it doesn't unreliably repeat keys and it shouldn't crash your X. All in all, it just seems to work. It relies on event interface of the Linux input subsystem. Once completely set, it logs all common character and function keys, while also being fully aware of Shift and AltGr key modifiers.
* [keysniffer: trace pressed keys in debugfs](http://tuxdiary.com/2015/10/14/keysniffer/)
* [SKeylogger](https://github.com/gsingh93/simple-key-logger)
	* SKeylogger is a simple keylogger. I had previously been using a few other open source keyloggers, but they stopped working when I upgraded my operating system. I tried to look through the code of those keyloggers, but it was undocumented, messy, and complex. I decided to make my own highly documented and very simple keylogger.
* [Using xkeyscan to Parse an X-Based Linux Keylogger](http://porterhau5.com/blog/xkeyscan-parse-linux-keylogger/)





## Screen Capture
-------------------------------
#### Windows
* [Screen Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1113)
	* Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. 
* [Using Problem Steps Recorder (PSR) Remotely with Metasploit](https://cyberarms.wordpress.com/2016/02/13/using-problem-steps-recorder-psr-remotely-with-metasploit/)
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)
* [Capturing Screenshots with PowerShell and .NET](https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/)

#### Linux
* On Linux, there is the native command xwd.
* [xwd - Wikipedia](https://en.wikipedia.org/wiki/Xwd)
* [xwd - dump an image of an X window - manpage](https://www.x.org/releases/X11R7.5/doc/man/man1/xwd.1.html)


#### Mac
* [OSX Backdoor – Camera Control](http://patrickmosca.com/osx-backdoor-camera-control/)




## Video Capture
-------------------------------
#### Windows
* [Video Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1125)
	* An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files. 
* [Meterpreter basic commands](https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/)
	* Note the webcam commands
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)