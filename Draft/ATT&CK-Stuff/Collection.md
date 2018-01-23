# Collection



* [MITRE ATT&CK - Collection](https://attack.mitre.org/wiki/Collection)
	* Collection consists of techniques used to identify and gather information, such as sensitive files, from a target network prior to exfiltration. This category also covers locations on a system or network where the adversary may look for information to exfiltrate. 


-------------------------------
## Audio Capture
* [Audio Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1123)
	* An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information. 
	* Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later. 

#### Windows
* [Audio Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1123)
	* An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information. 
* [The forgotten spying feature: Metasploit's Mic Recording Command - Rapid7](https://blog.rapid7.com/2013/01/23/the-forgotten-spying-feature-metasploits-mic-recording-command/)
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)
* [Get-MicrophoneAudio.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Exfiltration/Get-MicrophoneAudio.ps1)



-------------------------------
## Automated Collection
* [Automated Collection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1119)
	* Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of Scripting to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. This technique may incorporate use of other techniques such as File and Directory Discovery and Remote File Copy to identify and move files.

#### Linux
* [LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
	* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.

#### Mac
* [Lazagne](https://github.com/AlessandroZ/LaZagne)
	* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.

#### Windows
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


-------------------------------
## Browser Extensions
* [Browser Extensions - ATT&CK](https://attack.mitre.org/wiki/Technique/T1176)
	* Browser extensions or plugins are small programs that can add functionality and customize aspects of internet browsers. They can be installed directly or through a browser's app store. Extensions generally have access and permissions to everything that the browser can access.12 


-------------------------------
## Clipboard Data
* [Clipboard Data - ATT&CK](https://attack.mitre.org/wiki/Technique/T1115)
	* Adversaries may collect data stored in the Windows clipboard from users copying information within or between applications. 

#### Windows
* [About the Clipboard - msdn](https://msdn.microsoft.com/en-us/library/ms649012)
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)
* [clipboard.rb - metasploit](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/post/meterpreter/ui/console/command_dispatcher/extapi/clipboard.rb)

#### Linux
* [Access Unix Clipboard - StackOverflow](https://unix.stackexchange.com/questions/44204/access-unix-clipboard)
* If xclip is available: [Accessing clipboard in Linux terminal](http://www.nurkiewicz.com/2012/09/accessing-clipboard-in-linux-terminal.html)

#### Mac
* OSX provides a native command, pbpaste, to grab clipboard contents
* [pbcopy & pbpaste: Manipulating the Clipboard from the Command Line](http://osxdaily.com/2007/03/05/manipulating-the-clipboard-from-the-command-line/)



-------------------------------
## Data Staged 
* [Data Staged - ATT&CK](https://attack.mitre.org/wiki/Technique/T1074)
	* Collected data is staged in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Data Compressed or Data Encrypted. Interactive command shells may be used, and common functionality within cmd and bash may be used to copy data into a staging location.




-------------------------------
## Data from Local System
* [Data from Local System - ATT&CK](https://attack.mitre.org/wiki/Technique/T1005)
	* Sensitive data can be collected from local system sources, such as the file system or databases of information residing on the system prior to Exfiltration. Adversaries will often search the file system on computers they have compromised to find files of interest. They may do this using a Command-Line Interface, such as cmd, which has functionality to interact with the file system to gather information. Some adversaries may also use Automated Collection on the local system.

#### Windows
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






-------------------------------
## Data from Network Shared Drive
* [Data from Network Shared Drive - ATT&CK](https://attack.mitre.org/wiki/Technique/T1039)
	* Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Adversaries may search network shares on computers they have compromised to find files of interest. Interactive command shells may be in use, and common functionality within cmd may be used to gather information.

#### Windows





-------------------------------
## Data from Removable Media
* [Data from Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1025)
	* Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Adversaries may search connected removable media on computers they have compromised to find files of interest. Interactive command shells may be in use, and common functionality within cmd may be used to gather information. Some adversaries may also use Automated Collection on removable media.

#### Linux
#### OS X
#### Windows





-------------------------------
## Email Collection
* [Email Collection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1114)
	* Adversaries may target user email to collect sensitive information from a target. 
	* Files containing email data can be acquired from a user's system, such as Outlook storage or cache files .pst and .ost. 
	* Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. 
	* Some adversaries may acquire user credentials and access externally facing webmail applications, such as Outlook Web Access.

#### Windows
* [Pillaging .pst Files](https://warroom.securestate.com/pillaging-pst-files/)
* [Pillage Exchange](https://warroom.securestate.com/pillage-exchange/)




-------------------------------
## Input Capture
* [Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
	* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception. 
	* Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes,Adventures of a Keystroke but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider.Wrightson 2012 
	* Keylogging is likely to be used to acquire credentials for new access opportunities when Credential Dumping efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises. 
	*  Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through External Remote Services and Valid Accounts or as part of the initial compromise by exploitation of the externally facing web service.Volexity Virtual Private Keylogging

#### Linux
* [How to Monitor Keyboard Keystrokes Using ‘LogKeys’ in Linux](https://www.tecmint.com/how-to-monitor-keyboard-keystrokes-using-logkeys-in-linux/)
* [logkeys - a GNU/Linux keylogger](https://github.com/kernc/logkeys)
	* logkeys is a linux keylogger. It is no more advanced than other available linux keyloggers, notably lkl and uberkey, but is a bit newer, more up to date, it doesn't unreliably repeat keys and it shouldn't crash your X. All in all, it just seems to work. It relies on event interface of the Linux input subsystem. Once completely set, it logs all common character and function keys, while also being fully aware of Shift and AltGr key modifiers.
* [keysniffer: trace pressed keys in debugfs](http://tuxdiary.com/2015/10/14/keysniffer/)
* [SKeylogger](https://github.com/gsingh93/simple-key-logger)
	* SKeylogger is a simple keylogger. I had previously been using a few other open source keyloggers, but they stopped working when I upgraded my operating system. I tried to look through the code of those keyloggers, but it was undocumented, messy, and complex. I decided to make my own highly documented and very simple keylogger.
* [Using xkeyscan to Parse an X-Based Linux Keylogger](http://porterhau5.com/blog/xkeyscan-parse-linux-keylogger/)

#### Windows
* [Windows Interactive Logon Architecture - technet](https://technet.microsoft.com/en-us/library/ff404303(v=ws.10))
* [The Adventures of a KeyStroke: An in-depth look into Keyloggers on Windows](http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf)
* [Capturing Windows 7 Credentials at Logon Using Custom Credential Provider](https://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/)
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)


## Man in the Browser
* [Man in the Browser - ATT&CK](https://attack.mitre.org/wiki/Technique/T1185)
	* Adversaries can take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify behavior, and intercept information as part of various man in the browser techniques.1
	* A specific example is when an adversary injects software into a browser that allows an them to inherit cookies, HTTP sessions, and SSL client certificates of a user and use the browser as a way to pivot into an authenticated intranet.23
	* Browser pivoting requires the SeDebugPrivilege and a high-integrity process to execute. Browser traffic is pivoted from the adversary's browser through the user's browser by setting up an HTTP proxy which will redirect any HTTP and HTTPS traffic. This does not alter the user's traffic in any way. The proxy connection is severed as soon as the browser is closed. Whichever browser process the proxy is injected into, the adversary assumes the security context of that process. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly. With these permissions, an adversary could browse to any resource on an intranet that is accessible through the browser and which the browser has sufficient permissions, such as Sharepoint or webmail. Browser pivoting also eliminates the security provided by 2-factor authentication.4 



-------------------------------
## Screen Capture
* [Screen Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1113)
	* Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. 

#### Linux
* MITRE
	* On Linux, there is the native command `xwd`.
* [xwd - Wikipedia](https://en.wikipedia.org/wiki/Xwd)
* [xwd - dump an image of an X window - manpage](https://www.x.org/releases/X11R7.5/doc/man/man1/xwd.1.html)

#### Mac
* MITRE
	* On OSX, the native `command screencapture` is used to capture screenshots. 
* [OSX Backdoor – Camera Control](http://patrickmosca.com/osx-backdoor-camera-control/)

#### Windows
* [Using Problem Steps Recorder (PSR) Remotely with Metasploit](https://cyberarms.wordpress.com/2016/02/13/using-problem-steps-recorder-psr-remotely-with-metasploit/)
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)
* [Capturing Screenshots with PowerShell and .NET](https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/)



-------------------------------
## Video Capture
* [Video Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1125)
	* An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files. Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture video or images. Video or image files may be written to disk and exfiltrated later. This technique differs from Screen Capture due to use of specific devices or applications for video recording rather than capturing the victim's screen.
	
#### Windows
* [Meterpreter basic commands](https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/)
	* Note the webcam commands
* [Collection - Empire](http://www.powershellempire.com/?page_id=283)