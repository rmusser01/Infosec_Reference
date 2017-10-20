## Linux Collection


------------------------------- 
## Automated Collection
[Automated Collection - ATT&CK](https://attack.mitre.org/wiki/Technique/T1119)
* Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of Scripting to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. 

[LaZagne](https://github.com/AlessandroZ/LaZagne/blob/master/README.md)
* The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.





------------------------------- 
## Clipboard Data
[Clipboard Data - ATT&CK](https://attack.mitre.org/wiki/Technique/T1115)
* Adversaries may collect data stored in the clipboard from users copying information within or between applications. 

[Access Unix Clipboard - StackOverflow](https://unix.stackexchange.com/questions/44204/access-unix-clipboard)
* If xclip is available: [Accessing clipboard in Linux terminal](http://www.nurkiewicz.com/2012/09/accessing-clipboard-in-linux-terminal.html)



------------------------------- 
## Data Staged
[Data Staged - ATT&CK](https://attack.mitre.org/wiki/Technique/T1074)
* Collected data is staged in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Data Compressed or Data Encrypted. 





------------------------------- 
## Data from Local System
[Data from Local System - ATT&CK](https://attack.mitre.org/wiki/Technique/T1005)
* Sensitive data can be collected from local system sources, such as the file system or databases of information residing on the system prior to Exfiltration. 

List:
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
[Data from Network Shared Drive](https://attack.mitre.org/wiki/Technique/T1039)
* ensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Adversaries may search network shares on computers they have compromised to find files of interest. Interactive command shells may be in use, and common functionality within cmd may be used to gather information. 






------------------------------- 
## Data from Removable Media
[Data from Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1025)
* Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. 





------------------------------- 
## Input Capture
[Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception.
* Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes, but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider.
* Keylogging is likely to be used to acquire credentials for new access opportunities when Credential Dumping efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises.
* Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through External Remote Services and Valid Accounts or as part of the initial compromise by exploitation of the externally facing web service.

[How to Monitor Keyboard Keystrokes Using ‘LogKeys’ in Linux](https://www.tecmint.com/how-to-monitor-keyboard-keystrokes-using-logkeys-in-linux/)

[logkeys - a GNU/Linux keylogger](https://github.com/kernc/logkeys)
* logkeys is a linux keylogger. It is no more advanced than other available linux keyloggers, notably lkl and uberkey, but is a bit newer, more up to date, it doesn't unreliably repeat keys and it shouldn't crash your X. All in all, it just seems to work. It relies on event interface of the Linux input subsystem. Once completely set, it logs all common character and function keys, while also being fully aware of Shift and AltGr key modifiers.

[keysniffer: trace pressed keys in debugfs](http://tuxdiary.com/2015/10/14/keysniffer/)

[SKeylogger](https://github.com/gsingh93/simple-key-logger)
* SKeylogger is a simple keylogger. I had previously been using a few other open source keyloggers, but they stopped working when I upgraded my operating system. I tried to look through the code of those keyloggers, but it was undocumented, messy, and complex. I decided to make my own highly documented and very simple keylogger.

[Using xkeyscan to Parse an X-Based Linux Keylogger](http://porterhau5.com/blog/xkeyscan-parse-linux-keylogger/)





------------------------------- 
## Screen Capture
[Screen Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1113)
* Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. 
* On Linux, there is the native command xwd.

[xwd - Wikipedia](https://en.wikipedia.org/wiki/Xwd)

[xwd - dump an image of an X window - manpage](https://www.x.org/releases/X11R7.5/doc/man/man1/xwd.1.html)




