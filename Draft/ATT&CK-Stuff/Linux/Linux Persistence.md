## Linux Persistence


------------------------------- 
## .bash_profile and .bashrc
* [.bash_profile and .bashrc - ATT&CK](https://attack.mitre.org/wiki/Technique/T1156)
	* ~/.bash_profile and ~/.bashrc are executed in a user's context when a new shell opens or when a user logs in so that their environment is set correctly. ~/.bash_profile is executed for login shells and ~/.bashrc is executed for interactive non-login shells. This means that when a user logs in (via username and password) to the console (either locally or remotely via something like SSH), ~/.bash_profile is executed before the initial command prompt is returned to the user. After that, every time a new shell is opened, ~/.bashrc is executed. This allows users more fine grained control over when they want certain commands executed.
	* Mac's Terminal.app is a little different in that it runs a login shell by default each time a new terminal window is opened, thus calling ~/.bash_profile each time instead of ~/.bashrc. 





------------------------------- 
## Bootkit
* [Bootkit - ATT&CK](https://attack.mitre.org/wiki/Technique/T1067)
	* A bootkit is a malware variant that modifies the boot sectors of a hard drive, including the Master Boot Record (MBR) and Volume Boot Record (VBR).1
	* Adversaries may use bootkits to persist on systems at a layer below the operating system, which may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly. 











------------------------------- 
## Cron Job
* [Cron Job - ATT&CK](https://attack.mitre.org/wiki/Technique/T1168)
	* System-wide cron jobs are installed by modifying /etc/crontab while per-user cron jobs are installed using crontab with specifically formatted crontab files 1. This works on Mac and Linux systems.
	* Both methods allow for commands or scripts to be executed at specific, periodic intervals in the background without user interaction. An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence234, to conduct Execution as part of Lateral Movement, to gain root privileges, or to run a process under the context of a specific account. 
* [Intro to Cron - unixgeeks](http://www.unixgeeks.org/security/newbie/unix/cron-1.html)
* [Scheduling Tasks with Cron Jobs - tutsplus](https://code.tutsplus.com/tutorials/scheduling-tasks-with-cron-jobs--net-8800)









------------------------------- 
## Hidden Files and Directories
* [Hidden Files and Directories - ATT&CK](https://attack.mitre.org/wiki/Technique/T1158)
	* To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (dir /a for Windows and ls –a for Linux and macOS). 
* [Hidden File Definition - LinuxInfoProject](http://www.linfo.org/hidden_file.html)






------------------------------- 
## Rc.common
* [Rc.common - ATT&CK](https://attack.mitre.org/wiki/Technique/T1163)
	* During the boot process, macOS and Linux both execute source /etc/rc.common, which is a shell script containing various utility functions. This file also defines routines for processing command-line arguments and for gathering system settings, and is thus recommended to include in the start of Startup Item Scripts1. In macOS and OS X, this is now a deprecated technique in favor of launch agents and launch daemons, but is currently still used. 
* [An introduction to services, runlevels, and rc.d scripts - linux.com](https://www.linux.com/news/introduction-services-runlevels-and-rcd-scripts)









------------------------------- 
## Redundant Access
* [Redundant Access - ATT&CK](https://attack.mitre.org/wiki/Technique/T1108)
	* Adversaries may use more than one remote access tool with varying command and control protocols as a hedge against detection. If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to Valid Accounts to use External Remote Services such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.






------------------------------- 
## Trap
* [Trap - ATT&CK](https://attack.mitre.org/wiki/Technique/T1154)
	* The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d. Adversaries can use this to register code to be executed when the shell encounters specific interrupts either to gain execution or as a persistence mechanism. Trap commands are of the following format trap 'command list' signals where "command list" will be executed when "signals" are received. 
* [Traps - tldp](http://tldp.org/LDP/Bash-Beginners-Guide/html/sect_12_02.html)
* [Shell Scripting Tutorial - Trap](https://www.shellscript.sh/trap.html)
* [Unix / Linux - Signals and Traps - TutorialsPoint](https://www.tutorialspoint.com/unix/unix-signals-traps.htm)



------------------------------- 
## Valid Accounts
* [Valid Accounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)
	* Adversaries may steal the credentials of a specific user or service account using Credential Access techniques. Compromised credentials may be used to bypass access controls placed on various resources on hosts and within the network and may even be used for persistent access to remote systems. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.
	* Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful.
	* The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise






------------------------------- 
## Web Shell
* [Web Shell - ATT&CK](https://attack.mitre.org/wiki/Technique/T1100)
	* A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (see, for example, China Chopper Web shell client).
* [public-shell](https://github.com/BDLeet/public-shell)
	* Some Public Shell
* [php-webshells](https://github.com/JohnTroony/php-webshells)
	* Common php webshells. Do not host the file(s) on your server!
* [PHP-Backdoors](https://github.com/bartblaze/PHP-backdoors)
	* A collection of PHP backdoors. For educational or testing purposes only.
* [Weevely](https://github.com/epinna/weevely3)
	* Weevely is a command line web shell dynamically extended over the network at runtime, designed for remote server administration and penetration testing.













