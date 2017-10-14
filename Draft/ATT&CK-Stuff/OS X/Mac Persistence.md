## Mac Persistence

------------------------------- 
## .bash_profile and .bashrc
[.bash_profile and .bashrc - ATT&CK](https://attack.mitre.org/wiki/Technique/T1156)
* ~/.bash_profile and ~/.bashrc are executed in a user's context when a new shell opens or when a user logs in so that their environment is set correctly. ~/.bash_profile is executed for login shells and ~/.bashrc is executed for interactive non-login shells. This means that when a user logs in (via username and password) to the console (either locally or remotely via something like SSH), ~/.bash_profile is executed before the initial command prompt is returned to the user. After that, every time a new shell is opened, ~/.bashrc is executed. This allows users more fine grained control over when they want certain commands executed.
* Mac's Terminal.app is a little different in that it runs a login shell by default each time a new terminal window is opened, thus calling ~/.bash_profile each time instead of ~/.bashrc. 








------------------------------- 
## Cron Job
[Cron Job - ATT&CK](https://attack.mitre.org/wiki/Technique/T1168)
* Per Apple’s developer documentation, there are two supported methods for creating periodic background jobs: launchd and cron1. 
	* Launchd - Each Launchd job is described by a different configuration property list (plist) file similar to Launch Daemons or Launch Agents, except there is an additional key called StartCalendarInterval with a dictionary of time values. This only works on macOS and OS X. 
	* cron - System-wide cron jobs are installed by modifying /etc/crontab while per-user cron jobs are installed using crontab with specifically formatted crontab files. This works on Mac and Linux systems.
* Both methods allow for commands or scripts to be executed at specific, periodic intervals in the background without user interaction. An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence234, to conduct Execution as part of Lateral Movement, to gain root privileges, or to run a process under the context of a specific account. 














------------------------------- 
## Dylib Hijacking
[Dylib Hijacking - ATT&CK](https://attack.mitre.org/wiki/Technique/T1157)
* macOS and OS X use a common method to look for required dynamic libraries (dylib) to load into a program based on search paths. Adversaries can take advantage of ambiguous paths to plant dylibs to gain privilege escalation or persistence.






























------------------------------- 
## Hidden Files and Directories
[Hidden Files and Directories - ATT&CK](https://attack.mitre.org/wiki/Technique/T1158)
* To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (dir /a for Windows and ls –a for Linux and macOS). 



















------------------------------- 
## LC_LOAD_DYLIB Addition
[LC_LOAD_DYLIB Addition - ATT&CK](https://attack.mitre.org/wiki/Technique/T1161)
* Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long adjustments are made to the rest of the fields and dependencies. There are tools available to perform these changes. Any changes will invalidate digital signatures on binaries because the binary is being modified. Adversaries can remediate this issue by simply removing the LC_CODE_SIGNATURE command from the binary so that the signature isn’t checked at load time.














------------------------------- 
## Launch Agent
[Launch Agent - ATT&CK](https://attack.mitre.org/wiki/Technique/T1159)
* Per Apple’s developer documentation, when a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (plist) files found in /System/Library/LaunchAgents, /Library/LaunchAgents, and $HOME/Library/LaunchAgents. These launch agents have property list files which point to the executables that will be launched.
* Adversaries may install a new launch agent that can be configured to execute at login by using launchd or launchctl to load a plist into the appropriate directories. The agent name may be disguised by using a name from a related operating system or benign software. Launch Agents are created with user level privileges and are executed with the privileges of the user when they log in78. They can be set up to execute when a specific user logs in (in the specific user’s directory structure) or when any user logs in (which requires administrator privileges). 
















------------------------------- 
## Launch Daemon
[Launch Daemon - ATT&CK](https://attack.mitre.org/wiki/Technique/T1160)
* Per Apple’s developer documentation, when macOS and OS X boot up, launchd is run to finish system initialization. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in /System/Library/LaunchDaemons and /Library/LaunchDaemons1. These LaunchDaemons have property list files which point to the executables that will be launched2.
* Adversaries may install a new launch daemon that can be configured to execute at startup by using launchd or launchctl to load a plist into the appropriate directories3. The daemon name may be disguised by using a name from a related operating system or benign software 4. Launch Daemons may be created with administrator privileges, but are executed under root privileges, so an adversary may also use a service to escalate privileges from administrator to root.
* The plist file permissions must be root:wheel, but the script or program that it points to has no such requirement. So, it is possible for poor configurations to allow an adversary to modify a current Launch Daemon’s executable and gain persistence or Privilege Escalation. 

















------------------------------- 
## Launchctl
[Launchctl - ATT&CK](https://attack.mitre.org/wiki/Technique/T1152)
* Launchctl controls the macOS launchd process which handles things like launch agents and launch daemons, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input. By loading or reloading launch agents or launch daemons, adversaries can install persistence or execute changes they made 1. Running a command from launchctl is as simple as launchctl submit -l <labelName> -- /Path/to/thing/to/execute "arg" "arg" "arg". Loading, unloading, or reloading launch agents or launch daemons can require elevated privileges. 














------------------------------- 
## Login Item
[Login Item - ATT&CK](https://attack.mitre.org/wiki/Technique/T1162)
* MacOS provides the option to list specific applications to run when a user logs in. These applications run under the logged in user's context, and will be started every time the user logs in. Login items installed using the Service Management Framework are not visible in the System Preferences and can only be removed by the application that created them1. Users have direct control over login items installed using a shared file list which are also visible in System Preferences. These login items are stored in the user's ~/Library/Preferences/ directory in a plist file called com.apple.loginitems.plist. Some of these applications can open visible dialogs to the user, but they don’t all have to since there is an option to ‘Hide’ the window. If an adversary can register their own login item or modified an existing one, then they can use it to execute their code for a persistence mechanism each time the user logs in. 

















------------------------------- 
## Logon Scripts
[Logon Scripts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1037)
* Mac allows login and logoff hooks to be run as root whenever a specific user logs into or out of a system. A login hook tells Mac OS X to execute a certain script when a user logs in, but unlike startup items, a login hook executes as root. There can only be one login hook at a time though. If adversaries can access these scripts, they can insert additional code to the script to execute their tools when a user logs in. 

[Mac OS X: Creating a login hook - apple](https://support.apple.com/de-at/HT2420)






------------------------------- 
## Plist Modification
[list Modification - ATT&CK](https://attack.mitre.org/wiki/Technique/T1150)
* Property list (plist) files contain all of the information that macOS and OS X uses to configure applications and services. These files are UT-8 encoded and formatted like XML documents via a series of keys surrounded by < >. They detail when programs should execute, file paths to the executables, program arguments, required OS permissions, and many others. plists are located in certain locations depending on their purpose such as /Library/Preferences (which execute with elevated privileges) and ~/Library/Preferences (which execute with a user's privileges). Adversaries can modify these plist files to point to their own code, can use them to execute their code in the context of another user, bypass whitelisting procedures, or even use them as a persistence mechanism.















------------------------------- 
## Rc.common
[Rc.common - ATT&CK](https://attack.mitre.org/wiki/Technique/T1163)
* During the boot process, macOS and Linux both execute source /etc/rc.common, which is a shell script containing various utility functions. This file also defines routines for processing command-line arguments and for gathering system settings, and is thus recommended to include in the start of Startup Item Scripts. In macOS and OS X, this is now a deprecated technique in favor of launch agents and launch daemons, but is currently still used.


















------------------------------- 
## Re-opened Applications
[Re-opened Applications - ATT&CK](https://attack.mitre.org/wiki/Technique/T1164)
* Starting in Mac OS X 10.7 (Lion), users can specify certain applications to be re-opened when a user reboots their machine. While this is usually done via a Graphical User Interface (GUI) on an app-by-app basis, there are property list files (plist) that contain this information as well located at ~/Library/Preferences/com.apple.loginwindow.plist and ~/Library/Preferences/ByHost/com.apple.loginwindow.*.plist. 






------------------------------- 
## Redundant Access
[Redundant Access - ATT&CK](https://attack.mitre.org/wiki/Technique/T1108)
* Adversaries may use more than one remote access tool with varying command and control protocols as a hedge against detection. If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to Valid Accounts to use External Remote Services such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.











------------------------------- 
## Startup Items
[Startup Items - ATT&CK](https://attack.mitre.org/wiki/Technique/T1165)
* Per Apple’s documentation, startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items. This is technically a deprecated version (superseded by Launch Daemons), and thus the appropriate folder, /Library/StartupItems isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), StartupParameters.plist, reside in the top-level directory. 





























------------------------------- 
## Trap
[Trap - ATT&CK](https://attack.mitre.org/wiki/Technique/T1154)
* The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d. Adversaries can use this to register code to be executed when the shell encounters specific interrupts either to gain execution or as a persistence mechanism. Trap commands are of the following format trap 'command list' signals where "command list" will be executed when "signals" are received. 

















------------------------------- 
## Valid Acccounts
[Valid Acccounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)
* Adversaries may steal the credentials of a specific user or service account using Credential Access techniques. Compromised credentials may be used to bypass access controls placed on various resources on hosts and within the network and may even be used for persistent access to remote systems. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.
* Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful.
* The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.


















------------------------------- 
## Web Shell
[Web Shell - ATT&CK](https://attack.mitre.org/wiki/Technique/T1100)
* A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (see, for example, China Chopper Web shell client).1 




