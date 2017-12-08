## Linux Execution


------------------------------- 
## Command-Line Interface
* [Command-Line Interace - ATT&CK](https://attack.mitre.org/wiki/Technique/T1059)
	* Command-line interfaces provide a way of interacting with computer systems and is a common feature across many types of operating system platforms.1 One example command-line interface on Windows systems is cmd, which can be used to perform a number of tasks including execution of other software. Command-line interfaces can be interacted with locally or remotely via a remote desktop application, reverse shell session, etc. Commands that are executed run with the current permission level of the command-line interface process unless the command includes process invocation that changes permissions context for that execution (e.g. Scheduled Task). 
* [Linuxcommand.org](http://linuxcommand.org/lc3_learning_the_shell.php)
* [Learn the Bash Command Line](https://ryanstutorials.net/linuxtutorial/)




------------------------------- 
## Graphical User Interface
* [Graphical User Interface - ATT&CK](https://attack.mitre.org/wiki/Technique/T1061)
	* Cause a binary or script to execute based on interacting with the file through a graphical user interface (GUI) or in an interactive remote session such as Remote Desktop Protocol. 







------------------------------- 
## Scripting
* [Scripting - ATT&CK](https://attack.mitre.org/wiki/Technique/T1064)
	* Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and PowerShell but could also be in the form of command-line batch scripts. 
* [BASH Programming - Introduction HOW-TO - tldp](http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html)
* [Advanced Bash-Scripting Guide - tldp](http://tldp.org/LDP/abs/html/)
* [Bash Shell Scripting - Wikibooks](https://en.wikibooks.org/wiki/Bash_Shell_Scripting)






------------------------------- 
## Source
* [Source - ATT&CK](https://attack.mitre.org/wiki/Technique/T1153)
	* The source command loads functions into the current shell or executes files in the current context. This built-in command can be run in two different ways source /path/to/filename [arguments] or . /path/to/filename [arguments]. Take note of the space after the ".". Without a space, a new shell is created that runs the program instead of running the program within the current context. This is often used to make certain features or functions available to a shell or to update a specific shell's environment. 
* [Sourcing a File - tldp](http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x237.html)
* [Source command - bash.cyberciti](https://bash.cyberciti.biz/guide/Source_command)








------------------------------- 
## Space after Filename
* [Space after Filename - ATT&CK](https://attack.mitre.org/wiki/Technique/T1151)
	* Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system. For example, if there is a Mach-O executable file called evil.bin, when it is double clicked by a user, it will launch Terminal.app and execute. If this file is renamed to evil.txt, then when double clicked by a user, it will launch with the default text editing application (not executing the binary). However, if the file is renamed to "evil.txt " (note the space at the end), then when double clicked by a user, the true file type is determined by the OS and handled appropriately and the binary will be executed. 









------------------------------- 
## Third-Party Software
* [Third-Party Software](https://attack.mitre.org/wiki/Technique/T1072)
	* Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.). If an adversary gains access to these systems, then they may be able to execute code.
	* Adversaries may gain access to and use third-party application deployment systems installed within an enterprise network. Access to a network-wide or enterprise-wide software deployment system enables an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.
	* The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the deployment server, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform software deployment. 
* [How do I list all installed programs? - StackOverflow](https://unix.stackexchange.com/questions/20979/how-do-i-list-all-installed-programs)











------------------------------- 
## Trap
* [Trap - ATT&CK](https://attack.mitre.org/wiki/Technique/T1154)
	* The trap command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like ctrl+c and ctrl+d. Adversaries can use this to register code to be executed when the shell encounters specific interrupts either to gain execution or as a persistence mechanism. Trap commands are of the following format trap 'command list' signals where "command list" will be executed when "signals" are received. 
* [Traps - tldp](http://tldp.org/LDP/Bash-Beginners-Guide/html/sect_12_02.html)
* [Shell Scripting Tutorial - Trap](https://www.shellscript.sh/trap.html)
* [Unix / Linux - Signals and Traps - TutorialsPoint](https://www.tutorialspoint.com/unix/unix-signals-traps.htm)