## Linux Defense Evasion



------------------------------- 
## Binary Padding
[Binary Padding - ATT&CK](https://attack.mitre.org/wiki/Technique/T1009)
* Some security tools inspect files with static signatures to determine if they are known malicious. Adversaries may add data to files to increase the size beyond what security tools are capable of handling or to change the file hash to avoid hash-based blacklists. 















------------------------------- 
## Clear Command History
[Clear Command History - ATT&CK](https://attack.mitre.org/wiki/Technique/T1146)
* macOS and Linux both keep track of the commands users type in their terminal so that users can easily remember what they've done. These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable HISTFILE. When a user logs off a system, this information is flushed to a file in the user's home directory called ~/.bash_history. The benefit of this is that it allows users to go back to commands they've used before in different sessions. Since everything typed on the command-line is saved, passwords passed in on the command line are also saved. Adversaries can abuse this by searching these files for cleartext passwords. Additionally, adversaries can use a variety of methods to prevent their own commands from appear in these logs such as unset HISTFILE, export HISTFILESIZE=0, history -c, rm ~/.bash_history. 
* Location of bash history file on linux: ```~/.bash_history```


[How to clear bash history completely? - StackOverflow](https://askubuntu.com/questions/191999/how-to-clear-bash-history-completely)

[How To Delete / Clear Linux Comand Line History With Examples](https://linoxide.com/how-tos/how-to-delete-history-linux/)










------------------------------- 
## Disabling Security Tools
[Disabling Security Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1089)
* Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security scanning or event reporting. 












------------------------------- 
## Exploitation of Vulnerability
[Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)
* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.
























------------------------------- 
## File Deletion
[File Deletion - ATT&CK](https://attack.mitre.org/wiki/Technique/T1107)
* Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
* There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples include native cmd functions such as DEL, secure deletion tools such as Windows Sysinternals SDelete, or other third-party file deletion tools.




[rm(1) - Linux man page](https://linux.die.net/man/1/rm)

[Linux / UNIX: Delete a file - nixcraft](https://www.google.com/search?q=linux+clear+history&ie=utf-8&oe=utf-8)







------------------------------- 
## HISTCONTROL
[HISTCONTROL - ATT&CK](https://attack.mitre.org/wiki/Technique/T1148)
* The HISTCONTROL environment variable keeps track of what should be saved by the history command and eventually into the ~/.bash_history file when a user logs out. This setting can be configured to ignore commands that start with a space by simply setting it to "ignorespace". HISTCONTROL can also be set to ignore duplicate commands by setting it to "ignoredups". In some Linux systems, this is set by default to "ignoreboth" which covers both of the previous examples. This means that “ ls” will not be saved, but “ls” would be saved by history. HISTCONTROL does not exist by default on macOS, but can be set by the user and will be respected. Adversaries can use this to operate without leaving traces by simply prepending a space to all of their terminal commands. 

[15 Examples To Master Linux Command Line History](http://www.thegeekstuff.com/2008/08/15-examples-to-master-linux-command-line-history/)








------------------------------- 
## Hidden Files and Directories
[Hidden Files and Directories - ATT&CK](https://attack.mitre.org/wiki/Technique/T1158)
* To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (dir /a for Windows and ls –a for Linux and macOS). 

















------------------------------- 
## Indicator Removal from Tools
[Indicator Removal from Tools - ATT&CK](https://attack.mitre.org/wiki/Technique/T1066)
* * If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.
* A good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may use Software Packing or otherwise modify the file so it has a different signature, and then re-use the malware. 





















------------------------------- 
## Indicator Removal on Host
[Indicator Removal on Host - ATT&CK](https://attack.mitre.org/wiki/Technique/T1070)
* Adversaries may delete or alter generated event files on a host system, including potentially captured files such as quarantined malware. This may compromise the integrity of the security solution, causing events to go unreported, or make forensic analysis and incident response more difficult due to lack of sufficient data to determine what occurred. 
























------------------------------- 
## Install Root Certificate
[Install Root Certificate - ATT&CK](https://attack.mitre.org/wiki/Technique/T1130)
* Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate. Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website.
* Installation of a root certificate on a compromised system would give an adversary a way to degrade the security of that system. Adversaries have used this technique to avoid security warnings prompting users when compromised systems connect over HTTPS to adversary controlled web servers that spoof legitimate websites in order to collect login credentials.
* Atypical root certificates have also been pre-installed on systems by the manufacturer or in the software supply chain and were used in conjunction with malware/adware to provide a man-in-the-middle capability for intercepting information transmitted over secure TLS/SSL communications.


[How do I install a root certificate? - StackOverflow](https://askubuntu.com/questions/73287/how-do-i-install-a-root-certificate)

























------------------------------- 
## Masquerading
[Masquerading - ATT&CK](https://attack.mitre.org/wiki/Technique/T1036)
* Masquerading occurs when an executable, legitimate or malicious, is placed in a commonly trusted location (such as C:\Windows\System32) or named with a common name (such as "explorer.exe" or "svchost.exe") to bypass tools that trust executables by relying on file name or path. An adversary may even use a renamed copy of a legitimate utility, such as rundll32.exe. Masquerading also may be done to deceive defenders and system administrators into thinking a file is benign by associating the name with something that is thought to be legitimate. 

* Think Shell Scripts that call out to services/items; Cron Jobs; 





















------------------------------- 
## Redundant Access
[Redundant Access - ATT&CK](https://attack.mitre.org/wiki/Technique/T1108)
* Adversaries may use more than one remote access tool with varying command and control protocols as a hedge against detection. If one type of tool is detected and blocked or removed as a response but the organization did not gain a full understanding of the adversary's tools and access, then the adversary will be able to retain access to the network. Adversaries may also attempt to gain access to Valid Accounts to use External Remote Services such as external VPNs as a way to maintain access despite interruptions to remote access tools deployed within a target network.
























------------------------------- 
## Scripting
[Scripting - ATT&CK](https://attack.mitre.org/wiki/Technique/T1064)
* Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the time required to gain access to critical resources. Some scripting languages may be used to bypass process monitoring mechanisms by directly interacting with the operating system at an API level instead of calling other programs. Common scripting languages for Windows include VBScript and PowerShell but could also be in the form of command-line batch scripts. 


[BASH Programming - Introduction HOW-TO - tldp](http://tldp.org/HOWTO/Bash-Prog-Intro-HOWTO.html)

[Advanced Bash-Scripting Guide - tldp](http://tldp.org/LDP/abs/html/)

[Bash Shell Scripting - Wikibooks](https://en.wikibooks.org/wiki/Bash_Shell_Scripting)



















------------------------------- 
## Spaces after Filename
[Spaces after Filename - ATT&CK](https://attack.mitre.org/wiki/Technique/T1151)
* Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system. For example, if there is a Mach-O executable file called evil.bin, when it is double clicked by a user, it will launch Terminal.app and execute. If this file is renamed to evil.txt, then when double clicked by a user, it will launch with the default text editing application (not executing the binary). However, if the file is renamed to "evil.txt " (note the space at the end), then when double clicked by a user, the true file type is determined by the OS and handled appropriately and the binary will be executed.
























------------------------------- 
## Timestomp
[Timestomp - ATT&CK](https://attack.mitre.org/wiki/Technique/T1099)
* Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. This is done, for example, on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools. Timestomping may be used along with file name Masquerading to hide malware and tools.




[Bash - Timestomping Linux Files](http://64bit.ca/code/bash-timestomping-linux-files/)

[Timestomp - Forensics Wiki](http://www.forensicswiki.org/wiki/Timestomp)

[Linux Timestamps, Oh boy!](https://articles.forensicfocus.com/2015/08/25/linux-timestamps-oh-boy/)
















------------------------------- 
## Valid Accounts
[Valid Accounts - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)
* Adversaries may steal the credentials of a specific user or service account using Credential Access techniques. Compromised credentials may be used to bypass access controls placed on various resources on hosts and within the network and may even be used for persistent access to remote systems. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.
* Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful.
* The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.

* ```cat /etc/passwd```








