## Linux Privilege Escalation

------------------------------- 
## Exploitation of Vulnerability
* [Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)
	* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.
* [unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)
	* Shell script to check for simple privilege escalation vectors on Unix systems. Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2). It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases).
* [LinEnum](https://github.com/rebootuser/LinEnum)
	* Scripted Local Linux Enumeration & Privilege Escalation Checks
* [linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)
	* linux-exploit-suggester.sh was inspired by the excellent Linux_Exploit_Suggester script by PenturaLabs. The issue with Pentura's script however is that it isn't up to date anymore (the script was last updated in early 2014) so it lacks some recent Linux kernel exploits. linux-exploit-suggester.sh on the other hand also contains all the latest (as of early 2017) publicly known Linux kernel exploits. It is also capable to identify possible privilege escalation vectors via installed userspace packages and comes with some additional minor features that makes finding right exploit more time efficient.
* [cve-check-tool - Intel](https://github.com/clearlinux/cve-check-tool)
	* Original Automated CVE Checking Tool
* [Linux Kernel Exploitation - xairy github](https://github.com/xairy/linux-kernel-exploitation)
* [Vuls: Vulnerability Scanner](https://github.com/future-architect/vuls)
	* Vulnerability scanner for Linux/FreeBSD, agentless, written in golang.
* [cvechecker](https://github.com/sjvermeu/cvechecker)
	* The goal of cvechecker is to report about possible vulnerabilities on your system, by scanning a list of installed software and matching results with the CVE database. This is not a bullet-proof method and you will have many false positives (ie: vulnerability is fixed with a revision-release, but the tool isn't able to detect the revision itself), yet it is still better than nothing, especially if you are running a distribution with little security coverage.
* [kernel-exploits - xairy](https://github.com/xairy/kernel-exploits)
	* A bunch of proof-of-concept exploits for the Linux kernel







------------------------------- 
## Setuid and Setgid
* [Setuid and Setgid - ATT&CK](https://attack.mitre.org/wiki/Technique/T1166)
	* When the setuid or setgid bits are set on Linux or macOS for an application, this means that the application will run with the privileges of the owning user or group respectively. Normally an application is run in the current user’s context, regardless of which user or group owns the application. There are instances where programs need to be executed in an elevated context to function properly, but the user running them doesn’t need the elevated privileges. Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications. These bits are indicated with an "s" instead of an "x" when viewing a file's attributes via ls -l. The chmod program can set these bits with via bitmasking, chmod 4777 [file] or via shorthand naming, chmod u+s [file]. 
* [Setuid - Wikipedia](https://en.wikipedia.org/wiki/Setuid)
* [SETGID(2) - man7.org](http://man7.org/linux/man-pages/man2/setgid.2.html)
* [Special File Permissions (setuid, setgid and Sticky Bit)](https://docs.oracle.com/cd/E19683-01/806-4078/secfiles-69/index.html)
* [Exploiting SUID Executables](https://www.pentestpartners.com/security-blog/exploiting-suid-executables/)












------------------------------- 
## Sudo
* [Sudo - ATT&CK](https://attack.mitre.org/wiki/Technique/T1169)
	* The sudoers file, ****/etc/sudoers****, describes which users can run which commands and from which terminals. This also describes which commands users can run as other users or groups. This provides the idea of least privilege such that users are running in their lowest possible permissions for most of the time and only elevate to other users or permissions as needed, typically by prompting for a password. However, the sudoers file can also specify when to not prompt users for passwords with a line like user1 ALL=(ALL) NOPASSWD: ALL1.
	* Adversaries can take advantage of these configurations to execute commands as other users or spawn processes with higher privileges. You must have elevated privileges to edit this file though. 
* [sudo(8) - Linux man page](https://linux.die.net/man/8/sudo)
* [Sudo Main Page](https://www.sudo.ws/)
* [sudo - Wikipedia](https://en.wikipedia.org/wiki/Sudo)


------------------------------- 
## Valid Accounts
* [Valid Accounts	 - ATT&CK](https://attack.mitre.org/wiki/Technique/T1078)
	* Adversaries may steal the credentials of a specific user or service account using Credential Access techniques. Compromised credentials may be used to bypass access controls placed on various resources on hosts and within the network and may even be used for persistent access to remote systems. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.
	* Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful.
	* The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.










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




