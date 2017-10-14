## Linux Credential Access








------------------------------- 
## Bash History
[Bash History - ATT&CK](https://attack.mitre.org/wiki/Technique/T1139)
* Bash keeps track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user’s .bash_history file. For each user, this file resides at the same location: ~/.bash_history. Typically, this file keeps track of the user’s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Attackers can abuse this by looking through the file for potential credentials.


[Command history in Zsh - StackOverflow](https://unix.stackexchange.com/questions/111718/command-history-in-zsh)
















------------------------------- 
## Brute Force
[Brute Force - ATT&CK](https://attack.mitre.org/wiki/Technique/T1110)
* Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.
* Credential Dumping to obtain password hashes may only get an adversary so far when Pass the Hash is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table. Cracking hashes is usually done on adversary-controlled systems outside of the target network.
* Adversaries may attempt to brute force logins without knowledge of passwords or hashes during an operation either with zero knowledge or by attempting a list of known or possible passwords. This is a riskier option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies.
* A related technique called password spraying uses one password, or a small list of passwords, that matches the complexity policy of the domain and may be a commonly used password. Logins are attempted with that password and many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords.

















------------------------------- 
## Create Account
[Create Account - ATT&CK](https://attack.mitre.org/wiki/Technique/T1136)
* Adversaries with a sufficient level of access may create a local system or domain account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system. 

[adduser(8) - Linux man page](https://linux.die.net/man/8/adduser)

[The Complete Guide to “useradd” Command in Linux – 15 Practical Examples](https://www.tecmint.com/add-users-in-linux/)























------------------------------- 
## Credentials in Files
[Credentials in Files - ATT&CK](https://attack.mitre.org/wiki/Technique/T1081)
* * Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.
* It is possible to extract passwords from backups or saved virtual machines through Credential Dumping. Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller.

[How do I find all files containing specific text on Linux? - StackOverflow](https://stackoverflow.com/questions/16956810/how-do-i-find-all-files-containing-specific-text-on-linux)

[Find Files in Linux, Using the Command Line - Linode](https://www.linode.com/docs/tools-reference/tools/find-files-in-linux-using-the-command-line)















------------------------------- 
## Exploitation of Vulnerability
[Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068) 
* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.


[Triple-Fetch-Kernel-Creds](https://github.com/coffeebreakerz/Tripple-Fetch-Kernel-Creds)
* Attempt to steal kernelcredentials from launchd + task_t pointer (Based on: CVE-2017-7047)

















------------------------------- 
## Input Capture
[Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception.
* Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes, but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider.
* Keylogging is likely to be used to acquire credentials for new access opportunities when Credential Dumping efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises.
* Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through External Remote Services and Valid Accounts or as part of the initial compromise by exploitation of the externally facing web service.


[logkeys - a GNU/Linux keylogger](https://github.com/kernc/logkeys)
* logkeys is a linux keylogger. It is no more advanced than other available linux keyloggers, notably lkl and uberkey, but is a bit newer, more up to date, it doesn't unreliably repeat keys and it shouldn't crash your X. All in all, it just seems to work. It relies on event interface of the Linux input subsystem. Once completely set, it logs all common character and function keys, while also being fully aware of Shift and AltGr key modifiers.

[Using xkeyscan to Parse an X-Based Linux Keylogger](http://porterhau5.com/blog/xkeyscan-parse-linux-keylogger/)
*  Leverage native X-based tools for real-time keylogging with xkeyscan, a Python script that translates X keycodes into legible keystrokes.

[keysniffer: trace pressed keys in debugfs](http://tuxdiary.com/2015/10/14/keysniffer/)

[SKeylogger](https://github.com/gsingh93/simple-key-logger)
* SKeylogger is a simple keylogger. I had previously been using a few other open source keyloggers, but they stopped working when I upgraded my operating system. I tried to look through the code of those keyloggers, but it was undocumented, messy, and complex. I decided to make my own highly documented and very simple keylogger.

[The Linux Security Circus: On GUI isolation](https://theinvisiblethings.blogspot.com/2011/04/linux-security-circus-on-gui-isolation.html)




------------------------------- 
## Network Sniffing
[Network Sniffing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1040)
* Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.
* User credentials may be sent over an insecure, unencrypted protocol that can be captured and obtained through network packet analysis. An adversary may place a network interface into promiscuous mode, using a utility to capture traffic in transit over the network or use span ports to capture a larger amount of data. In addition, Address Resolution Protocol (ARP) and Domain Name Service (DNS) poisoning can be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary. 

[Manpage for TCPDump](http://www.tcpdump.org/tcpdump_man.html)

[A tcpdump Tutorial and Primer with Examples - Daniel Messler](https://danielmiessler.com/study/tcpdump/)

[net-creds](https://github.com/DanMcInerney/net-creds)
* Thoroughly sniff passwords and hashes from an interface or pcap file. Concatenates fragmented packets and does not rely on ports for service identification.

[tcpflow](https://github.com/simsong/tcpflow)
* tcpflow is a program that captures data transmitted as part of TCP connections (flows), and stores the data in a way that is convenient for protocol analysis and debugging. Each TCP flow is stored in its own file. Thus, the typical TCP flow will be stored in two files, one for each direction. tcpflow can also process stored 'tcpdump' packet flows.







------------------------------- 
## Private Keys
[Private Keys - ATT&CK](https://attack.mitre.org/wiki/Technique/T1145)
* Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.1
* Adversaries may gather private keys from compromised systems for use in authenticating to Remote Services like SSH or for use in decrypting other collected files such as email. Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, pfx, .cer, .p7b, .asc. Adversaries may also look in common key directories, such as ~/.ssh for SSH keys on *nix-based systems or C:\Users\(username)\.ssh\ on Windows.
* Private keys should require a password or passphrase for operation, so an adversary may also use Input Capture for keylogging or attempt to Brute Force the passphrase off-line. 

[What is a Pem file and how does it differ from other OpenSSL Generated Key File Formats? - StackOverflow](https://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file)













------------------------------- 
## Two-Factor Authentication Interception
[Two-Factor Authentication Interception - ATT&CK](https://attack.mitre.org/wiki/Technique/T1111)
* Use of two- or multifactor authentication is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. Adversaries may target authentication mechanisms, such as smart cards, to gain access to systems, services, and network resources.
* If a smart card is used for two-factor authentication (2FA), then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token.
* Other methods of 2FA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Although primarily focused on by cyber criminals, these authentication mechanisms have been targeted by advanced actors.
* Other hardware tokens, such as RSA SecurID, require the adversary to have access to the physical device or the seed and algorithm in addition to the corresponding credentials. 









