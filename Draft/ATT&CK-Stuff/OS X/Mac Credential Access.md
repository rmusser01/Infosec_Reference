### Mac Credential Access

Gatekeeper exposed
Writing Bad@ass os x malware
Attacking the XNU kernel in el capitan
OS X El Capitan-Sinking the S/h\IP
Memory corruption is for wussies
------------------------------- 
## Bash History
* [Bash History - ATT&CK](https://attack.mitre.org/wiki/Technique/T1139)
	* Bash keeps track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user’s .bash_history file. For each user, this file resides at the same location: ~/.bash_history. Typically, this file keeps track of the user’s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Attackers can abuse this by looking through the file for potential credentials.





------------------------------- 
## Brute Force
* [Brute Force - ATT&CK](https://attack.mitre.org/wiki/Technique/T1110)
	* Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.
	* Credential Dumping to obtain password hashes may only get an adversary so far when Pass the Hash is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table. Cracking hashes is usually done on adversary-controlled systems outside of the target network.
	* Adversaries may attempt to brute force logins without knowledge of passwords or hashes during an operation either with zero knowledge or by attempting a list of known or possible passwords. This is a riskier option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies.
	* A related technique called password spraying uses one password, or a small list of passwords, that matches the complexity policy of the domain and may be a commonly used password. Logins are attempted with that password and many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords.









------------------------------- 
## Create Account
* [Create Account - ATT&CK](https://attack.mitre.org/wiki/Technique/T1136)
	* Adversaries with a sufficient level of access may create a local system or domain account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system. 






------------------------------- 
## Credentials in Files
* [Credentials in Files - ATT&CK](https://attack.mitre.org/wiki/Technique/T1081)
	* Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.
	* It is possible to extract passwords from backups or saved virtual machines through Credential Dumping. Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller.



------------------------------- 
## Exploitation of Vulnerability
* [Exploitation of Vulnerability - ATT&CK](https://attack.mitre.org/wiki/Technique/T1068)
	* Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Exploiting software vulnerabilities may allow adversaries to run a command or binary on a remote system for lateral movement, escalate a current process to a higher privilege level, or bypass security mechanisms. Exploits may also allow an adversary access to privileged accounts and credentials. One example of this is MS14-068, which can be used to forge Kerberos tickets using domain user permissions.





------------------------------- 
## Input Capture
* [Input Capture - ATT&CK](https://attack.mitre.org/wiki/Technique/T1056)
	* Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception.
	* Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes,1 but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider.2
	* Keylogging is likely to be used to acquire credentials for new access opportunities when Credential Dumping efforts are not effective, and may require an adversary to remain passive on a system for a period of time before an opportunity arises.
	* Adversaries may also install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through External Remote Services and Valid Accounts or as part of the initial compromise by exploitation of the externally facing web service.3 
* [OSX-Keylogger](https://github.com/CounterfeitLlama/OSX-Keylogger)
* [Swift-Keylogger](https://github.com/SkrewEverything/Swift-Keylogger)
	* Keylogger for mac written in Swift using HID
* [Mac OS X Keylogger](https://github.com/caseyscarborough/keylogger)
	* This repository holds the code for a simple and easy to use keylogger for Mac OS X. It is not meant to be malicious, and is written as a proof of concept. There is not a lot of information on keyloggers or implementing them on Mac OS X, and most of the ones I've seen do not work as indicated. This project aims to be a simple implementation on how it can be accomplished on OS X.





------------------------------- 
## Input Prompt
* [Input Prompt - ATT&CK](https://attack.mitre.org/wiki/Technique/T1141)
	* When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task. Adversaries can mimic this functionality to prompt users for credentials with a normal-looking prompt. This type of prompt can be accomplished with AppleScript:
	* set thePassword to the text returned of (display dialog "AdobeUpdater needs permission to check for updates. Please authenticate." default answer "")
	* Adversaries can prompt a user for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite.
* [osascript: for local phishing - fuzzyknop](http://fuzzynop.blogspot.com/2014/10/osascript-for-local-phishing.html)
* [FiveOnceInYourLife](https://github.com/fuzzynop/FiveOnceInYourLife)
* [osascript - macphish](https://github.com/cldrn/macphish/wiki/Osascript)
* [EvilOSX](https://github.com/Marten4n6/EvilOSX)
	* A pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX.






------------------------------- 
## Keychain
* [Keychain - ATT&CK](https://attack.mitre.org/wiki/Technique/T1142)
	* Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features such as WiFi passwords, websites, secure notes, certificates, and Kerberos. Keychain files are located in ~/Library/Keychains/,/Library/Keychains/, and /Network/Library/Keychains/. The security command-line utility, which is built into macOS by default, provides a useful way to manage these credentials.
	* To manage their credentials, users have to use additional credentials to access their keychain. If an adversary knows the credentials for the login keychain, then they can get access to all the other credentials stored in this vault. By default, the passphrase for the keychain is the user’s logon credentials.
* [Keychain for Mac: Keychain Access overview](https://support.apple.com/kb/PH20093?locale=en_US)
* [Is there a quick and easy way to dump the contents of a MacOS X keychain? - StackOverflow](https://stackoverflow.com/questions/717095/is-there-a-quick-and-easy-way-to-dump-the-contents-of-a-macos-x-keychain)
* [How to dump the content of keychain from the shell? - askdifferent](https://apple.stackexchange.com/questions/184897/how-to-dump-the-content-of-keychain-from-the-shell)
* [Breaking into the OS X keychain - 2012](http://juusosalonen.com/post/30923743427/breaking-into-the-os-x-keychain)
* [chainbreaker](https://github.com/n0fate/chainbreaker)
	* chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner. Master Key candidates can be extracted from volafox or volatility keychaindump module.
* [Examining Mac OS X User & System Keychains - Digital Forensics Today blog](http://encase-forensic-blog.guidancesoftware.com/2013/07/examining-mac-os-x-user-system-keychains.html)
* [Dumping cleartext passwords from the OS X keychain](http://x3ro.de/retrieving-passwords-from-keychain.html)
* [Keychain Analysis with Mac OS X Memory Forensics](https://forensic.n0fate.com/wp-content/uploads/2012/07/Keychain-Analysis-with-Mac-OS-X-Memory-Forensics.pdf)





------------------------------- 
## Network Sniffing
* [Network Sniffing - ATT&CK](https://attack.mitre.org/wiki/Technique/T1040)
	* Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.
	* User credentials may be sent over an insecure, unencrypted protocol that can be captured and obtained through network packet analysis. An adversary may place a network interface into promiscuous mode, using a utility to capture traffic in transit over the network or use span ports to capture a larger amount of data. In addition, Address Resolution Protocol (ARP) and Domain Name Service (DNS) poisoning can be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary. 
* [OS X Yosemite Has A Secret Packet Sniffer](https://jacobsalmela.com/2014/11/23/os-x-yosemite-secret-packet-sniffer/)
* [Capture a packet trace using Terminal on your Mac - support.apple](https://support.apple.com/en-us/HT202013)





------------------------------- 
## Private Keys
* [Private Keys - ATT&CK](https://attack.mitre.org/wiki/Technique/T1145)
	* Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.
	* Adversaries may gather private keys from compromised systems for use in authenticating to Remote Services like SSH or for use in decrypting other collected files such as email. Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, pfx, .cer, .p7b, .asc. Adversaries may also look in common key directories, such as ~/.ssh for SSH keys on nix-based systems or C:\Users\(username)\.ssh\ on Windows.
	* Private keys should require a password or passphrase for operation, so an adversary may also use Input Capture for keylogging or attempt to Brute Force the passphrase off-line.






------------------------------- 
## Securityd Memory
* [Securityd Memory - ATT&CK](https://attack.mitre.org/wiki/Technique/T1167)
	* In OS X prior to El Capitan, users with root access can read plaintext keychain passwords of logged-in users because Apple’s keychain implementation allows these credentials to be cached so that users are not repeatedly prompted for passwords. Apple’s securityd utility takes the user’s logon password, encrypts it with PBKDF2, and stores this master key in memory. Apple also uses a set of keys and algorithms to encrypt the user’s password, but once the master key is found, an attacker need only iterate over the other values to unlock the final password.1
	* If an adversary can obtain root access (allowing them to read securityd’s memory), then they can scan through memory to find the correct sequence of keys in relatively few tries to decrypt the user’s logon keychain. This provides the adversary with all the plaintext passwords for users, WiFi, mail, browsers, certificates, secure notes, etc







------------------------------- 
## Two-Factor Authentication Interception
* [Two-Factor Authentication Interception - ATT&CK](https://attack.mitre.org/wiki/Technique/T1111)
	* Use of two- or multifactor authentication is recommended and provides a higher level of security than user names and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. Adversaries may target authentication mechanisms, such as smart cards, to gain access to systems, services, and network resources.
	* If a smart card is used for two-factor authentication (2FA), then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token.
	* Other methods of 2FA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Although primarily focused on by cyber criminals, these authentication mechanisms have been targeted by advanced actors.
	* Other hardware tokens, such as RSA SecurID, require the adversary to have access to the physical device or the seed and algorithm in addition to the corresponding credentials. 



