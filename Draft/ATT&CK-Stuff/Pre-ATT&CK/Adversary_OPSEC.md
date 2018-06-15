# Adversary OPSEC - Pre-ATT&CK
 
## Table of Contents
- []()
- []()
- []()
- []()
- []()
- []()
- []()
- []()
- []()
- []()
- []()
- []()
- []()




[Adversary OPSEC - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Adversary_OPSEC)
* Adversary OPSEC consists of the use of various technologies or 3rd party services to obfuscate, hide, or blend in with accepted network traffic or system behavior. The adversary may use these techniques to evade defenses, reduce attribution, minimize discovery, and/or increase the time and effort required to analyze. 




-------------------------------
### Acquire and/or use 3rd party infrastructure services
* [Acquire and/or use 3rd party infrastructure services - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1084)
	* A wide variety of cloud, virtual private services, hosting, compute, and storage solutions are available. Additionally botnets are available for rent or purchase. Use of these solutions allow an adversary to stage, launch, and execute an attack from infrastructure that does not physically tie back to them and can be rapidly provisioned, modified, and shut down.



-------------------------------
### Acquire and/or use 3rd party software services
* [Acquire and/or use 3rd party software services - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1085)
	* A wide variety of 3rd party software services are available (e.g., Twitter, Dropbox, GoogleDocs). Use of these solutions allow an adversary to stage, launch, and execute an attack from infrastructure that does not physically tie back to them and can be rapidly provisioned, modified, and shut down.


-------------------------------
### Acquire or compromise 3rd party signing certificates
* [Acquire or compromise 3rd party signing certificates - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1087)
	* Code signing is the process of digitally signing executables or scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Users may trust a signed piece of code more than an signed piece of code even if they don't know who issued the certificate or who the author is.

-------------------------------
### Anonymity services
* [Anonymity services - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1083)
	* Anonymity services reduce the amount of information available that can be used to track an adversary's activities. Multiple options are available to hide activity, limit tracking, and increase anonymity.



-------------------------------
### Common, high volume protocols and software
* [Common, high volume protocols and software - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1098)
	* Certain types of traffic (e.g., Twitter14, HTTP) are more commonly used than others. Utilizing more common protocols and software may make an adversary's traffic more difficult to distinguish from legitimate traffic.


-------------------------------
### Compromise 3rd party infrastructure to support delivery
* [Compromise 3rd party infrastructure to support delivery - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1089)
	* Instead of buying, leasing, or renting infrastructure an adversary may compromise infrastructure and use it for some or all of the attack cycle.


-------------------------------
### DNSCalc
* [DNSCalc - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1101)
	* DNS Calc is a technique in which the octets of an IP address are used to calculate the port for command and control servers from an initial DNS request.



-------------------------------
### Data Hiding
* [Data Hiding - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1097)
	* Certain types of traffic (e.g., DNS tunneling, header inject) allow for user-defined fields. These fields can then be used to hide data. In addition to hiding data in network protocols, steganography techniques can be used to hide data in images or other file formats. Detection can be difficult unless a particular signature is already known.


-------------------------------
### Domain Generation Algorithms (DGA)
* [Domain Generation Algorithms (DGA) - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1100)
	* The use of algorithms in malware to periodically generate a large number of domain names which function as rendezvous points for malware command and control servers.


-------------------------------
### Dynamic DNS
* [Dynamic DNS - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1088)
	* Dynamic DNS is a method of automatically updating a name in the DNS system. Providers offer this rapid reconfiguration of IPs to hostnames as a service.



-------------------------------
### Fast Flux DNS
* [Fast Flux DNS - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1102)
	* A technique in which a fully qualified domain name has multiple IP addresses assigned to it which are swapped with extreme frequency, using a combination of round robin IP address and short Time-To-Live (TTL) for a DNS resource record.


-------------------------------
### Host-based hiding techniques
* [Host-based hiding techniques - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1091)
	* Host based hiding techniques are designed to allow an adversary to remain undetected on a machine upon which they have taken action. They may do this through the use of static linking of binaries, polymorphic code, exploiting weakness in file formats, parsers, or self-deleting code.


-------------------------------
### Misattributable credentials
* [Misattributable credentials - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1099)
	* The use of credentials by an adversary with the intent to hide their true identity and/or portray them self as another person or entity. An adversary may use misattributable credentials in an attack to convince a victim that credentials are legitimate and trustworthy when this is not actually the case.



-------------------------------
### Network-based hiding techniques
* [Network-based hiding techniques - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1092)
	* Technical network hiding techniques are methods of modifying traffic to evade network signature detection or to utilize misattribution techniques. Examples include channel/IP/VLAN hopping, mimicking legitimate operations, or seeding with misinformation.


-------------------------------
### Non-traditional or less attributable payment options
* [Non-traditional or less attributable payment options - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1093)
	* Using alternative payment options allows an adversary to hide their activities. Options include crypto currencies, barter systems, pre-paid cards or shell accounts.


-------------------------------
### OS-vendor provided communication channels
* [OS-vendor provided communication channels - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1167)
	* Google and Apple provide Google Cloud Messaging and Apple Push Notification Service, respectively, services designed to enable efficient communication between third-party mobile app backend servers and the mobile apps running on individual devices. These services maintain an encrypted connection between every mobile device and Google or Apple that cannot easily be inspected and must be allowed to traverse networks as part of normal device operation. These services could be used by adversaries for communication to compromised mobile devices.



-------------------------------
### Obfuscate infrastructure
* [Obfuscate infrastructure - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1086)
	* Obfuscation is hiding the day-to-day building and testing of new tools, chat servers, etc.


-------------------------------
### Obfuscate operational infrastructure
* [Obfuscate operational infrastructure - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1095)
	* Obfuscation is hiding the day-to-day building and testing of new tools, chat servers, etc.



-------------------------------
### Obfuscate or encrypt code
* [Obfuscate or encrypt code - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1096)
	* Obfuscation is the act of creating code that is more difficult to understand. Encoding transforms the code using a publicly available format. Encryption transforms the code such that it requires a key to reverse the encryption.



-------------------------------
### Obfuscation or cryptography
* [Obfuscation or cryptography - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1090)
	* Obfuscation is the act of creating communications that are more difficult to understand. Encryption transforms the communications such that it requires a key to reverse the encryption.


-------------------------------
### Private whois services
* [Private whois services - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1082)
	* Every domain registrar maintains a publicly viewable database that displays contact information for every registered domain. Private 'whois' services display alternative information, such as their own company data, rather than the owner of the domain.


-------------------------------
### Proxy/protocol relays
* [Proxy/protocol relays - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1081)
	* Proxies act as an intermediary for clients seeking resources from other systems. Using a proxy may make it more difficult to track back the origin of a network communication.



-------------------------------
### Secure and protect infrastructure
* [Secure and protect infrastructure - Pre-ATT&CK](https://attack.mitre.org/pre-attack/index.php/Technique/PRE-T1094)
	* An adversary may secure and protect their infrastructure just as defenders do. This could include the use of VPNs, security software, logging and monitoring, passwords, or other defensive measures.



