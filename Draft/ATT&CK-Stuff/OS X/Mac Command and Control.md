## Mac Command and Control



------------------------------- 
## Commonly Used Port
[Commonly Used Port - ATT&CK](https://attack.mitre.org/wiki/Technique/T1043)
* Adversaries may communicate over a commonly used port to bypass firewalls or network detection systems and to blend with normal network activity to avoid more detailed inspection.





------------------------------- 
## Communication Through Removable Media
[Communication Through Removable Media - ATT&CK](https://attack.mitre.org/wiki/Technique/T1092)
* Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system. Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by Replication Through Removable Media. Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access. 






------------------------------- 
## Connection Proxy
[Connection Proxy - ATT&CK](https://attack.mitre.org/wiki/Technique/T1090)
* A connection proxy is used to direct network traffic between systems or act as an intermediary for network communications. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap.
* The definition of a proxy can also be expanded out to encompass trust relationships between networks in peer-to-peer, mesh, or trusted connections between networks consisting of hosts or systems that regularly communicate with each other.
* The network may be within a single organization or across organizations with trust relationships. Adversaries could use these types of relationships to manage command and control communications, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. 









------------------------------- 
## Custom Command and Control Protocol
[Custom Command and Control Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1094)
* Adversaries may communicate using a custom command and control protocol instead of using existing Standard Application Layer Protocol to encapsulate commands. Implementations could mimic well-known protocols. 







------------------------------- 
## Custom Cryptographic Protocol
[Custom Cryptographic Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1024)
* Adversaries may use a custom cryptographic protocol or algorithm to hide command and control traffic. A simple scheme, such as XOR-ing the plaintext with a fixed key, will produce a very weak ciphertext.
* Custom encryption schemes may vary in sophistication. Analysis and reverse engineering of malware samples may be enough to discover the algorithm and encryption key used.
* Some adversaries may also attempt to implement their own version of a well-known cryptographic algorithm instead of using a known implementation library, which may lead to unintentional errors.












------------------------------- 
## Data Encoding
[Data Encoding - ATT&CK](https://attack.mitre.org/wiki/Technique/T1132)
* Command and control (C2) information is encoded using a standard data encoding system. Use of data encoding may be to adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, UTF-8, or other binary-to-text and character encoding systems. Some data encoding systems may also result in data compression, such as gzip. 









------------------------------- 
## Data Obfuscation
[Data Obfuscation - ATT&CK](https://attack.mitre.org/wiki/Technique/T1001)
* Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, commingling legitimate traffic with C2 communications traffic, or using a non-standard data encoding system, such as a modified Base64 encoding for the message body of an HTTP request. 










------------------------------- 
## Fallback Channels
[Fallback Channels - ATT&CK](https://attack.mitre.org/wiki/Technique/T1008)
* Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds. 











------------------------------- 
## Multi-Stage Channels
[Multi-Stage Channels - ATT&CK](https://attack.mitre.org/wiki/Technique/T1104)
* Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.
* Remote access tools will call back to the first-stage command and control server for instructions. The first stage may have automated capabilities to collect basic host information, update tools, and upload additional files. A second remote access tool (RAT) could be uploaded at that point to redirect the host to the second-stage command and control server. The second stage will likely be more fully featured and allow the adversary to interact with the system through a reverse shell and additional RAT features.
* The different stages will likely be hosted separately with no overlapping infrastructure. The loader may also have backup first-stage callbacks or Fallback Channels in case the original first-stage communication path is discovered and blocked. 

























------------------------------- 
## Multiband Communication
[Multiband Communication - ATT&CK](https://attack.mitre.org/wiki/Technique/T1026)
* Some adversaries may split communications between different protocols. There could be one protocol for inbound command and control and another for outbound data, allowing it to bypass certain firewall restrictions. The split could also be random to simply avoid data threshold alerts on any one communication. 








------------------------------- 
## Multilayer Encryption
[Multilayer Encryption - ATT&CK](https://attack.mitre.org/wiki/Technique/T1079)
* An adversary performs C2 communications using multiple layers of encryption, typically (but not exclusively) tunneling a custom encryption scheme within a protocol encryption scheme such as HTTPS or SMTPS. 









------------------------------- 
## Remote File Copy
[Remote File Copy - ATT&CK](https://attack.mitre.org/wiki/Technique/T1105)
* Files may be copied from one system to another to stage adversary tools or other files over the course of an operation. Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.
* Adversaries may also copy files laterally between internal victim systems to support Lateral Movement with remote Execution using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with Windows Admin Shares or Remote Desktop Protocol. 









------------------------------- 
## Standard Application Layer Protocol
[Standard Application Layer Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1071)
* Adversaries may communicate using a common, standardized application layer protocol such as HTTP, HTTPS, SMTP, or DNS to avoid detection by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.
 *For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are RPC, SSH, or RDP. 
















------------------------------- 
## Standard Cryptographic Protocol
[Standard Cryptographic Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1032)
* Adversaries use command and control over an encrypted channel using a known encryption protocol like HTTPS or SSL/TLS. The use of strong encryption makes it difficult for defenders to detect signatures within adversary command and control traffic.
* Some adversaries may use other encryption protocols and algorithms with symmetric keys, such as RC4, that rely on encryption keys encoded into malware configuration files and not public key cryptography. Such keys may be obtained through malware reverse engineering. 













------------------------------- 
## Standard Non-Application Layer Protocol
[Standard Non-Application Layer Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1095)
* Use of a standard non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive. Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), and transport layer protocols, such as the User Datagram Protocol (UDP).
* ICMP communication between hosts is one example. Because ICMP is part of the Internet Protocol Suite, it is required to be implemented by all IP-compatible hosts; however, it is not as commonly monitored as other Internet Protocols such as TCP or UDP and may be used by adversaries to hide communications.





------------------------------- 
## Uncommonly Used Port
[Uncommonly Used Port - ATT&CK](https://attack.mitre.org/wiki/Technique/T1065)
* Adversaries may conduct C2 communications over a non-standard port to bypass proxies and firewalls that have been improperly configured. 









------------------------------- 
## Web Service
[Web Service - ATT&CK](https://attack.mitre.org/wiki/Technique/T1102)
* Adversaries may use an existing, legitimate external Web service as a means for relaying commands to a compromised system.
* Popular websites and social media can act as a mechanism for command and control and give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection. 

