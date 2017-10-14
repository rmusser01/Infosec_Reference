## Mac Exfiltration

------------------------------- 
## Automated Exfiltration
[Automated Exfiltration - ATT&CK](https://attack.mitre.org/wiki/Technique/T1020)
* Data, such as sensitive documents, may be exfiltrated through the use of automated processing or Scripting after being gathered during Collection. 









------------------------------- 
## Data Compressed
[Data Compressed - ATT&CK](https://attack.mitre.org/wiki/Technique/T1002)
* An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib. 











------------------------------- 
## Data Encrypted
[Data Encrypted - ATT&CK](https://attack.mitre.org/wiki/Technique/T1022)
* Data is encrypted before being exfiltrated in order to hide the information that is being exfiltrated from detection or to make the exfiltration less conspicuous upon inspection by a defender. The encryption is performed by a utility, programming library, or custom algorithm on the data itself and is considered separate from any encryption performed by the command and control or file transfer protocol. Common file archive formats that can encrypt files are RAR and zip. 










------------------------------- 
## Data Transfer Size Limits
[Data Transfer Size Limits - ATT&CK](https://attack.mitre.org/wiki/Technique/T1030)
* An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts. 












------------------------------- 
## Exfiltration Over Alternative Protocol
[Exfiltration Over Alternative Protocol - ATT&CK](https://attack.mitre.org/wiki/Technique/T1048)
* Data exfiltration is performed with a different protocol from the main command and control protocol or channel. The data is likely to be sent to an alternate network location from the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, or some other network protocol. Different channels could include Internet Web services such as cloud storage. 













---------------------------------
## Exfiltration Over Command and Control Channel
[Exfiltration Over Command and Control Channel - ATT&CK](https://attack.mitre.org/wiki/Technique/T1048)









------------------------------- 
## Exfiltration Over Other Network Medium
[Exfiltration Over Other Network Medium - ATT&CK](https://attack.mitre.org/wiki/Technique/T1011)
* Exfiltration could occur over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel. Adversaries could choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network. 












------------------------------- 
## Exfiltration Over Physical Medium
[Exfiltration Over Physical Medium - ATT&CK](https://attack.mitre.org/wiki/Technique/T1052)
Data exfiltration may be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability. 













------------------------------- 
## Scheduled Transfer 
[Scheduled Transfer - ATT&CK](https://attack.mitre.org/wiki/Technique/T1029)
* Data exfiltration may be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability. 	





