# Ports & Commonly Associated Services

## Ports

[https://github.com/mubix/akb/blob/master/Scanning/ports.md](https://github.com/mubix/akb/blob/master/Scanning/ports.md)

| **Port Number** | **Protocol** | **Service & Application** | **Commands** |
| :--- | :--- | :--- | :--- |
| 1 | tcp | blackice |  |
| 7 | tcp | echo |  |
| 11 | tcp | systat |  |
| 13 | tcp | daytime |  |
| 15 | tcp | netstat |  |
| 17 | tcp | quote of the day |  |
| 19 | tcp | character generator |  |
| 21 | tcp | ftp | nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 _IP_ |
| 22 | tcp | ssh | msf &gt; use auxiliary/scanner/ssh/ssh\_login nmap --script ssh2-enum-algos 192.168.108.197 nmap --script ssh-hostkey _IP_ nmap --script sshv1 192.168.108.197 |
| 23 | tcp | telnet | msf &gt; use auxiliary/scanner/telnet/telnet\_login nmap -p 23 --script telnet-brute --script-args _IP_ userdb=myusers.lst,passdb=mypwds.lst,telnet-brute.timeout=8s _IP_ nmap -p 23 --script telnet-encryption _IP_ nmap -p 23 --script telnet-ntlm-info _IP_ |
| 25 | tcp | smtp | nmap -p 25 --script smtp-brute _IP_ nmap --script smtp-commands.nse \[--script-args smtp-commands.domain=`domain`\] -pT:25,465,587 _IP_ nmap -p 25,465,587 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=domain.com _IP_ nmap --script smtp-open-relay.nse \[--script-args smtp-open-relay.domain=`domain`,smtp-open-relay.ip=`address`,...\] -p 25,465,587 _IP_ nmap --script=smtp-vuln-cve2010-4344 --script-args="smtp-vuln-cve2010-4344.exploit" -pT:25,465,587 _IP_ nmap --script=smtp-vuln-cve2010-4344 --script-args="exploit.cmd='uname -a'" -pT:25,465,587 _IP_ nmap --script=smtp-vuln-cve2011-1720 --script-args='smtp.domain=`domain`' -pT:25,465,587 _IP_ nmap --script=smtp-vuln-cve2011-1764 -pT:25,465,587 _IP_ |
| 26 | tcp | ssh |  |
| 37 | tcp | rdate |  |
| 49 | tcp | TACACS+ |  |
| 53 | tcp | dns |  |
| 53 | udp | dns |  |
| 67 | tcp | DHCP |  |
| 68 | tcp | dhclient |  |
| 69 | udp | TFTP,BitTorrent |  |
| 70 | tcp | Gopher |  |
| 79 | tcp | Finger |  |
| 80 | tcp | HTTP,malware |  |
| 81 | tcp | HTTP,malware |  |
| 82 | tcp | HTTP,malware |  |
| 83 | tcp | HTTP |  |
| 84 | tcp | HTTP |  |
| 88 | tcp | Kerberos | use auxiliary/admin/kerberos/ms14\_068\_kerberos\_checksum |
| 102 | tcp | Siemens S7 |  |
| 110 | tcp | pop3 |  |
| 111 | tcp | RPC | rpcinfo -p 192.168.1.111 msf &gt;use auxiliary/scanner/nfs/nfsmount  Nfspy |
| 119 | tcp | NNTP |  |
| 123 | tcp | NTP |  |
| 123 | udp | ntp | ntpdc -n -c monlist _IP_ nmap -sU -p 123 -Pn -n --script ntp-info _IP_ nmap -sU -p 123 -Pn -n --script ntp-monlist _IP_ msf &gt; use auxiliary/scanner/ntp/ntp\_readvar |
| 137 | tcp | NetBIOS | nbtscan -A _IP_ |
| 139 | tcp | SMB | enum4linux -a _IP_ rpcclient -U "" _IP_ + srvinfo; enumdomusers; getdompwinfo; querydominfo; netshareenum; netshareenumall |
| 143 | tcp | IMAP |  |
| 161 | udp | snmp | snmpcheck -p 161 -c public -t _IP_ snmpwalk -v1 -c public _IP_ msf &gt; use auxiliary/scanner/snmp/snmp\_enum |
| 162 | udp | snmp |  |
| 175 | tcp | IBM Network Job Entry |  |
| 179 | tcp | BGP |  |
| 195 | tcp | TA14-353a |  |
| 264 |  | Checkpoint Firewall |  |
| 311 | tcp | OS X Server Manager |  |
| 389 | tcp | ldap | ldap://_IP_/dc=com |
| 443 | tcp | https | openssl s\_client -host _ADDR_ -port 443 sslscan _ADDR_ tlssled _ADDR_ 443 nmap --script sslv2 _ADDR_ nmap --script ssl-cert _ADDR_ nmap --script ssl-date _ADDR_ nmap --script ssl-enum-ciphers _ADDR_ nmap --script ssl-google-cert-catalog _ADDR_ msf &gt; use auxiliary/pro/web\_ssl\_scan msf &gt; use auxiliary/scanner/ssl/openssl\_heartbleed msf &gt; use auxiliary/server/openssl\_heartbeat\_client\_memory |
| 445 | tcp | Microsoft-DS Active Directory, Windows shares Microsoft-DS SMB file sharing | smbclient -U root -L _IP_ smbclient -U root //_IP_/tmp rpcclient -U "" _IP_ msf &gt; auxiliary/admin/smb/samba\_symlink\_traversal |
| 465 | tcp | smtps |  |
| 500 | udp | ike |  |
| 502 | tcp | modbus |  |
| 503 | tcp | modbus |  |
| 512 | tcp |  |  |
| 513 | tcp |  |  |
| 514 | tcp |  |  |
| 515 | tcp | Line Printer Daemon |  |
| 520 | tcp | RIP |  |
| 523 | tcp | IBM DB2 |  |
| 554 | tcp | RTSP |  |
| 587 | tcp | SMTP mail submission |  |
| 623 | tcp | IPMI |  |
| 626 | tcp | OS X serialnumbered |  |
| 631 | tcp | CUPS Service error |  |
| 636 | tcp | ldaps |  |
| 771 | tcp | Realport |  |
| 789 | tcp | Redlion Crimson3 |  |
| 873 | tcp | rsync | rsync -a user@host::tools/ nmap -p 873 --script rsync-brute --script-args 'rsync-brute.module=www' _IP_ nmap -p 873 --script rsync-list-modules _IP_ msf &gt;use auxiliary/scanner/rsync/modules\_list |
| 902 | tcp | VMware authentication |  |
| 953 |  | BIND Contorl Port |  |
| 992 | tcp | Telnet\(secure\) |  |
| 993 | tcp | IMAPs |  |
| 995 | tcp | POP3s |  |
| 1023 | tcp | telnet |  |
| 1025 | tcp | Kamstrup |  |
| 1030 | tcp | RPC |  |
| 1032 | tcp | RPC |  |
| 1033 | tcp | RPC |  |
| 1038 | tcp | RPC |  |
| 1099 | tcp | Remote Method invocation | use exploit/multi/misc/java\_rmi\_server |
| 1194 | tcp | openvpn |  |
| 1200 | tcp | Codesys |  |
| 1234 | udp | udpxy |  |
| 1202 | tcp | linknat |  |
| 1433 | tcp | MS-SQL | MSF&gt;use auxiliary/scanner/mssql/mssql\_ping |
| 1434 | udp | MS-SQL monitor |  |
| 1521 | tcp | Oracle | tnscmd10g version/status -h _IP_ |
| 1604 |  | Citrix, malware |  |
| 1723 | tcp | pptp | thc-pptp-bruter -v -u `username` -n 4 _IP_ &lt; pass.txt |
| 1741 |  | CiscoWorks |  |
| 1833 |  | MQTT |  |
| 1900 | tcp | bes,UPnP |  |
| 1911 |  | Niagara Fox |  |
| 1962 |  | PCworx |  |
| 2000 |  | iKettle,MikroTik bandwidth test |  |
| 2049 | tcp | nfs | showmount --all _IP_ showmount --exports _IP_  mount -t nfs _IP_:/ /mnt/nfs/ Nfspy |
| 2082 | tcp | cpanel |  |
| 2083 | tcp | cpanel |  |
| 2086 |  | WHM |  |
| 2087 |  | WHM |  |
| 2100 | tcp | Oracel XML DB | [Default Username/Passwords](https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm) |
| 2121 | tcp | ftp | msf &gt; use auxiliary/scanner/ftp/ftp\_login |
| 2123 |  | GTPv1 |  |
| 2152 |  | GTPv1 |  |
| 2182 |  | Apache Zookeeper |  |
| 2222 | tcp | SSH, PLC5, EtherNet/IP |  |
| 2323 | tcp | telnet |  |
| 2332 | tcp | Sierra wireless\(telnet\) |  |
| 2375 |  | Docker |  |
| 2376 |  | Docker |  |
| 2404 |  | IEC-104 |  |
| 2455 |  | CoDeSys |  |
| 2480 |  | OrientDB |  |
| 2628 |  | Dictionary |  |
| 2967 |  | Symantec System Center Alert Management System |  |
| 3000 |  | ntop |  |
| 3128 | tcp | squid |  |
| 3299 | tcp | sap | msf &gt; use auxiliary/scanner/sap/sap\_router\_portscanner |
| 3306 | tcp | mysql | msf &gt; auxiliary/scanner/mysql/mysql\_login nmap --script mysql-brute _IP_ nmap --script mysql-databases _IP_ nmap -p 3306 --script mysql-dump-hashes _IP_  --script-args='username=`username`,password=`password`' _IP_ nmap -p 3306 --script mysql-enum _IP_ nmap -p 3306 --script mysql-users _IP_ nmap -p 3306  --script mysql-query --script-args='query="`query`"\[,username=`username`,password=`password`\] _IP_' |
| 3310 | tcp | ClamAV |  |
| 3339 | Oracle Web Interace |  |  |
| 3386 |  | GTPv1 |  |
| 3388 |  | RDP |  |
| 3389 |  | RDP | rdesktop -u guest -p guest _IP_ -g 94% rdp-sec-check _IP_ |
| 3541 |  | PBX GUI |  |
| 3542 |  | PBX GUI |  |
| 3632 | tcp | distccd | msf &gt; use exploit/unix/misc/distcc\_exec |
| 3689 |  | DACP |  |
| 3780 |  | Metasploit |  |
| 3787 |  | Ventrilo |  |
| 4022 |  | udpxy |  |
| 4369 | tcp | Erlang Port Mapper Daemon | nmap -p 4369 --script epmd-info _IP_ |
| 4440 | tcp | rundeck |  |
| 4500 |  | IKE NAT-T\(VPN\) |  |
| 4567 |  | Modem web interface |  |
| 4070 |  | VertX/Edge door controller |  |
| 4800 |  | Noxa Nport |  |
| 4911 |  | Niagara Fox with SSL |  |
| 4949 |  | Munin |  |
| 5006 |  | MELSEC-Q |  |
| 5007 |  | MELSEC-Q |  |
| 5008 |  | NetMobility |  |
| 5009 |  | Apple Aitport Administrator |  |
| 5038 | tcp | Asterisk Call Manager | [http://code.google.com/p/sipvicious/](http://code.google.com/p/sipvicious/)  $ ncat -v 192.168.108.196 5038 Ncat: Version 6.47 \( [http://nmap.org/ncat](http://nmap.org/ncat) \) Ncat: Connected to 192.168.108.196:5038. Asterisk Call Manager/1.1 action: login username: admin secret: amp111  Response: Success Message: Authentication accepted action: command command: core show help |
| 5432 | tcp | postgresql |  |
| 5060 | udp | sip | msf &gt; use auxiliary/scanner/sip/options |
| 5222 |  | XMPP |  |
| 5269 |  | XMPP Server to Server |  |
| 5353 |  | mDNS |  |
| 5357 |  | Mirosoft-HTTP API/2.0 |  |
| 5432 |  | Postgresql |  |
| 5555 | tcp | hp data protector | msf &gt; use exploit/windows/misc/hp\_dataprotector\_cmd\_exec |
| 5577 |  | Flux LED |  |
| 5601 | tcp | kibana |  |
| 5632 |  | PCAnywhere |  |
| 5672 |  | RabbitMQ |  |
| 5900 | tcp | vnc | msf &gt; use auxiliary/scanner/vnc/vnc\_none\_auth msf &gt; use auxiliary/scanner/vnc/vnc\_login  msf &gt; use exploit/multi/vnc/vnc\_keyboard\_exec nmap --script vnc-brute -p 5900  nmap --script vnc-info -p 5900  |
| 5901 |  | vnc |  |
| 5938 |  | TeamViewer |  |
| 5984 |  | CouchDB |  |
| 5985 | tcp | winrm | msf &gt;use exploit/windows/winrm/winrm\_script\_exec msf &gt;use auxiliary/scanner/winrm/winrm\_auth\_methods msf &gt;use auxiliary/scanner/winrm/winrm\_cmd msf &gt;use auxiliary/scanner/winrm/winrm\_login msf &gt;use auxiliary/scanner/winrm/winrm\_wql |
| 6000 | tcp | x11 | xwd -root -screen -slient -display 192.168.1.108:0 &gt; out.xwd convert out.xwd out.png |
| 6379 | tcp | redis | redis-cli -h 127.0.0.1 -p 6379 msf &gt;use auxiliary/scanner/redis/file\_upload msf &gt;use auxiliary/scanner/redis/redis\_login use auxiliary/scanner/redis/redis\_server |
| 6380 | tcp | redis |  |
| 6082 | tcp | varnish |  |
| 6667 | tcp | ircd backdoor | msf &gt; use exploit/unix/irc/unreal\_ircd\_3281\_backdoor |
| 6881 |  | BitTorrent |  |
| 6969 |  | TFTP,BitTorrent |  |
| 7001 | tcp | weblogic |  |
| 8080 | tcp | jekins | Jekins Console println "cmd.exe /c dir".execute\(\).text  msf &gt;use auxiliary/scanner/http/jenkins\_enum msf &gt;use exploit/multi/http/jenkins\_script\_console |
| 8083 | tcp | vestacp |  |
| 8089 | tcp | jboss |  |
| 8101 | tcp | apache karaf |  |
| 8180 | tcp | apache tomcat | msf &gt; use exploit/multi/http/tomcat\_mgr\_deploy |
| 8443 | tcp | https |  |
| 8443 |  | Symantec SEP Manager |  |
| 8554 | tcp | rtsp |  |
| 8649 | tcp | ganglia |  |
| 9009 | tcp | Julia |  |
| 9043 | tcp | WebSpeher |  |
| 9090 |  | Symantec SEP Manager |  |
| 9151 | tcp | Tor Control |  |
| 9160 |  | Apache Cassandra |  |
| 9200 | tcp | elasticsearch | msf &gt;use exploit/multi/elasticsearch/search\_groovy\_script |
| 9418 | tcp | git |  |
| 10000 | tcp | virtualmin/webmin |  |
| 11211 | tcp | memcache | msf &gt; use auxiliary/gather/memcached\_extractor $ nc x.x.x.x 11211 stats\r\n |
| 12174 | tcp | Symantec System Center Alert Management System |  |
| 13579 |  | Media Player classic web interface |  |
| 17185 |  | VxWorks WDBRPC |  |
| 18083 | tcp | vbox server |  |
| 27017 | tcp | mongodb | msf &gt;use auxiliary/scanner/mongodb/mongodb\_login $ mongo host:port/database MongoDB shell version: 2.6.12 &gt; help |
| 28017 | tcp | mongodb |  |
| 37777 |  | Dahua DVR |  |
| 38292 |  | Symantec System Center Alert Management System |  |
| 44818 |  | EtherNet/IP |  |
| 49153 |  | WeMo Link |  |
| 50000 | tcp | sap |  |
| 50030 | tcp | hadoop |  |
| 50070 | tcp | hadoop |  |
| 51106 |  | Deluge\(HTTP\) |  |
| 54138 |  | Toshiba PoS |  |
| 55553 |  | Metasploit |  |
| 55554 |  | Metasploit |  |
| 62078 |  | Apple iDevice |  |
| 64738 |  | Mumble |  |

## Links

1. [http://www.rfc-editor.org/search/rfc\_search.php](http://www.rfc-editor.org/search/rfc_search.php)
2. [http://packetlife.net/](http://packetlife.net/)
3. [https://www.leanpub.com/shodan](https://www.leanpub.com/shodan)

```text
Originally taken from: https://github.com/nixawk/pentest-wiki/blob/master/3.Exploitation-Tools/Network-Exploitation/ports_number.md
The MIT License (MIT)

Copyright (c) 2016 Vex Woo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

