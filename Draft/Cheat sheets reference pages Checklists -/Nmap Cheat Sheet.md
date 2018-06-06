## Nmap Cheat Sheet

### Basic Scanning Techniques
* Scan a single target
	* `nmap [target]`
* Scan multiple targets
	* `nmap [target1,target2,etc]`
* Scan a list of targets
	* `nmap -iL [list.txt]`
* Scan a range of hosts
	* `nmap [range of IP addresses]
* Scan an entire subnet	
	* `nmap [IP address/cdir]`
* Scan random hosts 
	* `nmap -iR [number]`
* Excluding targets from a scan	
	* `nmap [targets] –exclude [targets]`
* Excluding targets using a list
	* `nmap [targets] –excludefile [list.txt]`
* Perform an aggressive scan
	* `nmap -A [target]`
* Scan an IPv6 target
	* `nmap -6 [target]`

### Discovery Options
* Perform a ping scan only
	* `nmap -sP [target]`
* Don’t ping
	* `nmap -PN [target]`
* TCP SYN Ping	
	* `nmap -PS [target]`
* TCP ACK ping
	* `nmap -PA [target]`
* UDP ping
	* `nmap -PU [target]`
* SCTP Init Ping
	* `nmap -PY [target]`
* ICMP echo ping
	* `nmap -PE [target]`
* ICMP Timestamp ping
	* `nmap -PP [target]`
* ICMP address mask ping
	* `nmap -PM [target]`
* IP protocol ping
	* `nmap -PO [target]
* ARP ping
	* `nmap -PR [target]`
* Traceroute
	* `nmap –traceroute [target]`
* Force reverse DNS resolution
	* `nmap -R [target]`
* Disable reverse DNS resolution
	* `nmap -n [target]`
* Alternative DNS lookup
	* `nmap –system-dns [target]`
* Manually specify DNS servers
	* `nmap –dns-servers [servers] [target]`
* Create a host list
	* `nmap -sL [targets]`

### Advanced Scanning Options
* TCP SYN Scan
	* `nmap -sS [target]`
* TCP connect scan
	* `nmap -sT [target]`
* UDP scan
	* `nmap -sU [target]`
* TCP Null scan
	* `nmap -sN [target]`
* TCP Fin scan
	* `nmap -sF [target]`
* Xmas scan
	* `nmap -sX [target]`
* TCP ACK scan
	* `nmap -sA [target]`
* Custom TCP scan
	* `nmap –scanflags [flags] [target]`
* IP protocol scan
	* `nmap -sO [target]`
* Send Raw Ethernet packets
	* `nmap –send-eth [target]`
* Send IP packets
	* `nmap –send-ip [target]`

### Port Scanning Options
* Perform a fast scan
	* `nmap -F [target]`
* Scan specific ports
	* `nmap -p [ports] [target]`
* Scan ports by name
	* `nmap -p [port name] [target]`
* Scan ports by protocol
	* `nmap -sU -sT -p U:[ports],T:[ports] [target]`
* Scan all ports
	* `nmap -p “*” [target]`
* Scan top ports
	* `nmap –top-ports [number] [target]
* Perform a sequential port scan
	* `nmap -r [target]`

### Version Detection
* Operating system detection
	* `nmap -O [target]`
* Submit TCP/IP Fingerprints
	* `http://www.nmap.org/submit/`
* Attempt to guess an unknown
	* `nmap -O –osscan-guess [target]`
* Service version detection
	* `nmap -sV [target]`
* Troubleshooting version scans
	* `nmap -sV –version-trace [target]`
* Perform a RPC scan
	* `nmap -sR [target]`

### Timing Options
* Timing Templates
	* `nmap -T [0-5] [target]`
* Set the packet TTL
	* `nmap –ttl [time] [target]`
* Minimum of parallel connections
	* `nmap –min-parallelism [number] [target]`
* Maximum of parallel connection
	* `nmap –max-parallelism [number] [target]`
* Minimum host group size
	* `nmap –min-hostgroup [number] [targets]`
* Maximum host group size
	* `nmap –max-hostgroup [number] [targets]`
* Maximum RTT timeout
	* `nmap –initial-rtt-timeout [time] [target]`
* Initial RTT timeout
	* `nmap –max-rtt-timeout [TTL] [target]`
* Maximum retries
	* `nmap –max-retries [number] [target]`
* Host timeout
	* `nmap –host-timeout [time] [target]`
* Minimum Scan delay
	* `nmap –scan-delay [time] [target]`
* Maximum scan delay
	* `nmap –max-scan-delay [time] [target]`
* Minimum packet rate
	* `nmap –min-rate [number] [target]`
* Maximum packet rate
	* `nmap –max-rate [number] [target]`
* Defeat reset rate limits
	* `nmap –defeat-rst-ratelimit [target]`

### Firewall Evasion Techniques
* Fragment packets
	* `nmap -f [target]`
* Specify a specific MTU
	* `nmap –mtu [MTU] [target]`
* Use a decoy
	* `nmap -D RND: [number] [target]`
* Idle zombie scan
	* `nmap -sI [zombie] [target]`
* Manually specify a source port
	* `nmap –source-port [port] [target]`
* Append random data
	* `nmap –data-length [size] [target]`
* Randomize target scan order
	* `nmap –randomize-hosts [target]`
* Spoof MAC Address
	* `nmap –spoof-mac [MAC|0|vendor] [target]`
* Send bad checksums
	* `nmap –badsum [target]`

### Output Options
* Save output to a text file
	* `nmap -oN [scan.txt] [target]`
* Save output to a xml file
	* `nmap -oX [scan.xml] [target]`
* Grepable output
	* `nmap -oG [scan.txt] [target]`
* Output all supported file types
	* `nmap -oA [path/filename] [target]`
* Periodically display statistics
	* `nmap –stats-every [time] [target]`
* 133t output
	* `nmap -oS [scan.txt] [target]`

### Troubleshooting and debugging
* Help
	* `nmap -h`
* Display Nmap version
	* `nmap -V`
* Verbose output
	* `nmap -v [target]`
* Debugging
	* `nmap -d [target]`
* Display port state reason
	* `nmap –reason [target]`
* Only display open ports
	* `nmap –open [target]`
* Trace packets
	* `nmap –packet-trace [target]`
* Display host networking
	* `nmap –iflist`
* Specify a network interface
	* `nmap -e [interface] [target]`

### Nmap Scripting Engine
* Execute individual scripts
	* `nmap –script [script.nse] [target]`
* Execute multiple scripts
	* `nmap –script [expression] [target]`
* Script categories
	* `all, auth, default, discovery, external, intrusive, malware, safe, vuln`
* Execute scripts by category
	* `nmap –script [category] [target]`
* Execute multiple scripts categories
	* `nmap –script [category1,category2, etc]`
* Troubleshoot scripts
	* `nmap –script [script] –script-trace [target]`
* Update the script database
	* `nmap –script-updatedb`

### Ndiff
* Comparison using Ndiff
	* `ndiff [scan1.xml] [scan2.xml]`
* Ndiff verbose mode
	* `ndiff -v [scan1.xml] [scan2.xml]`
* XML output mode
	* `ndiff –xml [scan1.xm] [scan2.xml]`

### Links
* [Man Pages - http://nmap.org/book/man.html](http://nmap.org/book/man.html
* [Nmap Scripting Engine - http://nmap.org/book/nse.html](http://nmap.org/book/nse.html)
* [Nmap Scripting Engine list of current scripts - http://nmap.org/nsedoc/index.html](http://nmap.org/nsedoc/index.html)
* [Nmap Scripting Engine Documentation - http://nmap.org/book/nse.html](http://nmap.org/nsedoc/index.html)
* [Common Nmap Comman Examples - http://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/](http://nmap.org/nsedoc/index.html)
* [30 Nmap Command Examples - http://www.cyberciti.biz/networking/nmap-command-examples-tutorials/](http://www.cyberciti.biz/networking/nmap-command-examples-tutorials/)


```
Handy Examples:
Nmap Basics:

Scan a single target
	nmap [IP]

Scan multiple IPs
	nmap [IP1,IP2,IP3…]

Scan a list
	nmap -iL [list.txt]

Scan a range of hosts
	nmap [10.1.1.1-10.1.1.200]

Scan an entire subnet
	nmap [IP address/cdir]

Excluding targets from a scan
	nmap [IP] –exclude [IP]

Excluding targets using a list
	nmap [IPs] –excludefile [list.txt]

Create a list of hosts scanned
  	nmap -sL [IPs

     Evasion
Fragment packets
	nmap -f [IP]

Specify a specific MTU
	nmap –mtu [MTU] [IP]

Append random data
	nmap –data-length [size] [IP]

Spoof MAC Address
	nmap –spoof-mac [MAC|0|vendor] [IP]

Send bad checksums
	nmap –badsum [IP]

Output
Save output to a text file
	nmap -oN [scan.txt] [IP]

Save output to a xml file
	nmap -oX [scan.xml] [IP]

Grepable output
	nmap -oG [scan.txt] [IP]

Output all supported file types
	nmap -oA [path/filename] [IP

Comparing Scan Results
Comparison using Ndiff 
	ndiff [scan1.xml] [scan2.xml]

Ndiff verbose mode
	ndiff -v [scan1.xml] [scan2.xml]

XML output mode 
	ndiff –xml [scan1.xm] [scan2.xml]]

Nmap Scripting Engine

Execute individual NSE scripts
	nmap –script [script.nse] [IP]

Execute multiple NSE scripts
	nmap –script [script1.nse,script2.nse…] [IP]

Execute NSE scripts by category
	nmap –script [cat] [target]

Execute multiple NSE script categories
	nmap –script [auth, default…] [IP]

NSE Script categories:
all 
auth
default
discovery
external
intrusive
malware
safe

Nmap default commands:
Usage: nmap [Scan Type(s)] [Options] {target specification}

TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.

  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile <exclude_file>: Exclude list from file

HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
  --traceroute: Trace hop path to each host

SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan

PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude the specified ports from scanning
  -F: Fast mode - Scan fewer ports than the default scan
  -r: Scan ports consecutively - don't randomize
  --top-ports <number>: Scan <number> most common ports
  --port-ratio <ratio>: Scan ports more common than <ratio>

SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
  --version-trace: Show detailed version scan activity (for debugging)

SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
           <Lua scripts> is a comma-separated list of script-files or
           script-categories.

OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively

TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
      probe round trip time.
  --max-retries <tries>: Caps number of port scan probe retransmissions.
  --host-timeout <time>: Give up on target after this long
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second

FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S <IP_Address>: Spoof source address
  -e <iface>: Use specified interface
  -g/--source-port <portnum>: Use given port number
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
  --data <hex string>: Append a custom payload to sent packets
  --data-string <string>: Append a custom ASCII string to sent packets
  --data-length <num>: Append random data to sent packets
  --ip-options <options>: Send packets with specified ip options
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum

OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format, respectively, to the given filename.
  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
  --reason: Display the reason a port is in a particular state
  --open: Only show open (or possibly open) ports
  --packet-trace: Show all packets sent and received
  --iflist: Print host interfaces and routes (for debugging)
  --log-errors: Log errors/warnings to the normal-format output file
  --append-output: Append to rather than clobber specified output files
  --resume <filename>: Resume an aborted scan
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output

MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
  --datadir <dirname>: Specify custom Nmap data file location
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
  --privileged: Assume that the user is fully privileged
  --unprivileged: Assume the user lacks raw socket privileges
  -V: Print version number
  -h: Print this help summary page.

EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
SEE THE MAN PAGE (http://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES
```
