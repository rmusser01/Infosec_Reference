## Game Hacking


### TOC
* [General](#general)
* [Writeups](#writeups)
* [Console Hacking](#console)
* [Videos/Talks](#videos)
* [Reverse Engineering Games](#re)
* [Tools](#tools)










#### Sort



#### End Sort

### <a name="general"></a>General


[PwnAdventureZ](https://github.com/Vector35/PwnAdventureZ)
* NES zombie survival game made to be hacked 



#### <a name="writeups"></a>Writeups


[How do emulators work and how are they written?](https://stackoverflow.com/questions/448673/how-do-emulators-work-and-how-are-they-written)

[Reverse Engineering Strike Commander](http://fabiensanglard.net/reverse_engineering_strike_commander/index.php)

[Remote Code Execution In Source Games](https://oneupsecurity.com/research/remote-code-execution-in-source-games?t=r)

[Gotta catch-em-all worldwide - Pokemon GO GPS spoofing](https://insinuator.net/2016/07/gotta-catch-em-all-worldwide-or-how-to-spoof-gps-to-cheat-at-pokemon-go/)




### <a name="console"></a>Console Hacking
##### Nintendo 3DS
[Keyshuffling Attack for Persistent Early Code Execution in the Nintendo 3DS Secure Bootchain](https://github.com/Plailect/keyshuffling)
* We demonstrate an attack on the secure bootchain of the Nintendo 3DS in order to gain early code execution. The attack utilizes the block shuffling vulnerability of the ECB cipher mode to rearrange keys in the Nintendo 3DS's encrypted keystore. Because the shuffled keys will deterministically decrypt the encrypted firmware binary to incorrect plaintext data and execute it, and because the device's memory contents are kept between hard reboots, it is possible to reliably reach a branching instruction to a payload in memory. This payload, due to its execution by a privileged processor and its early execution, is able to extract the hash of hardware secrets necessary to decrypt the device's encrypted keystore and set up a persistant exploit of the system.

[ARM9Loader Technical Details - GBAtemp](https://gbatemp.net/threads/arm9loader-technical-details-and-discussion.408537/)

[Throwback: K9Lhax by Bruteforce](http://douevenknow.us/post/151129092928/throwback-k9lhax-by-bruteforce)

### Nintendo Wii 

[wiihacks forum](http://www.wiihacks.com/)

#### PS Vita

[Hacking the PS Vita](http://yifan.lu/2015/06/21/hacking-the-ps-vita/)





#### <a name="videos"></a>Videos & Talks

[The Multibillion Dollar Industry That's Ignored](http://www.irongeek.com/i.php?page=videos/derbycon4/t204-the-multibillion-dollar-industry-thats-ignored-jason-montgomery-and-ryan-sevey)

[Creating A Kewl And Simple Cheating Platform On Android - DeepSec2014](http://www.securitytube.net/video/12547?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SecurityTube+%28SecurityTube.Net%29)

[DEFCON 17: Fragging Game Servers - Bruce Potter](https://www.youtube.com/watch?v=SooVvF9qO_k&app=desktop)











### <a name="re"></a>RE



### <a name="tools"></a>Tools

[Pince](https://github.com/korcankaraokcu/PINCE)
* PINCE is a gdb front-end/reverse engineering tool focused on games, but it can be used for any reverse-engineering related stuff. PINCE is an abbreviation for "PINCE is not Cheat Engine". PINCE's GUI is heavily "inspired(;D)" by Cheat Engine. 

[ugtrain](https://github.com/ugtrain/ugtrain)
* Universal Elite Game Trainer for CLI(linux game trainer)

[CSGOSimple](https://github.com/MarkHC/CSGOSimple)
* A simple base for internal Counter-Strike: Global Offensive cheats.

[NoEye](https://github.com/Schnocker/NoEye)
* An usermode BE Rootkit Bypass

[PubgPrivXcode85](https://github.com/TonyZesto/PubgPrivXcode85)
* Simple chams wallhack for Player Unknowns Battlegrounds using a D3D11DrawIndexed hook

[PortAIO-Loader](https://github.com/PirateEmpire/PortAIO-Loader) 











