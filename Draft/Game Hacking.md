# Game Hacking


## Table of Contents
* [General](#general)
* [Writeups](#writeups)
* [Console Hacking](#console)
* [Reverse Engineering Games](#re)
* [Talks & Presentations](#talks)
* [Tools](#tools)


#### Sort
Fix ToC
* [OwnedCore](http://www.ownedcore.com/forums/)
* [Cathook Training Software](https://github.com/nullifiedcat/cathook)

* [CSGOSimple](https://github.com/MarkHC/CSGOSimple)
	* A simple base for internal Counter-Strike: Global Offensive cheats.
* [NoEye](https://github.com/Schnocker/NoEye)
	* An usermode BE Rootkit Bypass
* [PubgPrivXcode85](https://github.com/TonyZesto/PubgPrivXcode85)
	* Simple chams wallhack for Player Unknowns Battlegrounds using a D3D11DrawIndexed hook
* [PortAIO-Loader](https://github.com/PirateEmpire/PortAIO-Loader) 


#### End Sort


------------
### <a name="general"></a>General
* **101**
* [The Ultimate Online Game Hacking Resource](https://github.com/dsasmblr/hacking-online-games)
	* From dissecting game clients to cracking network packet encryption, this is a go-to reference for those interested in the topic of hacking online games.
* **Educational**
	* [PwnAdventureZ](https://github.com/Vector35/PwnAdventureZ)
		* NES zombie survival game made to be hacked 
* **Writeups**
	* [Hack the Vote CTF "The Wall" Solution](https://zerosum0x0.blogspot.com/2016/11/hack-vote-wall-solution.html)
	* **Emulators**
		* [How do emulators work and how are they written?](https://stackoverflow.com/questions/448673/how-do-emulators-work-and-how-are-they-written)
	* **Breaking The Game**
		* [Gotta catch-em-all worldwide - Pokemon GO GPS spoofing](https://insinuator.net/2016/07/gotta-catch-em-all-worldwide-or-how-to-spoof-gps-to-cheat-at-pokemon-go/)
		* [How to hack an MMO - Raph Koster - 2008](https://www.raphkoster.com/2008/04/17/how-to-hack-an-mmo/)
	* **Reverse Engineering**
		* [Reverse Engineering Strike Commander](http://fabiensanglard.net/reverse_engineering_strike_commander/index.php)
		* [Creating a Packet Logger for Dragomon Hunter](https://0xbaadf00dsec.blogspot.com/2016/01/reverse-engineering-online-games.html)
		* [Unravelling Konami's Arcade DRM](http://mon.im/2017/12/konami-arcade-drm.html)
		* [Introduction to Server Side Emulation - Corillian - tuts4you](https://tuts4you.com/download.php?view.2758)
		* [Remote Code Execution In Source Games](https://oneupsecurity.com/research/remote-code-execution-in-source-games?t=r)
* **Non-Specific Tools**
	* [Pince](https://github.com/korcankaraokcu/PINCE)
		* PINCE is a gdb front-end/reverse engineering tool focused on games, but it can be used for any reverse-engineering related stuff. PINCE is an abbreviation for "PINCE is not Cheat Engine". PINCE's GUI is heavily "inspired(;D)" by Cheat Engine. 
	* [loadlibraryy](https://github.com/G-E-N-E-S-I-S/loadlibrayy)
		* x64 manualmapper with kernel elevation and thread hijacking capabilities to bypass anticheats
	* [MTuner](https://github.com/milostosic/MTuner)
		* MTuner is a C/C++ memory profiler and memory leak finder for Windows, PlayStation 4, PlayStation 3, etc.




------------
### Android
* [Creating A Kewl And Simple Cheating Platform On Android - DeepSec2014](http://www.securitytube.net/video/12547?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SecurityTube+%28SecurityTube.Net%29)


------------
## <a name="console"></a>Console Hacking



------------
### <a name="console"></a>Nintendo
* **Nintendo Gameboy**
	* [Reverse engineering a Gameboy ROM with radare2](https://www.megabeets.net/reverse-engineering-a-gameboy-rom-with-radare2/)
* **Nintendo Gameboy Pocket/Color**
* **Nintendo Gameboy Advance**
* **Nintendo 3DS**
	* **Articles/Writeups**
		* [Keyshuffling Attack for Persistent Early Code Execution in the Nintendo 3DS Secure Bootchain](https://github.com/Plailect/keyshuffling)
		* We demonstrate an attack on the secure bootchain of the Nintendo 3DS in order to gain early code execution. The attack utilizes the block shuffling vulnerability of the ECB cipher mode to rearrange keys in the Nintendo 3DS's encrypted keystore. Because the shuffled keys will deterministically decrypt the encrypted firmware binary to incorrect plaintext data and execute it, and because the device's memory contents are kept between hard reboots, it is possible to reliably reach a branching instruction to a payload in memory. This payload, due to its execution by a privileged processor and its early execution, is able to extract the hash of hardware secrets necessary to decrypt the device's encrypted keystore and set up a persistant exploit of the system.
	* [ARM9Loader Technical Details - GBAtemp](https://gbatemp.net/threads/arm9loader-technical-details-and-discussion.408537/)
	* [Throwback: K9Lhax by Bruteforce](http://douevenknow.us/post/151129092928/throwback-k9lhax-by-bruteforce)
	* **Emulator**
	* [Citra](https://citra-emu.org/)
* **Nintendo**
* **Nintendo Super Nintendo**
* **Nintendo64**
* **Articles/Writeups**
	* [Reversing the Nintendo 64 CIC - Mike Ryan, marshallh, and John McMaster - REcon 2015](https://www.youtube.com/watch?v=HwEdqAb2l50)
		* This presentation covers our successful efforts to reverse engineer and clone the Nintendo 64's copy protection chip: the N64 CIC. We describe the processes and techniques we used to finally conquer this chip, nearly 20 years after its introduction.
* **Tools**
	* [libdragon](https://dragonminded.com/n64dev/libdragon/)
		* libdragon is meant to be a one stop library providing low level API for all hardware features of the N64.
	* [64Drive](http://64drive.retroactive.be/)
	* [FAT64](https://lacklustre.net/projects/fat64/)
		* FAT64 is a FAT32 library for use on the 64drive, a development cart for the Nintendo 64. It is used by the 64drive bootloader and menu.
* **Nintendo Gamecube**
* **Nintendo Wii**
	* [wiihacks forum](http://www.wiihacks.com/)
	* [WiiHacks](https://www.reddit.com/r/WiiHacks/)
* **Nintendo Switch**
	* [yuzu](https://github.com/yuzu-emu/yuzu)
		* yuzu is an experimental open-source emulator for the Nintendo Switch from the creators of Citra. It is written in C++ with portability in mind, with builds actively maintained for Windows, Linux and macOS. The emulator is currently only useful for homebrew development and research purposes.



------------
#### Sony 
* **PSP / PS Vita**
	* [Hacking the PS Vita](http://yifan.lu/2015/06/21/hacking-the-ps-vita/)
	* [ Playstation Portable Cracking [24c3]](https://www.youtube.com/watch?v=TgzxyO2QO1M)
* **Sony PlayStation 1**
* **Sony PlayStation 2**
* **Sony PlayStation 3**
* **Sony PlayStation 4**
	* [PS4 4.05 Kernel Exploit](https://github.com/Cryptogenic/PS4-4.05-Kernel-Exploit/blob/master/README.md)
	* [The First PS4 Kernel Exploit: Adieu](https://fail0verflow.com/blog/2017/ps4-namedobj-exploit/)
	* ["NamedObj" 4.05 Kernel Exploit Writeup.md](https://github.com/Cryptogenic/Exploit-Writeups/blob/master/PS4/%22NamedObj%22%204.05%20Kernel%20Exploit%20Writeup.md)
	* [4.0x WebKit Exploit Writeup - Breaking down qwertyoruiopz's 4.0x userland exploit(https://github.com/Cryptogenic/Exploit-Writeups/blob/master/PS4/4.0x%20WebKit%20Exploit%20Writeup.md)
	* [NamedObj Kernel Exploit Overview(writeup)](https://github.com/Cryptogenic/Exploit-Writeups/blob/master/PS4/NamedObj%20Kernel%20Exploit%20Overview.md)


------------
### PC Games
* **101**
* **Educational**
	* [DEFCON 17: Fragging Game Servers - Bruce Potter](https://www.youtube.com/watch?v=SooVvF9qO_k&app=desktop)
	* [The Multibillion Dollar Industry That's Ignored](http://www.irongeek.com/i.php?page=videos/derbycon4/t204-the-multibillion-dollar-industry-thats-ignored-jason-montgomery-and-ryan-sevey)
* **Writeups**
	* **Cheat Prevention Software**
		* [Valve Anti-Cheat Untrusted Bans (VAC) CSGO](http://dev.cra0kalo.com/?p=521)
		* [How ESEA detects cheat software in its online gaming league - Let's get physical!](http://everdox.blogspot.com/2015/02/how-esea-detects-cheat-software-in-its.html)
			* Before we dig in, this post should not be construed as an attack on ESEA, anti-cheat software, or fair gaming in general. It is simply an analysis thereof, detailing what the ESEA driver does on your machine. Although analysis will make attack vectors clear and obvious, no code or detailed explanation of how to leverage these points will be given.
		* [Inside Blizzard: Battle.net](http://uninformed.org/?v=all&a=8&t=sumry)
			* This paper intends to describe a variety of the problems Blizzard Entertainment has encountered from a practical standpoint through their implementation of the large-scale online game matchmaking and chat service, Battle.net. The paper provides some background historical information into the design and purpose of Battle.net and continues on to discuss a variety of flaws that have been observed in the implementation of the system. Readers should come away with a better understanding of problems that can be easily introduced in designing a matchmaking/chat system to operate on such a large scale in addition to some of the serious security-related consequences of not performing proper parameter validation of untrusted clients. 
		* [An Objective Analysis of the Lockdown Protection System for Battle.net](http://uninformed.org/?v=all&a=40&t=sumry)
			* Near the end of 2006, Blizzard deployed the first major update to the version check and client software authentication system used to verify the authenticity of clients connecting to Battle.net using the binary game client protocol. This system had been in use since just after the release of the original Diablo game and the public launch of Battle.net. The new authentication module (Lockdown) introduced a variety of mechanisms designed to raise the bar with respect to spoofing a game client when logging on to Battle.net. In addition, the new authentication module also introduced run-time integrity checks of client binaries in memory. This is meant to provide simple detection of many client modifications (often labeled "hacks") that patch game code in-memory in order to modify game behavior. The Lockdown authentication module also introduced some anti-debugging techniques that are designed to make it more difficult to reverse engineer the module. In addition, several checks that are designed to make it difficult to simply load and run the Blizzard Lockdown module from the context of an unauthorized, non-Blizzard-game process. After all, if an attacker can simply load and run the Lockdown module in his or her own process, it becomes trivially easy to spoof the game client logon process, or to allow a modified game client to log on to Battle.net successfully. However, like any protection mechanism, the new Lockdown module is not without its flaws, some of which are discussed in detail in this paper.
	* **Emulators**
	* **Breaking The Game**
		* [Hacking the Source Engine](http://vallentinsource.com/hacking-source-engine)
	* **Reverse Engineering**
		* [+1,000,000 -0: Cloning a Game Using Game Hacking and Terabytes of Data](https://github.com/nickcano/gamehackingpres2016)
			* In this talk, I'll provide a window into the warchest my team used to generate over a million lines of code. In particular, we created and used game hacks to process data from tens of millions of hours of in-game data and use the results to generate copies of a game's map, monsters, quests, items, spells, non-playable characters, and more. We also used a wiki crawler to obtain a large amount of data, generate additional code, and guide our cheat scripts in what to look for, clarify, and ignore. After explaining our end-game vision, I'll dive deep into the architecture of the game client, server and protocol. Once that's out of the way, I'll talk about the different types of hacks we used, how they work, and what data they were able to obtain. Once that's out of the way, I'll round out the story by explaining exactly what type of data we gathered and what parts of our toolkit we used to gather it.
	* **Miscellaneous**
		* [Hack the Vote CTF "The Wall" Solution](https://zerosum0x0.blogspot.com/2016/11/hack-vote-wall-solution.html)
* **Non-Specific Tools**
* [TruePlay - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/mt808781(v=vs.85).aspx)
*  **Game Trainers**
	* [ugtrain](https://github.com/ugtrain/ugtrain)
		* Universal Elite Game Trainer for CLI(linux game trainer)


--------------
### Game Programming Papers

* [The TRIBES Engine Networking Model or How to Make the Internet Rock for Multi­player Games](http://www.pingz.com/wordpress/wp-content/uploads/2009/11/tribes_networking_model.pdf)
	* This paper discusses the networking model developed to support a "real­time" multi­player gaming environment.  This model is being developed for TRIBES II, and was first implemented in Starsiege TRIBES, a multi­player online team game published in December '98. The three major features of this model are: support for multiple data delivery requirements, partial object state updates and a packet delivery notification protocol.

