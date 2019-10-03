# Game Hacking


## Table of Contents
* [General](#general)
* [Writeups](#writeups)
* [Console Hacking](#console)
* [Reverse Engineering Games](#re)
* [Talks & Presentations](#talks)
* [Tools](#tools)





------------
### <a name="general"></a>General
* **101**
	* [Awesome Gamedev](https://github.com/Calinou/awesome-gamedev)
		* A collection of free software and free culture resources for making amazing games. 
	* [The Ultimate Online Game Hacking Resource](https://github.com/dsasmblr/hacking-online-games)
		* From dissecting game clients to cracking network packet encryption, this is a go-to reference for those interested in the topic of hacking online games.
	* [EFF FAQ on Reverse Engineering Legalities](https://www.eff.org/issues/coders/reverse-engineering-faq)
		* This FAQ details information that may help reverse engineers reduce their legal risk. *Use this information as a guide, not actual legal advice.*
* **Educational**
	* [PwnAdventureZ](https://github.com/Vector35/PwnAdventureZ)
		* NES zombie survival game made to be hacked 
	* [Hack.lu 2017: (Workshop) Reverse Engineering a MMORPG](https://www.slideshare.net/AntoninBeaujeant/reverse-engineering-a-mmorpg)
		* This workshop covers the basics of reverse engineering a (M)MORPG. The target is [Pwn Adventure 3](http://www.pwnadventure.com/), an intentionally-vulnerable MMORPG developed by [Vector35](https://vector35.com/).
	* [DEF CON 18: Securing MMOs - A Security Professional's View from the Inside](https://www.youtube.com/watch?v=9IGvIexJSFU)
		* Closely following the model of "Brief Title: Long, Boring Description," Securing MMOs: A Security Professional's View From the Inside will give attendees a look at the security problems plaguing the MMO industry and how modern engineers are taking the fight to cheaters and hackers in MMOs.
* **Writeups**
	* [Hack the Vote CTF "The Wall" Solution](https://zerosum0x0.blogspot.com/2016/11/hack-vote-wall-solution.html)
	* [Creating A Kewl And Simple Cheating Platform On Android - DeepSec2014](http://www.securitytube.net/video/12547?utm_source=feedburner&utm_medium=feed&utm_campaign=Feed%3A+SecurityTube+%28SecurityTube.Net%29)
	* **Emulators**
		* [How do emulators work and how are they written?](https://stackoverflow.com/questions/448673/how-do-emulators-work-and-how-are-they-written)
	* **Breaking The Game**
		* [DEF CON 23: Shall We Play A Game](https://www.youtube.com/watch?v=XxyRDkmNMHg)
			* I'll show in this talk that playing on custom game servers and playing community created maps could easily lead to code execution on our machines - more so, in most cases without the need to bypass the operating system's exploit mitigation techniques. My targets include popular games and game engines like CryEngine 3, Dota 2, Garry's Mod, ARMA3 and Digital Combat Simulator. I'll show a wide range of script abuse from a simple direct command execution in an unrestricted scripting environment through brute forcing a security camera via HTTP requests to complex script sandbox escapes.
		* [Gotta catch-em-all worldwide - Pokemon GO GPS spoofing](https://insinuator.net/2016/07/gotta-catch-em-all-worldwide-or-how-to-spoof-gps-to-cheat-at-pokemon-go/)
		* [How to hack an MMO - Raph Koster - 2008](https://www.raphkoster.com/2008/04/17/how-to-hack-an-mmo/)
		* [Exploiting Game Engines for Fun and Profit](http://revuln.com/files/Ferrante_Auriemma_Exploiting_Game_Engines.pdf)
		* [Fuzzing Online Games](https://www.elie.net/static/files/fuzzing-online-games/fuzzing-online-games-slides.pdf)
			* [Presentation Page](https://www.elie.net/talk/fuzzing-online-games)
		* [How to Hack Local Values in Browser-Based Games with Cheat Engine](https://www.youtube.com/watch?v=f_axmYpG1Lk)
		* [Fragging Game Servers](https://www.youtube.com/watch?v=bRM4J-LphUw - DEF CON 17)
			* From hardware interaction to network protocols, this talk will present the inner workings of the Source Dedicated Server (used for games such as Left4Dead and Team Fortress 2). This talk will discuss some of the weaknesses in these game engines and ways they are exploited in the wild. A tool designed to dissect and analyze client/server communications will be released during the talk. We'll also provide some pragmatic advice for deploying game servers and release a white paper describing a secure configuration guidelines for the Source Dedicated Server.
		* [DEF CON 20: Fuzzing Online Games](https://www.youtube.com/watch?v=r0UQ6bpKOX0)
		* [DEF CON 19: Hacking MMORPGs for Fun and Mostly Profit](https://www.youtube.com/watch?v=hABj_mrP-no)
			* Online games, such as MMORPG's, are the most complex multi-user applications ever created. The security problems that plague these games are universal to all distributed software systems. Online virtual worlds are eventually going to replace the web as the dominant social space on the 'Net, as Facebook apps have shown, and this is big business. MMORPG game security is something that is very important to game studios and players, yet bots and exploits continue to infest all major MMORPG's, the creators and maintainers of the next generation of MMORPG's will need to understand software security from the ground up or face failure. The problem extends from software bugs such as item or money duplication, to mechanical exploitation such as botting, which leads to economic forces and digital identity theft. There is upwards of a billion dollars at stake, for both game hackers and game operators. Both Josh and Kuba have explored game hacking from both sides, and this talk presents a pragmatic view of both threats and defenses.
	* **Reverse Engineering**
		* [Reverse Engineering Strike Commander](http://fabiensanglard.net/reverse_engineering_strike_commander/index.php)
		* [Creating a Packet Logger for Dragomon Hunter](https://0xbaadf00dsec.blogspot.com/2016/01/reverse-engineering-online-games.html)
		* [Unravelling Konami's Arcade DRM](http://mon.im/2017/12/konami-arcade-drm.html)
		* [Introduction to Server Side Emulation - Corillian - tuts4you](https://tuts4you.com/download.php?view.2758)
		* [Remote Code Execution In Source Games](https://oneupsecurity.com/research/remote-code-execution-in-source-games?t=r)
		* [DEF CON 17: Subverting the World Of Warcraft API](https://www.youtube.com/watch?v=EnmoI2dRwX4)
		* [Cyber Necromancy - Reverse Engineering Dead Protocols](https://media.ccc.de/v/31c3_-_5956_-_en_-_saal_2_-_201412281400_-_cyber_necromancy_-_joseph_tartaro_-_matthew_halchyshak)
		* [32C3 - How Hackers Grind an MMORPG: By Taking it Apart!](https://www.youtube.com/watch?v=9pCb0vIp_kg)
		* [Black Hat Europe 2014 - Next Level Cheating and Leveling Up Mitigations](https://www.youtube.com/watch?v=bsYxcpz3w8A)
		* [DEF CON 18: Kartograph - Applying Reverse Engineering Techniques to Map Hacking](https://www.youtube.com/watch?v=WDNY4DMx8Jc)
		* [Deciphering MMORPG Protocol Encoding](https://stackoverflow.com/questions/539812/deciphering-mmorpg-protocol-encoding)
		* [Reverse Engineering of a Packet Encryption Function of a Game](https://reverseengineering.stackexchange.com/questions/8816/reverse-engineering-of-a-packet-encryption-function-of-a-game)
		* [Introduction to Server Side Emulation - Corilian(2006)](http://cellframework.sourceforge.net/uploads/Introduction%20to%20Server%20Side%20Emulation.pdf)
* **Non-Specific Tools**
	* [Pince](https://github.com/korcankaraokcu/PINCE)
		* PINCE is a gdb front-end/reverse engineering tool focused on games, but it can be used for any reverse-engineering related stuff. PINCE is an abbreviation for "PINCE is not Cheat Engine". PINCE's GUI is heavily "inspired(;D)" by Cheat Engine. 
	* [loadlibraryy](https://github.com/G-E-N-E-S-I-S/loadlibrayy)
		* x64 manualmapper with kernel elevation and thread hijacking capabilities to bypass anticheats
	* [MTuner](https://github.com/milostosic/MTuner)
		* MTuner is a C/C++ memory profiler and memory leak finder for Windows, PlayStation 4, PlayStation 3, etc.


------------
### <a name="console"></a>Nintendo
* **Nintendo Gameboy/Pocket/Color/Advance**
	* [Reverse engineering a Gameboy ROM with radare2](https://www.megabeets.net/reverse-engineering-a-gameboy-rom-with-radare2/)
	* [awesome-gbdev](https://github.com/avivace/awesome-gbdev)
		* A curated list of Game Boy development resources such as tools, docs, emulators, related projects and open-source ROMs.
* **Nintendo 3DS**
	* **Articles/Writeups**
		* [Keyshuffling Attack for Persistent Early Code Execution in the Nintendo 3DS Secure Bootchain](https://github.com/Plailect/keyshuffling)
			* We demonstrate an attack on the secure bootchain of the Nintendo 3DS in order to gain early code execution. The attack utilizes the block shuffling vulnerability of the ECB cipher mode to rearrange keys in the Nintendo 3DS's encrypted keystore. Because the shuffled keys will deterministically decrypt the encrypted firmware binary to incorrect plaintext data and execute it, and because the device's memory contents are kept between hard reboots, it is possible to reliably reach a branching instruction to a payload in memory. This payload, due to its execution by a privileged processor and its early execution, is able to extract the hash of hardware secrets necessary to decrypt the device's encrypted keystore and set up a persistant exploit of the system.
		* [ARM9Loader Technical Details - GBAtemp](https://gbatemp.net/threads/arm9loader-technical-details-and-discussion.408537/)
		* [Throwback: K9Lhax by Bruteforce](http://douevenknow.us/post/151129092928/throwback-k9lhax-by-bruteforce)
		* [soundhax](https://github.com/nedwill/soundhax)
			* A heap overflow in tag processing leads to code execution when a specially- crafted m4a file is loaded by Nintendo 3DS Sound. This bug is particularly good, because as far as I can tell it is the first ever homebrew exploit that is free, offline, and works on every version of the firmware for which the sound app is available.
	* **Emulator**
		* [Citra](https://citra-emu.org/)
	* **Homebrew**
		* [Luma3DS](https://github.com/AuroraWright/Luma3DS)
			* Luma3DS is a program to patch the system software of (New) Nintendo 3DS handheld consoles "on the fly", adding features (such as per-game language settings and debugging capabilities for developers) and removing restrictions enforced by Nintendo (such as the region lock). It also allows you to run unauthorized ("homebrew") content by removing signature checks.
* **Nintendo Entertainment System**
	* **Articles/Writeups**
	* **Emulators**
* **Nintendo Super Nintendo**
	* **Articles/Writeups**
	* **Emulators**
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
	* [Dolphin](https://github.com/dolphin-emu/dolphin)
		* Dolphin is a GameCube / Wii emulator, allowing you to play games for these two platforms on PC with improvements. https://dolphin-emu.org/
* **Nintendo Wii**
	* [Dolphin](https://github.com/dolphin-emu/dolphin)
		* Dolphin is a GameCube / Wii emulator, allowing you to play games for these two platforms on PC with improvements. https://dolphin-emu.org/
	* [wiihacks forum](http://www.wiihacks.com/)
	* [WiiHacks](https://www.reddit.com/r/WiiHacks/)
	* [The Homebrew Channel](https://github.com/fail0verflow/hbc)
		* The Homebrew Channel - open source edition
	* [WiiUse](https://github.com/rpavlik/wiiuse)
		* Wiiuse is a library written in C that connects with several Nintendo Wii remotes. Supports motion sensing, IR tracking, nunchuk, classic controller, Balance Board, and the Guitar Hero 3 controller. Single threaded and nonblocking makes a light weight and clean API.
* **Nintendo WiiU**
	* **Emulators**
	* **Firmware**
	* **Homebrew**
* **Articles/Writeups**
 * [Anatomy of a Wii U: The End...?](https://hexkyz.blogspot.com/2018/01/anatomy-of-wii-u-end.html)
* **Nintendo Switch**
	* **Articles/Writeups**
		* [Console Security - Switch Homebrew on the Horizon](https://media.ccc.de/v/34c3-8941-console_security_-_switch)
			* Nintendo has a new console, and it's more secure than ever.  The Switch was released less than a year ago, and we've been all over it.  Nintendo has designed a custom OS that is one of the most secure we've ever seen, making the game harder than it has ever been before.  In this talk we will give an introduction to the unique software stack that powers the Switch, and share our progress in the challenge of breaking it. We will talk about the engineering that went into the console, and dive deep into the security concepts of the device.  The talk will be technical, but we aim to make it enjoyable also for non-technical audiences.
		* [Nintendo_Switch_Reverse_Engineering - dekuNukem](https://github.com/dekuNukem/Nintendo_Switch_Reverse_Engineering)
			* A look at inner workings of Joycon and Nintendo Switch
	* **Emulators**
		* [Ryujinx](https://github.com/gdkchan/Ryujinx)
			* Experimental Switch emulator written in C#
		* [yuzu](https://github.com/yuzu-emu/yuzu)
			* yuzu is an experimental open-source emulator for the Nintendo Switch from the creators of Citra. It is written in C++ with portability in mind, with builds actively maintained for Windows, Linux and macOS. The emulator is currently only useful for homebrew development and research purposes.
	* **Firmware**
		* [Atmosphere-NX](https://github.com/SciresM/Atmosphere-NX)
			* This is a repo for a work-in-progress customized firmware for the Nintendo Switch.
	* **Homebrew**
		* [nx-hbmenu](https://github.com/switchbrew/nx-hbmenu)
			* Switch Homebrew Menu



------------
#### Sony 
* **PSP / PS Vita**
	* [Hacking the PS Vita](http://yifan.lu/2015/06/21/hacking-the-ps-vita/)
	* [ Playstation Portable Cracking [24c3]](https://www.youtube.com/watch?v=TgzxyO2QO1M)
	* [VITA2PC](https://github.com/Rinnegatamante/VITA2PC)
		* VITA2PC is a tool allowing to stream PSVITA/PSTV to your PC via WiFi.
	* [psvd](https://github.com/yifanlu/psvsd)
	* [henkaku](https://github.com/henkaku/henkaku)
		* Homebrew enabler for PS Vita
	* [vitadump](https://github.com/St4rk/vitadump)
		* This homebrew can dump some PS Vita shared modules
	* [vitastick](https://github.com/xerpi/vitastick)
		* vitastick is a plugin and an application that lets you use a PSVita as a USB controller. It uses the UDCD (USB Device Controller Driver) infrastructure in the kernel to simulate such controller, and thus, the host thinks the PSVita is a legit USB gamepad.
* **Sony PlayStation 1**
	* [Nocash PSX Emulator Specifications](http://problemkaputt.de/psx-spx.htm)
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
* **Articles/Blogposts/Writeups**
	* [Hacking/Exploiting/Cheating in Online Games (PDF)](https://zdresearch.com/wp-content/uploads/2013/04/Exploiting-Online-Games.pdf)
		* A presentation from 2013 that delves deeply into hacking online games, from defining terminology to providing code examples of specific hacks.
	* [How to Hack an MMO - raphkoster.com(2008)](https://www.raphkoster.com/2008/04/17/how-to-hack-an-mmo/)
	* [Reverse Engineering Online Games - Dragomon Hunter - 0xbaadf00dsec](http://0xbaadf00dsec.blogspot.com/2016/01/reverse-engineering-online-games.html)
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
		* [Source SDK Server [Security Research Repo] - pyperanger](https://github.com/pyperanger/sourcengine)
		* [+1,000,000 -0: Cloning a Game Using Game Hacking and Terabytes of Data](https://github.com/nickcano/gamehackingpres2016)
			* In this talk, I'll provide a window into the warchest my team used to generate over a million lines of code. In particular, we created and used game hacks to process data from tens of millions of hours of in-game data and use the results to generate copies of a game's map, monsters, quests, items, spells, non-playable characters, and more. We also used a wiki crawler to obtain a large amount of data, generate additional code, and guide our cheat scripts in what to look for, clarify, and ignore. After explaining our end-game vision, I'll dive deep into the architecture of the game client, server and protocol. Once that's out of the way, I'll talk about the different types of hacks we used, how they work, and what data they were able to obtain. Once that's out of the way, I'll round out the story by explaining exactly what type of data we gathered and what parts of our toolkit we used to gather it.
	* **Miscellaneous**
		* [Hack the Vote CTF "The Wall" Solution](https://zerosum0x0.blogspot.com/2016/11/hack-vote-wall-solution.html)
* **Tools**
	* [CSGOSimple](https://github.com/MarkHC/CSGOSimple)
		* A simple base for internal Counter-Strike: Global Offensive cheats.
	* [PubgPrivXcode85](https://github.com/TonyZesto/PubgPrivXcode85)
		* Simple chams wallhack for Player Unknowns Battlegrounds using a D3D11DrawIndexed hook
	* [TruePlay - msdn](https://msdn.microsoft.com/en-us/library/windows/desktop/mt808781(v=vs.85).aspx)
*  **Game Trainers**
	* [ugtrain](https://github.com/ugtrain/ugtrain)
		* Universal Elite Game Trainer for CLI(linux game trainer)
* **BattleEye**
	* [FuckBattlEye](https://github.com/G-E-N-E-S-I-S/FuckBattlEye)
		* Bypassing kernelmode anticheats via handle inheritance (across sections)
	* [NoEye](https://github.com/Schnocker/NoEye)
		* An usermode BE Rootkit Bypass






--------------
### Game Programming Papers
* [The TRIBES Engine Networking Model or How to Make the Internet Rock for Multi­player Games](http://www.pingz.com/wordpress/wp-content/uploads/2009/11/tribes_networking_model.pdf)
	* This paper discusses the networking model developed to support a "real­time" multi­player gaming environment.  This model is being developed for TRIBES II, and was first implemented in Starsiege TRIBES, a multi­player online team game published in December '98. The three major features of this model are: support for multiple data delivery requirements, partial object state updates and a packet delivery notification protocol.




```
And because hacking is easy; the Tegra X1 Bug.

Tegra X1 RCM forgets to limit wLength field of 8 byte long Setup Packet in some USB control transfers. Standard Endpoint Request GET_STATUS (0x00) can be used to do arbitrary memcpy from malicious RCM command and smash the Boot ROM stack before signature checks and after Boot ROM sends UID. Need USB connection and way to enter RCM (Switch needs volume up press and JoyCon pin shorted).

To:
ReSwitched
fail0verflow
SwitchBrew
BBB
Team Xecuter
Team SALT

Reminder: Real hackers hack in silence. You all suck.


"Game Over."


F8001BE1190CAED74BBDDAD78667877C84D1A128
```

### Sort
* [Fabien Sanglard's Website](http://fabiensanglard.net/)
* [Hack the Vote 2016 CTF "The Wall" Solution](https://zerosum0x0.blogspot.com/2016/11/hack-vote-wall-solution.html)
https://github.com/dsasmblr/game-hacking
https://github.com/dsasmblr/hacking-online-games

* [Diablo1 Notes](https://github.com/sanctuary/notes)
	* The aim of this project is to organize and cross-reference a collection of notes related to the inner workings of the Diablo 1 game engine.
* [CS:GO RCE 0-day - Real World CTF Qualifiers 2018 - Perfect Blue](https://blog.perfect.blue/P90_Rush_B)

https://web.archive.org/web/20110926012139/http://insertcredit.com/2011/09/22/who-killed-videogames-a-ghost-story/