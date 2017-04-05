##Game Hacking



[Pince](https://github.com/korcankaraokcu/PINCE)
* PINCE is a gdb front-end/reverse engineering tool focused on games, but it can be used for any reverse-engineering related stuff. PINCE is an abbreviation for "PINCE is not Cheat Engine". PINCE's GUI is heavily "inspired(;D)" by Cheat Engine. 

[Hacking the PS Vita](http://yifan.lu/2015/06/21/hacking-the-ps-vita/)

[ARM9Loader Technical Details - GBAtemp](https://gbatemp.net/threads/arm9loader-technical-details-and-discussion.408537/)

[Reverse Engineering Strike Commander](http://fabiensanglard.net/reverse_engineering_strike_commander/index.php)

[The Multibillion Dollar Industry That's Ignored](http://www.irongeek.com/i.php?page=videos/derbycon4/t204-the-multibillion-dollar-industry-thats-ignored-jason-montgomery-and-ryan-sevey)

[Keyshuffling Attack for Persistent Early Code Execution in the Nintendo 3DS Secure Bootchain](https://github.com/Plailect/keyshuffling)
* We demonstrate an attack on the secure bootchain of the Nintendo 3DS in order to gain early code execution. The attack utilizes the block shuffling vulnerability of the ECB cipher mode to rearrange keys in the Nintendo 3DS's encrypted keystore. Because the shuffled keys will deterministically decrypt the encrypted firmware binary to incorrect plaintext data and execute it, and because the device's memory contents are kept between hard reboots, it is possible to reliably reach a branching instruction to a payload in memory. This payload, due to its execution by a privileged processor and its early execution, is able to extract the hash of hardware secrets necessary to decrypt the device's encrypted keystore and set up a persistant exploit of the system. 