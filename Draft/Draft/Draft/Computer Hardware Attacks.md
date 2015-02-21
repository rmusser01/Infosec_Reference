Computer Hardware Attacks




[Timeline of Low level software and hardware attack papers - Essentially a list of all well known papers on pc hardware attacks](http://timeglider.com/timeline/5ca2daa6078caaf4)


Professor’s page:
http://www.cl.cam.ac.uk/~sps32/

Grab links for his papers


[Implementation and Implications of a Stealth Hard-Drive Backdoor](https://www.ibr.cs.tu-bs.de/users/kurmus/papers/acsac13.pdf)
* Modern workstations and servers implicitly trust hard disks to act as well-behaved block devices. This paper analyzes the catastrophic loss of security that occurs when hard disks are not trustworthy. First, we show that it is possible to compromise the rmware of a commercial o-the-shelf hard drive, by resorting only to public information and reverse en- gineering. Using such a compromised rmware, we present a stealth rootkit that replaces arbitrary blocks from the disk while they are written, providing a data replacement back- door . The measured performance overhead of the compro- mised disk drive is less than 1% compared with a normal, non-malicious disk drive. We then demonstrate that a re- mote attacker can even establish a communication channel with a compromised disk to inltrate commands and to ex- ltrate data. In our example, this channel is established over the Internet to an unmodied web server that relies on the compromised drive for its storage, passing through the original webserver, database server, database storage en- gine, lesystem driver, and block device driver. Additional experiments, performed in an emulated disk-drive environ- ment, could automatically extract sensitive data such as /etc/shadow (or a secret key le) in less than a minute. This paper claims that the diculty of implementing such an at- tack is not limited to the area of government cyber-warfare; rather, it is well within the reach of moderately funded crim- inals, botnet herders and academic researchers.


[Attackin the TPM part 2](https://www.youtube.com/watch?v=h-hohCfo4LA)

[Attacking “secure” chips](https://www.youtube.com/watch?v=w7PT0nrK2BE)

[Perimeter-Crossing Buses: a New Attack Surface for
Embedded Systems](http://www.cs.dartmouth.edu/~sws/pubs/bgjss12.pdf)
* Abstract: This paper maps out the bus-facing attack surface of a modern operating system, and demonstrates that e ective and ecient injection of trac into the buses is real and easily a ordable. Further, it presents a simple and inexpen-sive hardware tool for the job, outlining the architectural and computation-theoretic challenges to creating a defensive OS/driver architecture comparable to that which has been achieved for network stacks.



[Breaking apple touchID cheaply](http://www.ccc.de/en/updates/2013/ccc-breaks-apple-touchid)


[Keykeriki v2.0](http://www.remote-exploit.org/articles/keykeriki_v2_0__8211_2_4ghz/index.html)
* Hardware to attack wireless keyboards and other such things


[Stealthy Dopant-Level Hardware Trojans](Hardware level trojans http://sharps.org/wp-content/uploads/BECKER-CHES.pdf)
* Abstract: In this paper we propose an extremely stealthy approach for implement-
ing hardware Trojans below the gate level, and we evaluate their impact
on the security of the target device. Instead of adding additional cir-
cuitry to the target design, we insert our hardware Trojans by changing
the dopant polarity of existing transistors. Since the modi ed circuit ap-
pears legitimate on all wiring layers (including all metal and polysilicon),
our family of Trojans is resistant to most detection techniques, includ-
ing ne-grain optical inspection and checking against \golden chips".
We demonstrate the e ectiveness of our approach by inserting Trojans
into two designs | a digital post-processing derived from Intel's cryp-
tographically secure RNG design used in the Ivy Bridge processors and
a side-channel resistant SBox implementation | and by exploring their
detectability and their e ects on security.



###Tools: 
[Psychson](https://github.com/adamcaudill/Psychson)




Phison 2251-03 (2303) Custom Firmware & Existing Firmware Patches (BadUSB) 



###Defending Against Hardware Attacks


[Anti-Evil Maid](http://theinvisiblethings.blogspot.com/2011/09/anti-evil-maid.html?m=1)

###USB

[USB in a Nutshell](http://www.beyondlogic.org/usbnutshell/usb1.shtml)
* Great explanation of the USB standard in depth

[Psychson](https://github.com/adamcaudill/Psychson)

[USB Device Drivers: A Stepping Stone into your Kernel](https://www.youtube.com/watch?v=HQWFHskIY2)
* [Slides])(www.jodeit.org/research/DeepSec2009_USB_Device_Drivers.pdf)

[Lowering the USB Fuzzing Barrier by Transparent Two-Way Emulation](https://www.usenix.org/system/files/conference/woot14/woot14-vantonder.pdf)
* Abstract: Increased focus on the Universal Serial Bus (USB) attack surface of devices has recently resulted in a number of new vulnerabilities. Much of this advance has been aided by the advent of hardware-based USB emulation techniques. However, existing tools and methods are far from ideal, requiring a significant investment of time, money, and effort. In this work, we present a USB testing framework that improves significantly over existing methods in providing a cost-effective and flexible way to read and modify USB communication. Amongst other benefits, the framework enables man-in-the-middle fuzz testing between a host and peripheral. We achieve this by performing two-way emulation using inexpensive bespoke USB testing hardware, thereby delivering capa-bilities of a USB analyzer at a tenth of the cost. Mutational fuzzing is applied during live communication between a host and peripheral, yielding new security-relevant bugs. Lastly, we comment on the potential of the framework to improve current exploitation techniques on the USB channel.


###SD Cards
[The Exploration and Exploitation of an SD Memory Card](https://www.youtube.com/watch?v=Tj-zI8Tl218)
* This talk demonstrates a method for reverse engineering and loading code into the microcontroller within a SD memory card.


###RFID




http://theinvisiblethings.blogspot.com/2011/09/anti-evil-maid.html?m=1





