# Side-Channel Attacks

#### Table of Contents





* [Exploiting CVE-2018-1038 - Total Meltdown - Adam Chester](https://blog.xpnsec.com/total-meltdown-cve-2018-1038/)

* [NetSpectre: Read Arbitrary Memory over Network - Michael Schwarz, Martin Schwarzl, Moritz Lipp, Jon Masters, Daniel Gruss](https://misc0110.net/web/files/netspectre.pdf)
	* Abstract. All Spectre attacks so far required local code execution. We present the first fully remote Spectre attack. For this purpose, we demonstrate the first access-driven remote Evict+Reload cache attack over the network, leaking 15 bits per hour. We present a novel high-performance AVX-based covert channel that we use in our cache-free Spectre attack. We show that in particular remote Spectre attacks perform significantly better with the AVX-based covert channel, leaking 60 bits per hour from the target system. We demonstrate practical NetSpectre attacks on the Google cloud, remotely leaking data and remotely breaking ASLR.


Zombieload/RIDL
	https://www.cyberus-technology.de/posts/2019-05-14-zombieload.html
	https://www.redhat.com/en/blog/understanding-mds-vulnerability-what-it-why-it-works-and-how-mitigate-it
	https://seclists.org/bugtraq/2019/May/0


* [Understanding Microarchitectural Data Sampling (aka MDS, ZombieLoad, RIDL & Fallout) from Red Hat](https://www.youtube.com/watch?time_continue=2&v=Xn-wY6Ir1hw)
	* Microarchitectural Data Sampling—also known as MDS, ZombieLoad, RIDL & Fallout—is a set of Intel processor-based vulnerabilities that allows unauthorized users to access data used by other programs, containers, and virtual machines. In this video,Red Hat computer architect Jon Masters provides a technical overview on how the flaw works and what companies can do about it.


---------------------
### Side-Channel Attacks
* **Analysis**
	* **Tools**
		* [ChipWhisperer](http://www.newae.com/chipwhisperer)
			* ChipWhisperer is the first ever open-source solution that provides a complete toolchain for research and analysis of embedded hardware security. Side Channel Power Analysis, Clock Glitching, VCC Glitching, and more are all possible with this unique tool.
* **CPU**
* **Electricity/Power-Based**
    * [Get Your Hands Off My Laptop: Physical Side-Channel Key-Extraction Attacks On PCs](http://www.tau.ac.il/~tromer/handsoff/)
        * We demonstrated physical side-channel attacks on a popular software implementation of RSA and ElGamal, running on laptop computers. Our attacks use novel side channels and are based on the observation that the "ground" electric potential in many computers fluctuates in a computation-dependent way. An attacker can measure this signal by touching exposed metal on the computer's chassis with a plain wire, or even with a bare hand. The signal can also be measured at the remote end of Ethernet, VGA or USB cables. Through suitable cryptanalysis and signal processing, we have extracted 4096-bit RSA keys and 3072-bit ElGamal keys from laptops, via each of these channels, as well as via power analysis and electromagnetic probing. Despite the GHz-scale clock rate of the laptops and numerous noise sources, the full attacks require a few seconds of measurements using Medium Frequency signals (around 2 MHz), or one hour using Low Frequency signals (up to 40 kHz).
    * [An Inside Job: Remote Power Analysis Attacks on FPGAs](https://eprint.iacr.org/2018/012.pdf)
* **Attacks On Memory(RAM)**
	* **Rowhammer**
		* [Exploiting the DRAM rowhammer bug to gain kernel privileges](https://googleprojectzero.blogspot.com/2015/03/exploiting-dram-rowhammer-bug-to-gain.html)
		* [Row hammer - Wikipedia](https://en.wikipedia.org/wiki/Row_hammer)
		* [Another Flip in the Wall of Rowhammer Defenses](https://arxiv.org/abs/1710.00551)
		* [rowhammer.js](https://github.com/IAIK/rowhammerjs)
			* Rowhammer.js - A Remote Software-Induced Fault Attack in JavaScript
		* [Rowhammer.js: A Remote Software-Induced Fault Attack in JavaScript](https://link.springer.com/chapter/10.1007/978-3-319-40667-1_15)
		* [Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors](https://www.ece.cmu.edu/~safari/pubs/kim-isca14.pdf)
			* Abstract. Memory isolation is a key property of a reliable and secure computing system — an access to one memory ad- dress should not have unintended side e ects on data stored in other addresses. However, as DRAM process technology scales down to smaller dimensions, it becomes more diffcult to prevent DRAM cells from electrically interacting with each other. In this paper, we expose the vulnerability of commodity DRAM chips to disturbance errors. By reading from the same address in DRAM, we show that it is possible to corrupt data in nearby addresses. More specifically, activating the same row in DRAM corrupts data in nearby rows. We demonstrate this phenomenon on Intel and AMD systems using a malicious program that generates many DRAM accesses. We induce errors in most DRAM modules (110 out of 129) from three major DRAM manufacturers. From this we conclude that many deployed systems are likely to be at risk. We identify the root cause of disturbance errors as the repeated toggling of a DRAM row’s wordline, which stresses inter-cell coupling e ects that accelerate charge leakage from nearby rows. We provide an extensive characterization study of disturbance errors and their behavior using an FPGA-based testing plat- form. Among our key findings, we show that (i) it takes as few as 139K accesses to induce an error and (ii) up to one in every 1.7K cells is susceptible to errors. After examining var- ious potential ways of addressing the problem, we propose a low-overhead solution to prevent the errors.
* **Sound-Based**
    * [RSA Key Extraction via Low-Bandwidth Acoustic Cryptanalysis](http://www.tau.ac.il/~tromer/acoustic/)
        * Here, we describe a new acoustic cryptanalysis key extraction attack, applicable to GnuPG's current implementation of RSA. The attack can extract full 4096-bit RSA decryption keys from laptop computers (of various models), within an hour, using the sound generated by the computer during the decryption of some chosen ciphertexts. We experimentally demonstrate that such attacks can be carried out, using either a plain mobile phone placed next to the computer, or a more sensitive microphone placed 4 meters away.
