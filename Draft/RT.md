# Red Teaming/Adversary Simulation/Explicitly Pen testing stuff



### Table of Contents
- [General](#general)
- [Talks](#talks)
- [Cobalt Strike](#cobalt)
- [Command and Control](#cnc)
- [Domains](#domains)
- [Egress](#egress)
- [Empire](#empire)
- [Hardware](#hw)
- [Infrastructure](#infra)
- [Payloads](#payload)
- [Persistence](#persist)
- [Tactics](#tactics)
- [Pen Testing X](#unusual)
	- [AIX](#aix)
	- [Embedded](#embedded)
	- [MainFrames](#main)
	- [SCADA/PLCs](#scada)
	- [Virtual Appliances](#va)


* **To Do**

* [Victor or Victim Strategies for Avoiding an InfoSec Cold War - Jason Lang, Stuart McIntosh(Derbycon 2018)](https://www.youtube.com/watch?v=9_cZ5xn-huc)
https://github.com/vysec/RedTips
* [Finding Domain frontable Azure domains - thoth / Fionnbharr](https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html)

https://blogs.technet.microsoft.com/motiba/2018/04/09/invoke-adversary-simulating-adversary-operations/
* [Playing Cat and Mouse: Three Techniques Abused to Avoid Detection - ZLAB-YOROI](https://blog.yoroi.company/research/playing-cat-and-mouse-three-techniques-abused-to-avoid-detection/)
* [sh00t](https://github.com/pavanw3b/sh00t)
	* Security Testing is not as simple as right click > Scan. It's messy, a tough game. What if you had missed to test just that one thing and had to regret later? Sh00t is a highly customizable, intelligent platform that understands the life of bug hunters and emphasizes on manual security testing.
https://hackmd.io/EhFjuYHESIGhFQXFQ6duTQ?view
http://threatexpress.com/redteaming/redteamplanning/tradecraft/
https://github.com/HunnicCyber/SharpSniper
https://blog.xpnsec.com/rundll32-your-dotnet/
* [Domi-Owned](https://github.com/coldfusion39/domi-owned)
	* Domi-Owned is a tool used for compromising IBM/Lotus Domino servers.


* [Macros and More with SharpShooter v2.0 - MDSec](https://www.mdsec.co.uk/2019/02/macros-and-more-with-sharpshooter-v2-0/)
* [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
	* SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source code. SharpShooter is capable of creating payloads in a variety of formats, including HTA, JS, VBS and WSF. It leverages James Forshaw's DotNetToJavaScript tool to invoke methods from the SharpShooter DotNet serialised object. Payloads can be retrieved using Web or DNS delivery or both; SharpShooter is compatible with the MDSec ActiveBreach PowerDNS project. Alternatively, stageless payloads with embedded shellcode execution can also be generated for the same scripting formats.
https://bitbucket.org/gavinanders/callback-catcher/src/master/
https://medium.com/@prsecurity_/how-to-build-an-internal-red-team-7957ec644695

* [Advanced Pen-Testing Tricks: Building a Lure to Collect High Value Credentials - Bobby Kuzma](https://www.coresecurity.com/article/advanced-pen-testing-tricks-building-a-lure-to-collect-high-value-credentials)
* [Powershell Empire Stagers 1: Phishing with an Office Macro and Evading AVs - fzuckerman](https://fzuckerman.wordpress.com/2016/10/06/powershell-empire-stagers-1-phishing-with-an-office-macro-and-evading-avs/)
* [Invoke-Apex](https://github.com/securemode/Invoke-Apex)
	* Invoke-Apex is a PowerShell-based toolkit consisting of a collection of techniques and tradecraft for use in red team, post-exploitation, adversary simulation, or other offensive security tasks.  It can also be useful in identifying lapses in "malicious" activity detection processes for defenders as well.
* [Hacking Corporate Emil Systems - Nate Power(BSides Columbus 2016)](https://www.youtube.com/watch?v=mJ172K1dxoM)

https://github.com/praetorian-code/purple-team-attack-automation

	
* [Tips, Tricks, and Cheats Gathered from Red vs. Blue Team-Based Training - Ed Skoudis, Joshua Wright](https://www.sans.org/webcasts/tips-tricks-cheats-gathered-red-vs-blue-team-based-training-111505/success)
https://speakerdeck.com/patrickwardle/harnessing-weapons-of-mac-destruction?slide=23
https://www.coalfire.com/The-Coalfire-Blog/Sept-2018/From-OSINT-to-Internal-Gaining-Domain-Admin
https://github.com/mthbernardes/GTRS/blob/master/README.md
https://github.com/tearsecurity/firstorder
https://github.com/CylanceSPEAR/MarkovObfuscate
https://lockboxx.blogspot.com/2019/03/macos-red-teaming-201-introduction.html
https://rastamouse.me/2019/06/the-return-of-aggressor/
https://labs.mwrinfosecurity.com/tools/c3/
https://github.com/mwrlabs/C3
https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
https://github.com/BishopFox/sliver/blob/master/README.md

https://medium.com/@d.bougioukas/red-team-diary-entry-1-making-nsas-peddlecheap-rat-invisible-f88ccbdc484d

* [Empire Fails - harmj0y](http://www.harmj0y.net/blog/empire/empire-fails/)
https://ired.team/offensive-security/red-team-infrastructure
* [From OSINT to Internal – Gaining Access from outside the perimeter - n00py](https://www.n00py.io/2017/03/from-osint-to-internal-gaining-access-from-the-outside-the-perimeter/)
http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/

* [Invoke-Apex](https://github.com/securemode/Invoke-Apex)
	* Invoke-Apex is a PowerShell-based toolkit consisting of a collection of techniques and tradecraft for use in red team, post-exploitation, adversary simulation, or other offensive security tasks.  It can also be useful in identifying lapses in "malicious" activity detection processes for defenders as well.

https://www.slideshare.net/JasonLang1/red-team-methodology-a-naked-look-169879355

* [DeviceDetector.NET](https://github.com/totpero/DeviceDetector.NET)
	* The Universal Device Detection library will parse any User Agent and detect the browser, operating system, device used (desktop, tablet, mobile, tv, cars, console, etc.), brand and model.
* [DNSlivery](https://github.com/no0be/DNSlivery)
	* Easy files and payloads delivery over DNS.
https://blog.obscuritylabs.com/merging-web-apps-and-red-teams/

* [Invoke-Adversary – Simulating Adversary Operations - Moti Bani](https://blogs.technet.microsoft.com/motiba/2018/04/09/invoke-adversary-simulating-adversary-operations/)
* [Harlem Shake JS script](https://gist.github.com/devn/5007287)
https://ijustwannared.team/2017/10/28/outlooktoolbox/
https://github.com/francisck/DanderSpritz_lab
* [Post Exploitation with KOADIC - Ian Kings](https://www.prismacsi.com/en/post-exploitation-with-koadic/)
* [How to Start a Cyber War: Lessons from Brussels - Chris Kubecka(BSides Charm 2019)](http://www.irongeek.com/i.php?page=videos/bsidescharm2019/1-06-how-to-start-a-cyber-war-lessons-from-brussels-chris-kubecka)
	* A sanitized peek behind the diplomatic curtain, revealing challenges, decisions & tools at their disposal. The Vanguard cyber warfare exercises in Brussels involving EU & NATO member states. Nation-states leveraging software, hardware and human vulnerabilities into digital warfare, with devastating consequences. Embassy threats, leaked Intel agency tools, hacking back & mass casualties.

https://blogs.technet.microsoft.com/motiba/2018/04/09/invoke-adversary-simulating-adversary-operations/
https://www.sprocketsecurity.com/blog/penetration-testing-dropbox-setup-part2

https://mthbernardes.github.io/persistence/2019/03/07/using-firefox-webextensions-as-c2-client.html
https://www.welivesecurity.com/2018/08/22/turla-unique-outlook-backdoor/

* [Docker Your Command & Control (C2) - obscuritylabs](https://blog.obscuritylabs.com/docker-command-controll-c2/)
* [Firework: Leveraging Microsoft Workspaces in a Penetration Test - trustwave](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/firework-leveraging-microsoft-workspaces-in-a-penetration-test/)



https://chigstuff.com/blog/metasploit-domain-fronting-with-microsoft-azure/
https://medium.com/@rvrsh3ll/hardening-your-azure-domain-front-7423b5ab4f64

* [Cracking The Perimeter: How Red Teams Penetrate - Dominic Chell(BSidesMCR 2018)](https://www.youtube.com/watch?v=u-MHX9-O890)

https://github.com/panagioto/Covenant
* [Red v Blue Workshop - WOPR Summit - Taylor, Dan, Phil](https://github.com/ahhh/presentations/blob/master/Red%20V%20Blue%20Workshop.pdf)

https://www.irongeek.com/i.php?page=videos/derbycon7/t315-game-on-using-red-team-to-rapidly-evolve-your-defenses-joff-thyer-pete-petersen

https://www.irongeek.com/i.php?page=videos/derbycon7/t211-common-assessment-mistakes-pen-testers-and-clients-should-avoid-brent-white-tim-roberts

https://vincentyiu.co.uk/red-team/domain-fronting/domain-fronting-using-stackpath-cdn

* [Modern Defenses and YOU!](https://blog.cobaltstrike.com/2017/10/25/modern-defenses-and-you/)
* [OPSEC Considerations for Beacon Commands](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
* [Red Team Tradecraft and TTP Guidance](https://sec564.com/#!docs/tradecraft.md)
* [Fighting the Toolset](https://www.youtube.com/watch?v=RoqVunX_sqA)

https://posts.specterops.io/designing-effective-covert-red-team-attack-infrastructure-767d4289af43
https://github.com/psychsecurity/Red-Team-Infrastructure
* [Red Teaming in the EDR age - Will Burgess - WWF HackFest 2018](https://www.youtube.com/watch?v=l8nkXCOYQC4)
	* Will Burgess is a security consultant with experience across both defensive and offensive cyber security. Will previously worked as a Threat Hunter within MWR's Countercept Division and specialised in detecting advanced malware across enterprises. As part of his role, Will researched attack techniques used by a wide range of malware families (including popular commercial tools such as Cobalt Strike), developed new ways of catching attackers, and presented this research at different conferences. Most recently, Will has been involved in red team engagements, putting his extensive knowledge of detection to bypass and hide from existing Endpoint Detection & Response (EDR) tools and AV solutions. Will's research interests include advanced attack detection, Windows internals, and finding new techniques for post exploitation in Windows environments.
* [RedTeaming from Zero to One – Part 1](https://payatu.com/RedTeaming-from-zero-to-one-part-1/)
* [RedTeaming from Zero to One – Part 2 - Rashid Feroze](https://payatu.com/redteaming-zero-one-part-2/)
	* Sort articles better
		* Add pivoting stuff from postex/privesc
	* add usb/hw related stuff
* [Cons and Conjurers Lessons for Infiltration - Paul Blonsky - BSides Cleveland](https://www.youtube.com/watch?v=jRgOVCBg_Q4)
* [There is a shell in your lunch-box - Rotimi Akinyele](https://hakin9.org/shell-lunch-box-rotimi-akinyele/)
* [Cons and Conjurers Lessons for Infiltration - Paul Blonsky - BSides Cleveland](https://www.youtube.com/watch?v=jRgOVCBg_Q4)
* [No More Secrets - Sneakers](https://github.com/bartobri/no-more-secrets)
	* This project provides a command line tool called nms that recreates the famous data decryption effect seen on screen in the 1992 hacker movie Sneakers.
* [Windows API resolution via hashing](https://github.com/LloydLabs/Windows-API-Hashing)
	* Although this method of API obfuscation is relatively old, my friend who was wanting to increase his skills in the Windows sphere confronted me about a way a few malware families seem to resolve APIs. It's pretty simple, however he could not find any documentation with a solid programming example on the matter at the time, so I thought I'd quickly write something up regarding it. I was going to write my own loader for this example (loading the desired module via LdrLoadDll within kernel32.dll, walking the InMemoryOrderModuleList to find the desired loaded module, finding the exported function we're after within the EAT..) - however I thought this might of have been a bit overkill for such a simple concept, I want to cover writing your own PE loader in the future though as it's an interesting subject.
https://posts.specterops.io/being-a-good-domain-shepherd-part-2-5e8597c3fe63
* [Evading Anomaly-Based NIDS with Empire - utkusen.com](https://utkusen.com/blog/bypassing-anomaly-based-nids-with-empire.html)

https://github.com/nccgroup/phantap
https://github.com/SecurityRiskAdvisors/VECTR
* [Empire & Tool Diversity: Integration is Key - sixdub](https://www.sixdub.net/?p=627)

https://labs.mwrinfosecurity.com/blog/tasking-office-365-for-cobalt-strike-c2/
https://www.youtube.com/watch?v=OjtftdPts4g

* [Evading Anomaly-Based NIDS with Empire - utkusen.com](https://utkusen.com/blog/bypassing-anomaly-based-nids-with-empire.html)
https://attactics.org/2019/07/18/cslogwatch-cobalt-strike-tracking-parsing-storage/
* [e2modrewrite](https://github.com/infosecn1nja/e2modrewrite)
	* Convert Empire profiles to Apache mod_rewrite scripts


* [gscript](https://github.com/gen0cide/gscript)
	* Gscript is a framework for building multi-tenant executors for several implants in a stager. The engine works by embedding runtime logic (powered by the V8 Javascript Virtual Machine) for each persistence technique. This logic gets run at deploy time on the victim machine, in parallel for every implant contained with the stager. The Gscript engine leverages the multi-platform support of Golang to produce final stage one binaries for Windows, Mac, and Linux.


https://blog.stratumsecurity.com/2018/10/17/route-53-as-a-pentest-infrastructure/

https://github.com/operatorequals/covertutils


* [cmd.exe running any file no matter what extension - Hexacorn](http://www.hexacorn.com/blog/2019/04/21/cmd-exe-running-any-file-no-matter-what-extension/)
https://github.com/Mr-Un1k0d3r/ClickOnceGenerator
* [intrigue-core](https://github.com/intrigueio/intrigue-core)
	* Intrigue-core is a framework for external attack surface discovery and automated OSINT.
See payloads section in Postex_Privesc}
https://github.com/byt3bl33d3r/SILENTTRINITY
https://github.com/jymcheong/AutoTTP
https://github.com/vysecurity/RedTips
https://github.com/taherio/redi/
* [Let's Create A Redteam Mission - Alex Kouzmine - BlackAlps 2018](https://www.youtube.com/watch?v=-kK8K-UVhWY)
https://vanmieghem.io/reigning-the-empire-evading-detection/

* [How to Make Communication Profiles for Empire - Jeff Dimmock](https://posts.specterops.io/how-to-make-communication-profiles-for-empire-46da8554338a)
* [Being a Good Domain Shepherd - Christopher Maddalena](https://posts.specterops.io/being-a-good-domain-shepherd-57754edd955f?gi=2cadd2578045)

	* We wrote a tool called firstorder, which analyses the network traffic and identifies normal traffic profile. With this information, it configures Empire’s listener. So with this listener, we have a good chance to evade listener-agent communication from an -application layer- anomaly based NIDS, since we are matching with normal traffic profile.
* [firstorder](https://github.com/tearsecurity/firstorder)
	* firstorder is designed to evade Empire's C2-Agent communication from anomaly-based intrusion detection systems. It takes a traffic capture file (pcap) of the network and tries to identify normal traffic profile. According to results, it creates an Empire HTTP listener with appropriate options.
https://www.tarlogic.com/en/blog/red-team-tales-0x01/
https://www.mdsec.co.uk/2018/06/freestyling-with-sharpshooter-v1-0/

https://github.com/sveinbjornt/Platypus
* [PentestHardware](https://github.com/unprovable/PentestHardware)
	* Kinda useful notes collated together publicly	

https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html

https://github.com/SecurityRiskAdvisors/RedTeamSIEM




https://zachgrace.com/2018/05/20/Red_Team_Telemetry_Part_1.html
https://github.com/ztgrace/pwnboard


--------------
### <a name="general"></a>General
* **101**
	* [Red Team - Wikipedia](https://en.m.wikipedia.org/wiki/Red_team)
	* [Common Ground Part 1: Red Team History & Overview](https://www.sixdub.net/?p=705)
	* [Target Analysis - Wikipedia](https://en.wikipedia.org/wiki/Target_analysis)
	* [Center of Gravity Analysis - Dale C. Eikmeier](http://www.au.af.mil/au/awc/awcgate/milreview/eikmeier.pdf)
		* Center of Gravity: A system's source of power to act.
	* [A Tradecraft Primer: Structured Analytic Techniques for Improving Intelligence Analysis - USGov 2009](https://www.cia.gov/library/center-for-the-study-of-intelligence/csi-publications/books-and-monographs/Tradecraft%20Primer-apr09.pdf)
	* [The Black Team](http://www.penzba.co.uk/GreybeardStories/TheBlackTeam.html)
	* [IBM Black Team](http://www.t3.org/tangledwebs/07/tw0706.html)
* **APT Simulation**
	* [Unit42 Playbook Viewer](https://pan-unit42.github.io/playbook_viewer/)
	* [Introducing the Adversary Playbook: First up, OilRig - Ryan Olson](https://unit42.paloaltonetworks.com/unit42-introducing-the-adversary-playbook-first-up-oilrig/)
* **Courses**
	* [Advanced Threat Tactics – Course and Notes - CobaltStrike](https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes/)
* **General Informative Information**
	* [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
		* Wiki to collect Red Team infrastructure hardening resources
		* Accompanying Presentation: [Doomsday Preppers: Fortifying Your Red Team Infrastructure](https://speakerdeck.com/rvrsh3ll/doomsday-preppers-fortifying-your-red-team-infrastructure)
	* [Fools of Golden Gate](https://blog.silentsignal.eu/2017/05/08/fools-of-golden-gate/)
		* How major vulnerabilities/large amounts of publicly vulnerable systems can exist without public recognition for long periods of time. (i.e. CVEs(10.0) exist, but no mapping in nessus/metasploit/etc)
	* [Red Teaming and the Adversarial Mindset: Have a Plan, Backup Plan and Escape Plan - ITS](https://www.itstactical.com/digicom/security/red-teaming-and-the-adversarial-mindset-have-a-plan-backup-plan-and-escape-plan/)
	* [Raphael’s Magic Quadrant - Mudge](https://blog.cobaltstrike.com/2015/08/03/raphaels-magic-quadrant/)
	* [RAT - Repurposing Adversarial Tradecraft - killswitch_GUI](https://speakerdeck.com/killswitch_gui/rat-repurposing-adversarial-tradecraft)
	* [Penetration Testing considered Harmful Today](http://blog.thinkst.com/p/penetration-testing-considered-harmful.html)
	* [Planning a Red Team exercise](https://github.com/magoo/redteam-plan)
	* [Planning Effective Red Team Exercises - Sean T Malone - BSidesSF2016](https://www.youtube.com/watch?v=cD-jKBfSKP4)
		* An effective red team exercise is substantially different from a penetration test, and it should be chartered differently as well. The scenario, objective, scope, and rules of engagement all need to be positioned correctly at the beginning in order to most closely simulate a real adversary and provide maximum value to the client.In this presentation, we'll review best practices in each of these areas, distilled from conducting dozens of successful red team exercises - along with some war stories highlighting why each element matters. Those in offensive security will gain an understanding of how to manage the client's expectations for this process, and how to guide them towards an engagement that provides a realistic measurement of their ability to prevent, detect, and respond to real attacks. Those in enterprise security will gain a deeper understanding of this style of assessment, and how to work with a red team to drive real improvement in their security programs. 
	* [Red Team Gut Check - Tim MalcomVetter](https://medium.com/@malcomvetter/red-team-gut-check-10b5976ffd19)
	* [Internal Red Teams and Insider Knowledge - Tim MalcomVetter](https://medium.com/@malcomvetter/internal-red-teams-and-insider-knowledge-8324555aaf40)
* **Building a Red Team**
	* [Building A Successful Internal Adversarial Simulation Team - C. Gates & C. Nickerson - BruCON 0x08](https://www.youtube.com/watch?v=Q5Fu6AvXi_A&list=PLtb1FJdVWjUfCe1Vcj67PG5Px8u1VY3YD&index=1)
	* [Zero to Hero – Building a Red Team - Robert Neel & David Thompson](http://penconsultants.com/blog/presentation-zero-to-hero-building-a-red-team/)
* **Generally Relevant/Useful Information**
	* [The ‘Laws’ of Red Teaming - RedTeam Journal](https://redteamjournal.com/red-teaming-laws/)
		* Red teaming is governed by informal and wholly unscientific “laws” based largely on human nature. These laws are driven by paradox and, in many cases, a healthy dose of humor. We state some from a general perspective, some from the perspective of the customer or sponsor, and some from the perspective of the red team. Enjoy. We add to these as the mood strikes. (For an alternative list of rules, try the one at redteams.net.)
	* [Beyond Red Teaming Cards - ](https://www.reciprocalstrategies.com/resources/brt_cards/)
		* The Beyond Red Teaming (BRT) cards extend the Red Team Journal Red Teaming “Laws” and cards. The purpose of the BRT cards is to help security professionals consider and assess their own frames and narratives.
	* [Goodbye OODA Loop](http://armedforcesjournal.com/goodbye-ooda-loop/)
	* [Some Comments and Thoughts on Tradecraft](https://www.darkoperator.com/blog/2017/11/20/some-comments-and-thoughts-on-tradecraft)
* **Facilitating a Red Team Engagement**
	* [TIBER-EU FRAMEWORK - How to implement the European framework for Threat Intelligence-based Ethical Red Teaming](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf)
	* [TIBER - NL GUIDE - How to conduct the TIBER-NL test](https://www.dnb.nl/binaries/TIBER-NL%20Guide%20Second%20Test%20Round%20final_tcm46-365448.pdf)
	* [Planning a Red Team exercise](https://github.com/magoo/redteam-plan)
	* [Cyber Exercise  Playbook - MITRE](https://www.mitre.org/sites/default/files/publications/pr_14-3929-cyber-exercise-playbook.pdf)
* **Red Team Experiences**
	* [Passing the Torch: Old School Red Teaming, New School Tactics?](https://www.slideshare.net/harmj0y/derbycon-passing-the-torch)
	* [Red Teaming Tips - Vincent Yiu](https://threatintel.eu/2017/06/03/red-teaming-tips-by-vincent-yiu/)
	* [Red Team Tips as posted by @vysecurity on Twitter](https://github.com/vysec/RedTips)
	* [Red Teams - Facebook Experiences Writeup - Ryan McGeehan](https://medium.com/starting-up-security/red-teams-6faa8d95f602)
	* [Reflections from a Red Team Leader - Susan Craig](http://usacac.army.mil/CAC2/MilitaryReview/Archives/English/MilitaryReview_20070430_art011.pdf)
	* [Red Teaming: Using Cutting-Edge Threat Simulation to Harden the Microsoft Enterprise Cloud](https://azure.microsoft.com/en-us/blog/red-teaming-using-cutting-edge-threat-simulation-to-harden-the-microsoft-enterprise-cloud/)
	* [10 Red Teaming Lessons Learned over 20 Years](https://redteamjournal.com/2015/10/10-red-teaming-lessons-learned-over-20-years/)
	* [Red team versus blue team: How to run an effective simulation - CSOonline](https://www.csoonline.com/article/2122440/disaster-recovery/emergency-preparedness-red-team-versus-blue-team-how-to-run-an-effective-simulation.html)
	* [Red Teaming for Pacific Rim CCDC 2017](https://bluescreenofjeff.com/2017-05-02-red-teaming-for-pacific-rim-ccdc-2017/)
	* [How I Prepared to Red Team at PRCCDC 2015](https://bluescreenofjeff.com/2015-04-15-how-i-prepared-to-red-team-at-prccdc-2015/)
	* [Red Teaming for Pacific Rim CCDC 2016](https://bluescreenofjeff.com/2016-05-24-pacific-rim-ccdc_2016/)
	* [Red Teaming Windows: Building a better Windows by hacking it - MS Ignite2017](https://www.youtube.com/watch?v=CClpjtgaJVI)
	* [Breaking Red - Understanding Threats through Red Teaming - SANS Webcast](https://www.youtube.com/watch?v=QPmgV1SRTJY)
	* ['Red Team: How to Succeed By Thinking Like the Enemy' - Council on Foreign Relations - Micah Zenko](https://www.youtube.com/watch?v=BM2wYbu4EFY)
	* [Defenders, Bring Your 'A' Game](https://winterspite.com/security/defenders-bring-your-a-game/)
	* [The hidden horrors that 3 years of global red-teaming, Jos van der Peet](https://www.youtube.com/watch?v=7z63HrEiQUY&index=10&list=PLwZycuzv10iLBFwRIWNAR-s4iuuUMRuEB)
		* My last 3 years of global reteaming in small and large organisations has shown me that there still are a lot of misconceptions about security. We all know the ‘onion’ model for layered security. While useful for the ‘defence in depth’ principle, this talk will show that in reality, rather than an onion, security is more like a pyramid. The basis is the hardware people work on (laptops etc.) and the top your business applications. In between is everything else. Operating system, network components, proxies, shares, servers and their software stack. Like any hi-rise structure, the top cannot be secure if the base is not secure. Defence in depth matters, but it can be quite trivial for attackers to sidestep certain controls to get to the data they want. Just securing your ‘crown-jewels’ is insufficient. This talk will revolve around how we have defeated security controls on various levels, ranging from the systems your end-users work on, all the way through to 2FA and 4-eye principles on critical business assets. It will talk about common misconceptions which lull companies into a false sense of security, while making life far too easy for attackers. For example the fallacy of focussing security efforts only/mostly on ‘crown jewels’ and how misunderstanding of why certain controls are put in place jeopardize corporate and client data. The talk will be supported by real-life examples
	* [A  Year In The Red by Dominic Chell and Vincent Yiu - BSides Manchester2017](https://www.youtube.com/watch?v=-FQgWGktYtw&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP&index=23)
	* [Responsible Red Teams - Tim MaclomVetter](https://medium.com/@malcomvetter/responsible-red-teams-1c6209fd43cc)
		* [Response by John Strand](https://medium.com/@john_43488/there-was-a-very-well-thought-out-article-on-responsible-red-teaming-by-tim-malcomvetter-7131faa17047)
	* [Purple Team FAIL! - Jason Morrow - Derbycon2017](https://www.irongeek.com/i.php?page=videos/derbycon7/s16-purple-team-fail-jason-morrow)
		* What went wrong with the introduction of a red team discipline into fortune 1 and how the teams came together to course correct. The result has been a successful purple team that has driven the security posture forward at the world's leading retailer. This will cover some basic do's and don'ts along with new rules of engagement when integrating blue and red. 
	* [RedTeaming from Zero to One – Part 1 - payatu.com](https://payatu.com/redteaming-from-zero-to-one-part-1/)
	* [RedTeaming from Zero to One – Part 2 - payatu.com](https://payatu.com/redteaming-zero-one-part-2/)
* **Papers**
	* [Red teaming - A Short Introduction (1.0) June 2009 - Mark Mateski](https://redteamjournal.com/papers/A%20Short%20Introduction%20to%20Red%20Teaming%20(1dot0).pdf)
	* [Red Teaming Guide - UK Ministry of Defense](https://www.gov.uk/government/uploads/system/uploads/attachment_data/file/142533/20130301_red_teaming_ed2.pdf)
	* [Red Team Handbook(2012) - University of Foreign Military And Cultural studies](http://www.au.af.mil/au/awc/awcgate/army/ufmcs_red_team_handbook_apr2012.pdf)
	* [Red Teaming of Advanced Information Assurance Concepts - Bradley Wood, Ruth Duggan](http://cs.uccs.edu/~gsc/pub/master/sjelinek/doc/research/red.pdf)
	* [A Guide To Red Teaming - NATO](http://www.act.nato.int/images/stories/events/2011/cde/rr_ukdcdc.pdf)
	* [Modeling and Simulation of Red Teaming - Part 1: Why Red Team M&S? - Michael J Skroch](https://redteamjournal.com/wp-content/uploads/2009/12/msrt0.3-2nov2009-sand2009-7215J.pdf)
	* [Moving Forward with Computational Red Teaming - Scott Wheeler - Australian DoD](http://www.dtic.mil/dtic/tr/fulltext/u2/a569437.pdf)
	* [Cyber Red Teaming  Organisational, technical and legal implications in a military context - NATO](https://ccdcoe.org/sites/default/files/multimedia/pdf/Cyber_Red_Team.pdf)
	* [Traditions In Military-Strategic Thought In Germany And The Problem Of Deterrence - 1989 - Detlef Bald](http://www.mgfa.de/html/einsatzunterstuetzung/downloads/ap018englisch.pdf?PHPSESSID=931748af0e86616800373655acaf2902)
	* [Force Protection and Suicide Bombers: The Necessity for Two Types of Canadian Military Red Teams](http://www.journal.forces.gc.ca/vol12/no4/page35-eng.asp)
	* [The Applied Critical Thinking Handbook(2015) - University of Foreign Military And Cultural studies](http://usacac.army.mil/sites/default/files/documents/ufmcs/The_Applied_Critical_Thinking_Handbook_v7.0.pdf)
	* [Preparing for the War of the Future in the Wake of Defeat: The Evolution of German Strategic Thought, 1919 - 1935 - Mark Shannon](https://www.ciaonet.org/attachments/25573/uploads)
	* [Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains](https://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf)		
	* [Ananalysis of the Metasploit Framework relative to the Penetration Testing Execution Standard(PTES) guidance(2011) - Brandon Perry](http://www.nothink.org/metasploit/documentation/metasploit_msf_analysis_ptes.pdf)




--------------
### <a name="talks"></a>Talks/Videos
* [Hacks Lies Nation States - Mario DiNatale](https://www.youtube.com/watch?v=nyh_ORq1Qwk)
* [The Impact of Dark Knowledge and Secrets on Security and Intelligence Professionals - Richard Thieme](https://www.youtube.com/watch?v=0MzcPBAj88A&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe)
	* Dismissing or laughing off concerns about what it does to a person to know critical secrets does not lessen the impact on life, work, and relationships of building a different map of reality than “normal people” use. One has to calibrate narratives to what another believes. One has to live defensively, warily. This causes at the least cognitive dissonance which some manage by denial. But refusing to feel the pain does not make it go away. It just intensifies the consequences when they erupt. Philip K. Dick said, reality is that which, when you no longer believe in it, does not go away. When cognitive dissonance evolves into symptoms of traumatic stress, one ignores those symptoms at one’s peril. But the very constraints of one’s work often make it impossible to speak aloud about those symptoms, because that might threaten one’s clearances, work, and career. And whistle blower protection is often non-existent.
* **Educational**
	* [Finding Diamonds in the Rough- Parsing for Pentesters](https://bluescreenofjeff.com/2016-07-26-finding-diamonds-in-the-rough-parsing-for-pentesters/)
	* [Hillbilly Storytime - Pentest Fails - Adam Compton](https://www.youtube.com/watch?v=GSbKeTPv2TU)
		* Whether or not you are just starting in InfoSec, it is always important to remember that mistakes happen, even to the best and most seasoned of analysts. The key is to learn from your mistakes and keep going. So, if you have a few minutes and want to talk a load off for a bit, come and join in as a hillbilly spins a yarn about a group unfortunate pentesters and their misadventures. All stories and events are true (but the names have been be changed to prevent embarrassment).
	* [Traversing The Kill-Chain: The New Shiny In 2018 - Vincent Yiu - HITBGSEC 2018](https://www.youtube.com/watch?v=w1fNGOKkeSg&feature=youtu.be)
		* Long gone are the days of easy command shells through PowerShell. Defenders are catching more than ever, forcing red teamers to up their game in new and innovative ways. This presentation will explore several new OSINT sources, techniques, and tools developed to accelerate and assist in target asset discovery and profiling. We will discover how some new advances in EDR has changed the general landscape of more mature organisations, and how red team tactics and procedures have been modified to bypass certain obstacles faced. Relevant techniques will be revised, modified and made great again.
	* [Skills for a Red Teamer - Brent White & Tim Roberts - NolaCon 2018](https://www.youtube.com/watch?reload=9&v=Abr4HgSV9pc)
		* Want to incorporate hybrid security assessments into your testing methodology? What does going above and beyond look like for these types of assessments? How do you provide the best value with the resources and scope provided? What do some of these toolkits encompass? If you’re interested in what skills are needed for a Red-Teamer, or taking your red teaming assessments to the next level, here’s the basic info to get you started. We’ll discuss items of importance, methodology, gear, stories and even some tactics used to help give you an edge.
	* [You’re Probably Not Red Teaming... And Usually I’m Not, Either [SANS ICS 2018] - Deviant Ollam](https://www.youtube.com/watch?v=mj2iSdBw4-0&feature=youtu.be)
* **Phishing**
	* [Hacking Corporate Em@il Systems - Nate Power](http://www.irongeek.com/i.php?page=videos/bsidescolumbus2016/offense04-hacking-corporate-emil-systems-nate-power)
		* In this talk we will discuss current email system attack vectors and how these systems can be abused and leveraged to break into corporate networks. A penetration testing methodology will be discussed and technical demonstrations of attacks will be shown. Phases of this methodology include information gathering, network mapping, vulnerability identification, penetration, privilege escalation, and maintaining access. Methods for organizations to better protect systems will also be discussed.



--------------
### <a name="cobalt"></a>Cobalt Strike
* **Agressor Scripts**
	* [Aggressor Script - cs](https://www.cobaltstrike.com/aggressor-script/index.html)
	* [CS Aggressor Scripts - ramen0x3f](https://github.com/ramen0x3f/AggressorScripts#utilscna)
	* [aggressor_scripts_collection - invokethreatguy](https://github.com/invokethreatguy/aggressor_scripts_collection)
		* Collection of various Aggressor Scripts for Cobalt Strike from awesome people. Will be sure to update this repo with credit to each person.
	* [Aggressor Scripts - oldb00t](https://github.com/oldb00t/AggressorScripts)
	* [aggressor_scripts_collection - invokethreatguy](https://github.com/invokethreatguy/aggressor_scripts_collection)
		* Collection of various aggressor scripts for Cobalt Strike from awesome people. Will be sure to update this repo with credit to each person.
	* [AggressorScripts - bluescreenofjeff](https://github.com/bluscreenofjeff/AggressorScripts)
		* Aggressor scripts for use with Cobalt Strike 3.0+
	* [Agressor Script - rasta-mouse](https://github.com/rasta-mouse/Aggressor-Script)
		* Collection of Aggressor Scripts for Cobalt Strike
	* [CVE-2018-4878](https://github.com/vysec/CVE-2018-4878)
		* Aggressor Script to launch IE driveby for CVE-2018-4878
	* [Aggressor 101: Unleashing Cobalt Strike for Fun and Profit](https://medium.com/@001SPARTaN/aggressor-101-unleashing-cobalt-strike-for-fun-and-profit-879bf22cea31)
	* [UACBypass Aggressor Script](https://github.com/RhinoSecurityLabs/Aggressor-Scripts/tree/master/UACBypass)
		* This aggressor script adds three UAC bypass techniques to Cobalt Strike's interface + beacon console.
* **C2**
	* [Cobalt Strike External C2 Paper](https://www.cobaltstrike.com/downloads/externalc2spec.pdf)
	* [External C2 - cs](https://github.com/outflanknl/external_c2)
		* POC for Cobalt Strike external C2
	* [Cobalt Strike over external C2 – beacon home in the most obscure ways](https://outflank.nl/blog/2017/09/17/blogpost-cobalt-strike-over-external-c2-beacon-home-in-the-most-obscure-ways/)
	* [OPSEC Considerations for Beacon Commands - CobaltStrike](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
	* [Valid SSL Certificates with SSL Beacon - cs](https://www.cobaltstrike.com/help-malleable-c2#validssl)
	* [Randomized Malleable C2 Profiles Made Easy](https://bluescreenofjeff.com/2017-08-30-randomized-malleable-c2-profiles-made-easy/)
	* [OPSEC Considerations for beacon commands](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
	* [Agentless Post Exploitation](https://blog.cobaltstrike.com/2016/11/03/agentless-post-exploitation/)
	* [Malleable-C2-Profiles](https://github.com/rsmudge/Malleable-C2-Profiles)
		* Malleable C2 is a domain specific language to redefine indicators in Beacon's communication. This repository is a collection of Malleable C2 profiles that you may use. These profiles work with Cobalt Strike 3.x.
* **Documentation**
	* [Malleable C2 Documenation - cs](https://www.cobaltstrike.com/help-malleable-c2)
	* [stagelessweb.cna](https://gist.github.com/rsmudge/629bd4ddce3bbbca1f8c16378a6a419c#file-stagelessweb-cna-L6)
		* A stageless variant of the PowerShell Web Delivery attack. This script demonstrates the new scripting APIs in Cobalt Strike 3.7 (generate stageless artifacts, host content on Cobalt Strike's web server, build dialogs, etc.)
* **Phishing**
	* [Cobalt Strike - Spear Phishing documentation](https://www.cobaltstrike.com/help-spear-phish)
	* [Spear phishing with Cobalt Strike - Raphael Mudge](https://www.youtube.com/watch?v=V7UJjVcq2Ao)
	* [Cobalt Strike Blog - What's the go-to phishing technique or exploit?](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
* **Redirectors**
	* [Convert Cobalt Strike profiles to Apache mod_rewrite .htaccess files to support HTTP C2 Redirection](https://github.com/threatexpress/cs2modrewrite)
		* This is a quick script that converts a Cobalt Strike profile to a functional mod_rewrite .htaccess file to support HTTP proxy redirection from Apache to a CobaltStrike teamserver.
	* [redi](https://github.com/taherio/redi)
		* Automated redirector setup compatible with HTTP RATs (CobaltStrike Beacon, meterpreter, etc), and CobaltStrike DNS Beacon. The script can either set up nginx reverse proxy, or DNS proxy/forwarder using dnsmasq. If HTTPS was selected, it will automatically setup letsencrypt certbot and obtain valid letsencrypt SSL certificates for your redirector domain name, and start nginx using the generated configuration.
* **Other**
	* [ANGRYPUPPY](https://github.com/vysec/ANGRYPUPPY)
		* Bloodhound Attack Path Execution for Cobalt Strike
	* [Modern Defense and You - CS](https://blog.cobaltstrike.com/2017/10/25/modern-defenses-and-you/)
	* [User Driven Attacks - cs](https://blog.cobaltstrike.com/2014/10/01/user-driven-attacks/)
	* [DDEAutoCS](https://github.com/p292/DDEAutoCS)
		* A cobaltstrike script that integrates DDEAuto Attacks (launches a staged powershell CS beacon). This is not massively stealthy as far as CS scripts go anything like that at the moment, more of a proof of concept, and for having a play. Customise as you see fit to your needs.
	* [CSFM - Cobal Strike Field Manual](https://github.com/001SPARTaN/csfm)
		* Cobalt Strike Field Manual - A quick reference for Windows commands that can be accessed in a beacon console.
	* [Cobalt Strike Visualizations - SPARTan](https://medium.com/@001SPARTaN/cobalt-strike-visualizations-e6a6e841e16b)






--------------
### <a name="cnc"></a>Command & Control
* **General/Non-PoC&Dev Stuff**
	* [Abusing "Accepted Risk" With 3rd Party C2 - HackMiamiCon5](https://www.slideshare.net/sixdub/abusing-accepted-risk-with-3rd-party-c2-hackmiamicon5)
* **Development Of**
	* [CheckPlease](https://github.com/Arvanaghi/CheckPlease)
		* Implant-Security modules written in PowerShell, Python, Go, Ruby, C, C#, Perl, and Rust. 
	* [How to Build a 404 page not found C2](https://www.blackhillsinfosec.com/?p=5134)
	* [emptynest](https://github.com/empty-nest/emptynest)
		* Emptynest is a plugin based C2 server framework. The goal of this project is not to replace robust tools such as Empire, Metasploit, or Cobalt Strike. Instead, the goal is to create a supporting framework for quickly creating small, purpose built handlers for custom agents. No agent is provided. Users of Emptynest should create their own agents that implement minimal functionality and can be used to evade detection and establish a more robust channel. An example of an agent might support Unhooking, DLL Unloading, and code execution. Due to the simple nature of this project, it is recommended that agents be kept private.
	* [RemoteRecon](https://github.com/xorrior/RemoteRecon)
		* RemoteRecon provides the ability to execute post-exploitation capabilities against a remote host, without having to expose your complete toolkit/agent. Often times as operator's we need to compromise a host, just so we can keylog or screenshot (or some other miniscule task) against a person/host of interest. Why should you have to push over beacon, empire, innuendo, meterpreter, or a custom RAT to the target? This increases the footprint that you have in the target environment, exposes functionality in your agent, and most likely your C2 infrastructure. An alternative would be to deploy a secondary agent to targets of interest and collect intelligence. Then store this data for retrieval at your discretion. If these compromised endpoints are discovered by IR teams, you lose those endpoints and the information you've collected, but nothing more.
	* [Expand Your Horizon Red Team – Modern SaaS C2](https://cybersyndicates.com/2017/04/expand-your-horizon-red-team/)
* **Communication Channel Example PoCs**
	* **404**
		* [How to Build a 404 page not found C2](https://www.blackhillsinfosec.com/?p=5134)
		* [404 File not found C2 PoC](https://github.com/theG3ist/404)
	* **ActiveDirectory Features**
		* [Command and Control Using Active Directory](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)
	* **ARP**
		* [Zarp](https://github.com/hatRiot/zarp)
			* Zarp is a network attack tool centered around the exploitation of local networks. This does not include system exploitation, but rather abusing networking protocols and stacks to take over, infiltrate, and knock out. Sessions can be managed to quickly poison and sniff multiple systems at once, dumping sensitive information automatically or to the attacker directly. Various sniffers are included to automatically parse usernames and passwords from various protocols, as well as view HTTP traffic and more. DoS attacks are included to knock out various systems and applications.
	* **Browser**
		* [Browser-C2](https://github.com/0x09AL/Browser-C2)
			* Post Exploitation agent which uses a browser to do C2 operations.
	* **Cobalt Strike**
		* [External C2](https://github.com/ryhanson/ExternalC2)
			* A library for integrating communication channels with the Cobalt Strike External C2 server
	* **DNS-based**
		* [C2 with DNS](https://pentestlab.blog/2017/09/06/command-and-control-dns/)
		* [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell)
			* A Powershell client for dnscat2, an encrypted DNS command and control tool
		* [DNS-Persist](https://github.com/0x09AL/DNS-Persist)
			* DNS-Persist is a post-exploitation agent which uses DNS for command and control. The server-side code is in Python and the agent is coded in C++.
	* **Email**
		* [DicerosBicornis](https://github.com/maldevel/dicerosbicornis)
			* A stealthy Python based Windows backdoor that uses email as a command and control server.
	* **HTTP/S-based**
		* [PoshC2 v3 with SOCKS Proxy (SharpSocks)](https://labs.nettitude.com/blog/poshc2-v3-with-socks-proxy-sharpsocks/)
		* [PoshC2](https://github.com/nettitude/PoshC2)
			* Powershell C2 Server and Implants
		* [Galvatron](https://github.com/khr0x40sh/Galvatron)
			* Powershell fork of Monohard by Carlos Ganoza P. This botnet/backdoor was designed to egress over unecrypted web using very little, but effective obfuscation. Egress over ICMP and DNS are planned as features. Lastly, the server code is designed to setup the C2 on a LAMP-esque server. The default creds are admin/admin.
		* [C2 with https](https://pentestlab.blog/2017/10/04/command-and-control-https/)
		* [C2 over TLS Certs - Casey Smith](https://gist.github.com/caseysmithrc/a4c4748160ff9c782d8a86723dbc7334?t=1&cn=ZmxleGlibGVfcmVjcw%3D%3D&refsrc=email&iid=6e15d70104f847a8ae7723921067fe1d&fl=4&uid=150127534&nid=244+285282312)
		* [ThunderShell](https://github.com/Mr-Un1k0d3r/ThunderShell)
			* ThunderShell is a Powershell based RAT that rely on HTTP request to communicate. All the network traffic is encrypted using a second layer of RC4 to avoid SSL interception and defeat network hooks.
		* [FruityC2](https://github.com/xtr4nge/FruityC2)
			* FruityC2 is a post-exploitation (and open source) framework based on the deployment of agents on compromised machines. Agents are managed from a web interface under the control of an operator.
		* [PlugBot-C2C](https://github.com/redteamsecurity/PlugBot-C2C)
			* This is the Command & Control component of the PlugBot project
		* [EggShell](https://github.com/neoneggplant/EggShell)
			* EggShell is an iOS and macOS post exploitation surveillance pentest tool written in Python. This tool creates 1 line multi stage payloads that give you a command line session with extra functionality. EggShell gives you the power and convenience of uploading/downloading files, taking pictures, location tracking, shell command execution, persistence, escalating privileges, password retrieval, and much more. Server communication features end to end encryption with 128 bit AES and the ability to handle multiple clients. This is a proof of concept pentest tool, intended for use on machines you own.
			* [EggShell Blogpost](http://lucasjackson.me/dWkKX/index.php/eggshell)
		* [A Guide to Configuring Throwback](https://silentbreaksecurity.com/throwback-thursday-a-guide-to-configuring-throwback/)
			* [Throwback - beacon](https://github.com/silentbreaksec/Throwback)
			* [Throwback Listener](https://github.com/silentbreaksec/ThrowbackLP)
	* **HTTP2**
		* [Merlin](https://github.com/Ne0nd0g/merlin)
			* Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
	* **ICMP**
		* [ICMP C2](https://pentestlab.blog/2017/07/28/command-and-control-icmp/)
		* [C2 with ICMP](https://pentestlab.blog/2017/07/28/command-and-control-icmp/)
	* **PAC**
		* [Pacdoor](https://github.com/SafeBreach-Labs/pacdoor)
			* Pacdoor is a proof-of-concept JavaScript malware implemented as a Proxy Auto-Configuration (PAC) File. Pacdoor includes a 2-way communication channel, ability to exfiltrate HTTPS URLs, disable access to cherry-picked URLs etc.
	* **SSH** 
		* [Spidernet](https://github.com/wandering-nomad/Spidernet)
			* Proof of Concept of SSH Botnet C&C Using Python 
	* **Social Media-based**
		* [JSBN](https://github.com/Plazmaz/JSBN)
			* JSBN is a bot client which interprets commands through Twitter, requiring no hosting of servers or infected hosts from the command issuer. It is written purely in javascript as a Proof-of-Concept for javascript's botnet potentials.
		* [C2 with twitter](https://pentestlab.blog/2017/09/26/command-and-control-twitter/)
		* [C2 with Telegram](https://github.com/graniet/gshark-framework)
		* [BrainDamage](https://github.com/mehulj94/BrainDamage)
			* A fully featured backdoor that uses Telegram as a C&C server
		* [twittor - twitter based backdoor](https://github.com/PaulSec/twittor)
			* A stealthy Python based backdoor that uses Twitter (Direct Messages) as a command and control server This project has been inspired by Gcat which does the same but using a Gmail account.
		* [Instegogram](https://github.com/endgameinc/instegogram)
		* [canisrufus](https://github.com/maldevel/canisrufus)
			* A stealthy Python based Windows backdoor that uses Github as a command and control server.
	* **WebDAV**
		* [C2 with webdav](https://pentestlab.blog/2017/09/12/command-and-control-webdav/)
		* [Using WebDAV features as a covert channel](https://arno0x0x.wordpress.com/2017/09/07/using-webdav-features-as-a-covert-channel/)
	* **Web Services**
		* [C2 with Dropbox](https://pentestlab.blog/2017/08/29/command-and-control-dropbox/)
		* [DBC2](https://github.com/Arno0x/DBC2)
			* DBC2 (DropboxC2) is a modular post-exploitation tool, composed of an agent running on the victim's machine, a controler, running on any machine, powershell modules, and Dropbox servers as a means of communication.
		* [C2 with gmail](https://pentestlab.blog/2017/08/03/command-and-control-gmail/)	
		* [Simple domain fronting PoC with GAE C2 server](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)
		* [google_socks](https://github.com/lukebaggett/google_socks)
			* A proof of concept demonstrating the use of Google Drive for command and control.
		* [Powershell Github Shell](https://github.com/zlocal/Powershell-Github-Shell)
		* [google_RAT](https://github.com/a-rey/google_RAT)
			* A remote access tool for Windows systems using google apps script as the middle man
	* **WebSockets**
		* [WSC2](https://github.com/Arno0x/WSC2)
			* WSC2 is a PoC of using the WebSockets and a browser process to serve as a C2 communication channel between an agent, running on the target system, and a controller acting as the actual C2 server.
		* [Using WebSockets and IE/Edge for C2 communications](https://arno0x0x.wordpress.com/2017/11/10/https://github.com/leoloobeek/GoG reen/blob/master/README.mdusing-websockets-and-ie-edge-for-c2-communications/)
		* [MurDock - Mutable Universal Relay Document Kit](https://github.com/themson/MurDocK)
			* The purpose of this tool is to provide a protocol independent framework that contains a base set of features that can piggyback on top of any collaborative web platform or service. The base docClient and docServer are meant to be extended upon with Buffer classes written for individual web services. These buffer classes can be plugged into the MurDock framework in order to create a unique shell infrastructure that will always contains a base set of features, as well as the ability to tunnel over any web application traffic for which a buffer class has been constructed. The framework can be extended to operate over lower level protocols if desired.
	* **WMI-based**
		* [WMImplant](https://github.com/ChrisTruncer/WMImplant)
			* WMImplant is a PowerShell based tool that leverages WMI to both perform actions against targeted machines, but also as the C2 channel for issuing commands and receiving results. WMImplant will likely require local administrator permissions on the targeted machine.	
		* [WheresMyImplant](https://github.com/0xbadjuju/WheresMyImplant)
			* This WMI provider includes functions to execute commands, payloads, and Empire Agent to maintain a low profile on the host. This is related to the project PowerProvider. PowerProvider provides the deployment methods for the implant.
		* [PowerProvider](https://github.com/0xbadjuju/PowerProvider/)
			* PowerProvider: A toolkit to manipulate WMI. Used with WheresMyImplant
* **Papers**
	* [Command & Control: Understanding, Denying and Detecting - 2014 - Joseph Gardiner, Marco Cova, Shishir Nagaraja](https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf)




---------------------------------	
### <a name="domains"></a>Domains and Domain Related Things
* **Domain Fronting**
	* **101**
		* [Blocking-resistant communication through domain fronting](https://www.bamsoftware.com/talks/fronting-pets2015/)
		* [Camouflage at encryption layer: domain fronting](https://www.securityartwork.es/2017/01/24/camouflage-at-encryption-layer-domain-fronting/)
		* [Domain Fronting - Infosec Institute](http://resources.infosecinstitute.com/domain-fronting/)
	* **Articles/Writeups**
		* [High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
		* [TOR Fronting – Utilising Hidden Services for Privacy](https://www.mdsec.co.uk/2017/02/tor-fronting-utilising-hidden-services-for-privacy/)
		* [Finding Domain frontable Azure domains - thoth / Fionnbharr (@a_profligate)](https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html)
		* [Domain Fronting Via Cloudfront Alternate Domains](https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/)
		* [TTP: Domain Fronting with Metasploit and Meterpreter - beyondbinary](https://beyondbinary.io/articles/domain-fronting-with-metasploit-and-meterpreter/)
		* [Alibaba CDN Domain Fronting - Vincent Yiu](https://medium.com/@vysec.private/alibaba-cdn-domain-fronting-1c0754fa0142)
		* [How I Identified 93k Domain-Frontable CloudFront Domains](https://www.peew.pw/blog/2018/2/22/how-i-identified-93k-domain-frontable-cloudfront-domains)
		* [Metasploit Domain Fronting With Microsoft Azure - chigstuff](https://chigstuff.com/blog/metasploit-domain-fronting-with-microsoft-azure/)
		* [Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/)
		* [DomainFrontingLists](https://github.com/vysec/DomainFrontingLists)
			* A list of Domain Frontable Domains by CDN
		* [Metasploit Domain Fronting With Microsoft Azure - Chris Higgins](https://chigstuff.com/blog/metasploit-domain-fronting-with-microsoft-azure/)
	* **Talks & Videos**
	* **Tools**
		* **Finding Vulnerable Domains**
			* [DomainFrontDiscover](https://github.com/peewpw/DomainFrontDiscover)
				* Scripts and results for finding domain frontable CloudFront domains
			* [FindFrontableDomains](https://github.com/rvrsh3ll/FindFrontableDomains)
				* Search for potential frontable domains
			* [Simple domain fronting PoC with GAE C2 server](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)
				* In this entry we continue with domain fronting; on this occasion we will explore how to implement a simple PoC of a command and control and exfiltration server on Google App Engine (GAE), and we will see how to do the domain fronting from Windows, with a VBS or PowerShell script, to hide interactions with the C2 server.
			* [Finding Frontable Domain](https://github.com/rvrsh3ll/FindFrontableDomains)
* **Tools**
	* **Identifyin Useful Domains**
		* [Domain Hunter](https://github.com/minisllc/domainhunter)
			* Checks expired domains, bluecoat categorization, and Archive.org history to determine good candidates for phishing and C2 domain names
		* [AIRMASTER](https://github.com/t94j0/AIRMASTER)
			* Use ExpiredDomains.net and BlueCoat to find useful domains for red team.
	* **Domain Reputation/Identification**
		* [Chameleon](https://github.com/mdsecactivebreach/Chameleon)
			* Chameleon is a tool which assists red teams in categorising their infrastructure under arbitrary categories. Currently, the tool supports arbitrary categorisation for Bluecoat, McAfee Trustedsource and IBM X-Force. However, the tool is designed in such a way that additional proxies can be added with ease.
		* [CatMyFish](https://github.com/Mr-Un1k0d3r/CatMyFish)
			* Search for categorized domain that can be used during red teaming engagement. Perfect to setup whitelisted domain for your Cobalt Strike beacon C&C.  It relies on expireddomains.net to obtain a list of expired domains. The domain availability is validated using checkdomain.com
* **Domain Reputation Sites**
	* [Alien Vault](http://www.alienvault.com)
	* [Isithacked?](http://www.isithacked.com)
	* [Robtex](https://dns.robtex.com)
	* [Scan4You](http://scan4you.net/)
	* [Sucuri](http://sitecheck.sucuri.net/scanner/)
	* [Trustedsource](http://www.trustedsource.org/)
	* [urlQuery](http://urlquery.net/search.php)
	* [URLVoid](http://www.urlvoid.com/scan/)
	* [VirusTotal](https://www.virustotal.com/)
	* [WOT](http://www.mywot.com/en/scorecard)
	* [Zeltser BL](http://zeltser.com)
* **Redirectors**
	* **101**
	* **Articles/Writeups**
		* [Redirecting Cobalt Strike DNS Beacons](http://www.rvrsh3ll.net/blog/offensive/redirecting-cobalt-strike-dns-beacons/)
		* [High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
		* [Cobalt Strike HTTP C2 Redirectors with Apache mod_rewrite - Jeff Dimmock](https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/)
	* **Samples/Setups**
		* [Apache2Mod Rewrite Setup](https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup)








-----------------------------------
### <a name="egress"></a>Egress/Exfiltration
* **See Also: <a href="Exfiltration.md">Exfiltration.md</a>
* **Articles**
	* [Practical Comprehensive Bounds on Surreptitious Communication Over DNS](http://www.icir.org/vern/papers/covert-dns-usec13.pdf)
	* [Exfiltration by encoding data in pixel colour values](https://www.pentestpartners.com/security-blog/exfiltration-by-encoding-data-in-pixel-colour-values/)
	* [Data Sound Modulation POC](https://github.com/iiamit/data-sound-poc)
	* [Hiding Malicious Traffic Under the HTTP 404 Error](https://blog.fortinet.com/2015/04/09/hiding-malicious-traffic-under-the-http-404-error)
	* [Covert Channels in TCP/IP Protocol Stack - extended version-](https://eprints.ugd.edu.mk/10284/1/surveyAMBPselfArc.pdf)
	* [A Survey of Covert Channels and Countermeasures in Computer Network Protocols](http://caia.swin.edu.au/cv/szander/publications/szander-ieee-comst07.pdf)
		* Covert channels are used for the secret transfer of information. Encryption only protects communication from being decoded by unauthorised parties, whereas covert channels aim to hide the very existence of the communication. Initially, covert channels were identified as a security threat on monolithic systems i.e. mainframes. More recently focus has shifted towards covert channels in computer network protocols. The huge amount of data and vast number of different protocols in the Internet seems ideal as a high-bandwidth vehicle for covert communication. This article is a survey of the existing techniques for creating covert channels in widely deployed network and application protocols. We also give an overview of common methods for their detection, elimination, and capacity limitation, required to improve security in future computer networks.
	* [Covert Timing Channels Based on HTTP Cache Headers - Video Presentation](https://www.youtube.com/watch?v=DOAG3mtz7H4)
	* [Covert Timing Channels Based on HTTP Cache Headers - Paper](https://scholarworks.rit.edu/cgi/viewcontent.cgi?filename=0&article=1784&context=other&type=additional)
	* [Blocking-resistant communication through domain fronting](https://www.bamsoftware.com/papers/fronting/)
	* [Egressing Bluecoat with CobaltStike & Let's Encrypt](https://cybersyndicates.com/2016/12/egressing-bluecoat-with-cobaltstike-letsencrypt/)
	* [Project Loki - Phrack 7-49](http://phrack.org/issues/49/6.html)
		* This whitepaper is intended as a complete description of the covert channel that exists in networks that allow ping traffic (hereon referred to in the more general sense of ICMP_ECHO traffic --see below) to pass.
	* [Escape and Evasion Egressing Restricted Networks - Tom Steele and Chris Patten](https://www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks)
* **Talks**
	* [DIY Spy Covert Channels With Scapy And Python - Jen Allen - ANYCON 2017](http://www.irongeek.com/i.php?page=videos/anycon2017/diy-spy-covert-channels-with-scapy-and-python-jen-allen)
	* [Goodbye Data, Hello Exfiltration - Itzik Kotler](https://www.youtube.com/watch?v=GwaIvm2HJKc)
		* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.
		* [Slides](http://www.ikotler.org/GoodbyeDataHelloExfiltration_BSidesORL.pdf)
	* [Itzik Kotler | Goodbye Data, Hello Exfiltration - BSides Orlando](https://www.youtube.com/watch?v=GwaIvm2HJKc)
		* Penetration testing isn’t about getting in, it’s also about getting out with the goodies. In this talk, you will learn how leverage commonly installed software (not Kali Linux!) to exfiltrate data from networks. Moving on to more advanced methods that combines encryption, obfuscation, splitting (and Python). Last but not least, I’ll address data exfiltration via physical ports and demo one out-of-the-box method to do it.
	* [In Plain Sight: The Perfect Exfiltration Technique - Itzik Kotler and Amit Klein - HiTB2016](https://www.youtube.com/watch?v=T6PscV43C0w)
		* In this session, we will reveal and demonstrate perfect exfiltration via indirect covert channels (i.e. the communicating parties don’t directly exchange network packets). This is a family of techniques to exfiltrate data (low throughput) from an enterprise in a manner indistinguishable from genuine traffic. Using HTTP and exploiting a byproduct of how some websites choose to cache their pages, we will demonstrate how data can be leaked without raising any suspicion. These techniques are designed to overcome even perfect knowledge and analysis of the enterprise network traffic.
	* [How To Bypass Email Gateways Using Common Payloads by Neil Lines - BSides Manchester2017](https://www.youtube.com/watch?v=eZxWDCetqkE&index=11&list=PLcgqQkap1lNrOBNCXqpPqpPAqckxv0XhP)
* **Tools**
	* [PTP-RAT](https://github.com/pentestpartners/PTP-RAT)
		* Exfiltrate data over screen interfaces
	




--------------
### <a name="empire"></a>Empire
* **Articles**
	* [Hunting Red Team Empire C2 Infrastructure](http://www.chokepoint.net/2017/04/hunting-red-team-empire-c2.html)
	* [Athena: The CIA’s RAT vs Empire](https://bneg.io/2017/05/22/athena-the-cias-rat-vs-empire/)
	* [Bringing the hashes home with reGeorg & Empire](https://sensepost.com/blog/2016/bringing-the-hashes-home-with-regeorg-empire/)
	* [Intercepting passwords with Empire and winning](https://sensepost.com/blog/2016/intercepting-passwords-with-empire-and-winning/)
	* [Advanced Weapons Training - for the Empire - Jeremy Johnson](https://www.slideshare.net/JeremyJohnson166/advanced-weapons-training-for-the-empire)
	* [Empire API Cheat Sheet](https://github.com/SadProcessor/Cheats/blob/master/EmpireAPI.md)
	* [Evading Anomaly-Based NIDS with Empire - Utku Sen blog](https://utkusen.com/blog/bypassing-anomaly-based-nids-with-empire.html)
* **Customizing**
	* [Using PowerShell Empire with a Trusted Certificate](https://www.blackhillsinfosec.com/using-powershell-empire-with-a-trusted-certificate/)
	* [How to Make Empire Communication profiles - bluescreenofjeff](https://github.com/bluscreenofjeff/bluscreenofjeff.github.io/blob/master/_posts/2017-03-01-how-to-make-communication-profiles-for-empire.md)
	* [Empire – Modifying Server C2 Indicators](http://threatexpress.com/2017/05/empire-modifying-server-c2-indicators/)
	* [Empire Domain Fronting](https://www.xorrior.com/Empire-Domain-Fronting/)
	* [Empire without powershell](https://bneg.io/2017/07/26/empire-without-powershell-exe/)
	* [Build Your Own: Plugins in Empire - strikersecurity](https://strikersecurity.com/blog/empire-plugins/)
* **Manual**
	* [RedTrooperFM - Empire Module Wiki](https://github.com/SadProcessor/Cheats/blob/master/RedTrooperFM.md)
		* A one page Wiki for all your Empire RTFM needs...
	* [Encrypted Key Exchange understanding - StackOverflow](https://stackoverflow.com/questions/15779392/encrypted-key-exchange-understanding)
* **Modules & Additions/Extensions**
	* [Empire-mod-Hackplayers](https://github.com/Hackplayers/Empire-mod-Hackplayers)
		* Collection of custom Empire Modules
	* [Sharpire - An implimentation of the Empire Agent in C#](https://github.com/0xbadjuju/Sharpire)
	* [Automated Empire Infrastructure - bneg.io](https://bneg.io/2017/11/06/automated-empire-infrastructure/)


--------------
##### <a name="hardware"></a>HW Related
* **Dropboxes**
	* [DigiDucky - How to setup a Digispark like a rubber ducky](http://www.redteamr.com/2016/08/digiducky/)
	* [Bash Bunny](https://hakshop.com/products/bash-bunny)
	* [How to Build Your Own Penetration Testing Drop Box - BHIS](https://www.blackhillsinfosec.com/?p=5156&)
	* [P4wnP1](https://github.com/mame82/P4wnP1)
		* P4wnP1 is a highly customizable USB attack platform, based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W.
* **Physical Implants Relating to Persistence Methods**
	* **Articles/Writeups**
		* [Implanting a Dropcam](https://www.defcon.org/images/defcon-22/dc-22-presentations/Moore-Wardle/DEFCON-22-Colby-Moore-Patrick-Wardle-Synack-DropCam-Updated.pdf)
	* **Papers**
		* [Stealthy Dopant-Level Hardware Trojans](Hardware level trojans http://sharps.org/wp-content/uploads/BECKER-CHES.pdf)
			* Abstract: In this paper we propose an extremely stealthy approach for implementing hardware Trojans below the gate level, and we evaluate their impact on the security of the target device. Instead of adding additional circuitry to the target design, we insert our hardware Trojans by changing the dopant polarity of existing transistors. Since the modied circuit ap- pears legitimate on all wiring layers (including all metal and polysilicon), our family of Trojans is resistant to most detection techniques, including negrain optical inspection and checking against \golden chips". We demonstrate the e ectiveness of our approach by inserting Trojans into two designs | a digital post-processing derived from Intel's cryptographically secure RNG design used in the Ivy Bridge processors and a side-channel resistant SBox implementation | and by exploring their detectability and their effects on security.
		* [Implementation and Implications of a Stealth Hard-Drive Backdoor](https://www.ibr.cs.tu-bs.de/users/kurmus/papers/acsac13.pdf) 
			* Modern workstations and servers implicitly trust hard disks to act as well-behaved block devices. This paper analyzes the catastrophic loss of security that occurs when hard disks are not trustworthy. First, we show that it is possible to compromise the firmware of a commercial ovt-the-shelf hard drive, by resorting only to public information and reverse engineering. Using such a compromised firmware, we present a stealth rootkit that replaces arbitrary blocks from the disk while they are written, providing a data replacement back- door . The measured performance overhead of the compromised disk drive is less than 1% compared with a normal, non-malicious disk drive. We then demonstrate that a re- mote attacker can even establish a communication channel with a compromised disk to infiltrate commands and to ex-filtrate data. In our example, this channel is established over the Internet to an unmodified web server that relies on the compromised drive for its storage, passing through the original webserver, database server, database storage engine, filesystem driver, and block device driver. Additional experiments, performed in an emulated disk-drive environment, could automatically extract sensitive data such as /etc/shadow (or a secret key le) in less than a minute. This paper claims that the diffculty of implementing such an at- tack is not limited to the area of government cyber-warfare; rather, it is well within the reach of moderately funded criminals, botnet herders and academic researchers.
		* [Inside a low budget consumer hardware espionage implant](https://ha.cking.ch/s8_data_line_locator/)
	* **Teensy**
		* [USB teensy attack set OSX](http://samy.pl/usbdriveby/)
		* [Paensy](https://github.com/Ozuru/Paensy)
			* Paensy is a combination of the word payload and Teensy - Paensy is an attacker-oriented library written for the development of Teensy devices. Paensy simplifies mundane tasks and allows an easier platform for scripting.
			* [Blogpost](http://malware.cat/?p=89)












--------------
### <a name="infrastructure"></a>Infrastructure
* **General**
	* [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
		* Wiki to collect Red Team infrastructure hardening resources
		* Accompanying Presentation: [Doomsday Preppers: Fortifying Your Red Team Infrastructure](https://speakerdeck.com/rvrsh3ll/doomsday-preppers-fortifying-your-red-team-infrastructure)
	* [6 RED TEAM INFRASTRUCTURE TIPS](https://cybersyndicates.com/2016/11/top-red-team-tips/)
* **Articles & Writeups**
	* [Building a Better Moat: Designing an Effective Covert Red Team Attack Infrastructure - @bluescreenofjeff](https://speakerdeck.com/bluscreenofjeff/building-a-better-moat-designing-an-effective-covert-red-team-attack-infrastructure)
	* [Infrastructure for Ongoing Red Team Operations](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations/)
	* [How to Build a C2 Infrastructure with Digital Ocean – Part 1](https://www.blackhillsinfosec.com/build-c2-infrastructure-digital-ocean-part-1/)
	* [Automated Red Team Infrastructure Deployment with Terraform - Part 1](https://rastamouse.me/2017/08/automated-red-team-infrastructure-deployment-with-terraform---part-1/)
	* [Migrating Your infrastructure](https://blog.cobaltstrike.com/2015/10/21/migrating-your-infrastructure/)
* **Hardware**
	* [tap](https://github.com/trustedsec/tap)
		* TAP is a remote penetration testing platform builder. For folks in the security industry, traveling often times becomes a burden and adds a ton of cost to the customer. TAP was designed to make the deployment of these boxes super simple and create a self-healing and stable platform to deploy remote penetration testing platforms. Essentially the concept is simple, you pre-configure a brand new box and run the TAP setup file. This will install a service on Linux that will be configured the way you want. What it will do is establish a reverse SSH tunnel back to a machine thats exposed on the Internet for you. From there you can access the box locally from the server it connects back to. TAP automatically detects when an SSH connection has gone stale and will automatically rebuild it for you.
	* [Red Team Laptop & Infrastructure (pt 1: Architecture) - hon1nbo](https://hackingand.coffee/2018/02/assessment-laptop-architecture/)
* **Logging**
	* [Attack Infrastructure Log Aggregation and Monitoring](https://posts.specterops.io/attack-infrastructure-log-aggregation-and-monitoring-345e4173044e)
* **Scripts**
	* [Red Baron](https://github.com/Coalfire-Research/Red-Baron)
		* Red Baron is a set of modules and custom/third-party providers for Terraform which tries to automate creating resilient, disposable, secure and agile infrastructure for Red Teams.
	* [RedTeam-Automation - bneg](https://github.com/bneg/RedTeam-Automation)
		* Automating those tasks which can or should be automated
* **Tools**
	* **Pentest Box Setup**
		* [Trusted Attack Platform - TrustedSec](https://github.com/trustedsec/tap)
			* TAP is a remote penetration testing platform builder. For folks in the security industry, traveling often times becomes a burden and adds a ton of cost to the customer. TAP was designed to make the deployment of these boxes super simple and create a self-healing and stable platform to deploy remote penetration testing platforms. Essentially the concept is simple, you pre-configure a brand new box and run the TAP setup file. This will install a service on Linux that will be configured the way you want. What it will do is establish a reverse SSH tunnel back to a machine thats exposed on the Internet for you. From there you can access the box locally from the server it connects back to. TAP automatically detects when an SSH connection has gone stale and will automatically rebuild it for you.
	* **Other**
		* [APT Simulator](https://github.com/NextronSystems/APTSimulator)
			* APT Simulator is a Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised
* **Wireless**
	* [Rogue Toolkit](https://github.com/InfamousSYN/rogue)
		* The Rogue Toolkit: An extensible toolkit aimed at providing penetration testers an easy-to-use platform to deploy Access Points for the purpose of conducting penetration testing and red team engagements.



------------------
### <a name="payload"></a>Payloads
* **Development**
	* [covertutils - A framework for Backdoor development!](https://github.com/operatorequals/covertutils)
		* This Python package is used to create Agent/Handler backdoors, like metasploit's meterpreter, empire's empire agent, cobalt strike's beacon and so on... It automatically handles all communication channel options, like encryption, chunking, steganography, sessions, etc. With a recent package addition (httpimport), staging from pure Python2/3 is finally possible! With all those set with a few lines of code, a programmer can spend time creating the actual payloads, persistense mechanisms, shellcodes and generally more creative stuff!! The security programmers can stop re-inventing the wheel by implementing encryption mechanisms both Agent-side and Handler-side to spend their time developing more versatile Agents, and generally feature-rich shells!
* **Tools**
	* [Demiguise](https://github.com/nccgroup/demiguise)
		* The aim of this project is to generate .html files that contain an encrypted HTA file. The idea is that when your target visits the page, the key is fetched and the HTA is decrypted dynamically within the browser and pushed directly to the user. This is an evasion technique to get round content / file-type inspection implemented by some security-appliances. This tool is not designed to create awesome HTA content. There are many other tools/techniques that can help you with that. What it might help you with is getting your HTA into an environment in the first place, and (if you use environmental keying) to avoid it being sandboxed.
	* [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter)
		* SharpShooter is a payload creation framework for the retrieval and execution of arbitrary CSharp source code. SharpShooter is capable of creating payloads in a variety of formats, including HTA, JS, VBS and WSF. It leverages James Forshaw's DotNetToJavaScript tool to invoke methods from the SharpShooter DotNet serialised object. Payloads can be retrieved using Web or DNS delivery or both; SharpShooter is compatible with the MDSec ActiveBreach PowerDNS project. Alternatively, stageless payloads with embedded shellcode execution can also be generated for the same scripting formats.
* **Examples/Samples**
	* [Invoke-BSOD](https://github.com/peewpw/Invoke-BSOD)
		* A PowerShell script to induce a Blue Screen of Death (BSOD) without admin privileges. Also enumerates Windows crash dump settings. This is a standalone script, it does not depend on any other files.
	* [Pupy](https://github.com/n1nj4sec/pupy)
		* Pupy is an opensource, multi-platform Remote Administration Tool with an embedded Python interpreter. Pupy can load python packages from memory and transparently access remote python objects. Pupy can communicate using different transports and have a bunch of cool features & modules. On Windows, Pupy is a reflective DLL and leaves no traces on disk.
		* [Pupy WebSocket Transport](https://bitrot.sh/post/28-11-2017-pupy-websocket-transport/)
	* [RedSails](https://github.com/BeetleChunks/redsails)
		* Python based post-exploitation project aimed at bypassing host based security monitoring and logging. [DerbyCon 2017 Talk](https://www.youtube.com/watch?v=Ul8uPvlOsug)
	* [stupid_malware](https://github.com/andrew-morris/stupid_malware)
		* Python malware for pentesters that bypasses most antivirus (signature and heuristics) and IPS using sheer stupidity
	* [Dragon: A Windows, non-binding, passive download / exec backdoor](http://www.shellntel.com/blog/2015/6/11/dragon-a-windows-non-binding-passive-downloadexec-backdoor)
	* [MetaTwin](https://github.com/minisllc/metatwin)
		* The project is designed as a file resource cloner. Metadata, including digital signature, is extracted from one file and injected into another. Note: Signatures are copied, but no longer valid.
		* [Blogpost](http://threatexpress.com/2017/10/metatwin-borrowing-microsoft-metadata-and-digital-signatures-to-hide-binaries/)
	* [Windows oneliners to download remote payload and execute arbitrary code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
	* [Stitch](https://github.com/nathanlopez/Stitch)
		* This is a cross platform python framework which allows you to build custom payloads for Windows, Mac OSX and Linux as well. You are able to select whether the payload binds to a specific IP and port, listens for a connection on a port, option to send an email of system info when the system boots, and option to start keylogger on boot. Payloads created can only run on the OS that they were created on.
	* [QuasarRAT](https://github.com/quasar/QuasarRAT)
		* Quasar is a fast and light-weight remote administration tool coded in C#. Providing high stability and an easy-to-use user interface, Quasar is the perfect remote administration solution for you.
	* [Ares](https://github.com/sweetsoftware/Ares)
		* Ares is a Python Remote Access Tool.
	* [CHAOS](https://github.com/tiagorlampert/CHAOS)
		* Windows payload generator in go
	* [go-deliver](https://github.com/0x09AL/go-deliver)
		* Go-deliver is a payload delivery tool coded in Go.






----------
### <a name="persistence"></a>Persistence
* [Staying Persistent in Software Defined Networks](https://www.blackhat.com/docs/us-15/materials/us-15-Pickett-Staying-Persistent-In-Software-Defined-Networks-wp.pdf)
* [Phant0m: Killing Windows Event Log Phant0m: Killing Windows Event Log](https://artofpwn.com/phant0m-killing-windows-event-log.html)
* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m)
	* This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.
* [Software Distribution Malware Infection Vector](https://dl.packetstormsecurity.net/papers/general/Software.Distribution.Malware.Infection.Vector.pdf)



--------------
### <a name="tactics"></a>Tactics
* **Ideas**
	* **Articles/Blogposts/Writeups**
		* [Hiding your process from sysinternals](https://riscybusiness.wordpress.com/2017/10/07/hiding-your-process-from-sysinternals/)
		* [Google Calendar Event Injection with MailSniper](https://www.blackhillsinfosec.com/google-calendar-event-injection-mailsniper/)	
		* [#OLEOutlook - bypass almost every Corporate security control with a point’n’click GUI](https://doublepulsar.com/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0)
		* [Offensive Encrypted Data Storage](http://www.harmj0y.net/blog/redteaming/offensive-encrypted-data-storage/)
		* [Offensive Encrypted Data Storage (DPAPI edition)](https://posts.specterops.io/offensive-encrypted-data-storage-dpapi-edition-adda90e212ab)
		* [File Server Triage on Red Team Engagements](http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/)
		* [Advanced Threat Analytics Attack Simulation Playbook - Microsoft](https://gallery.technet.microsoft.com/Advanced-Threat-Analytics-8b0a86bc)
		* [Week of Evading Microsoft ATA - Announcement and Day 1 to Day 5](http://www.labofapenetrationtester.com/2017*8/week-of-evading-microsoft-ata-day1.html)
		* [LAteral Movement Encryption technique (a.k.a. The "LAME" technique) - dotelite.gr](https://dotelite.gr/the-lame-technique/amp/?__twitter_impression=true)
		* [How to Bypass Safe Link/Attachment Processing of ATP - support.knowbe4.com](https://support.knowbe4.com/hc/en-us/articles/115004326408-How-to-Bypass-Safe-Link-Attachment-Processing-of-ATP)
	* **Projects**
		* [unindexed](https://github.com/mroth/unindexed/blob/master/README.md)
			* The site is constantly searching for itself in Google, over and over and over, 24 hours a day. The instant it finds itself in Google search results, the site will instantaneously and irrevocably securely delete itself. Visitors can contribute to the public content of the site, these contributions will also be destroyed when the site deletes itself.
	* **Talks & Presentations**
		* [Stupid RedTeamer Tricks - Laurent Desaulniers](https://www.youtube.com/watch?v=2g_8oHM0nwA&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=11)
		* [Full Contact Recon int0x80 of Dual Core savant - Derbycon7](https://www.youtube.com/watch?v=XBqmvpzrNfs)
		* [Abusing Webhooks for Command and Control - Dimitry Snezhkov](https://www.youtube.com/watch?v=1d3QCA2cR8o&list=PLuUtcRxSUZUpv2An-RNhjuZSJ5fjY7ghe&index=12)
		* [Looping Surveillance Cameras through Live Editing - Van Albert and Banks - Defcon23](https://www.youtube.com/watch?v=RoOqznZUClI)
			* This project consists of the hardware and software necessary to hijack wired network communications. The hardware allows an attacker to splice into live network cabling without ever breaking the physical connection. This allows the traffic on the line to be passively tapped and examined. Once the attacker has gained enough knowledge about the data being sent, the device switches to an active tap topology, where data in both directions can be modified on the fly. Through our custom implementation of the network stack, we can accurately mimic the two devices across almost all OSI layers. We have developed several applications for this technology. Most notable is the editing of live video streams to produce a “camera loop,” that is, hijacking the feed from an Ethernet surveillance camera so that the same footage repeats over and over again. More advanced video transformations can be applied if necessary. This attack can be executed and activated with practically no interruption in service, and when deactivated, is completely transparent.
		* [Sniffing Sunlight - Erik Kamerling - ANYCON2017](http://www.irongeek.com/i.php?page=videos/anycon2017/102-sniffing-sunlight-erik-kamerling)
			* Laser listening devices (laser microphones) are a well understood technology. They have historically been used in the surreptitious surveillance of protected spaces. Using such a device, an attacker bounces an infrared laser off of a reflective surface, and receives the ricocheted beam with a photoreceptor. If the beam is reflected from a surface that is vibrating due to sound (voice is a typical background target), that sound is subsequently modulated into the beam and can be demodulated at the receptor. This is a known attack method and will be briefly discussed. However, does this principle also hold for non-amplified or naturally concentrated light sources? Can one retrieve modulated audio from reflected sunlight? The idea of modulating voice with sunlight was pioneered by Alexander Graham Bell in 1880 with an invention called the Photophone. A Photophone uses the audio modulation concept now used in laser microphones, but relied on a concentrated beam of sunlight rather than a laser to communicate at distance. Considering that Bell proved that intentionally concentrated sunlight can be used to modulate voice, we will explore under what natural conditions modulated audio can be found in reflected ambient light. Using off the shelf solar-cells and handmade amplifiers, Erik will demonstrate the use of the receiver side of a historic Photophone to identify instances of modulated audio in reflected light under common conditions.
		* [Red Teaming Back and Forth 5ever Fuzzynop - Derbycon4](https://www.youtube.com/watch?time_continue=6&v=FTiBwFJQg64)
		* [Advanced Red Teaming: All Your Badges Are Belong To Us - DEF CON 22 - Eric Smith and Josh Perrymon](https://www.youtube.com/watch?v=EEGxifOAk48)
		* [Operating in the Shadows Carlos Perez - Derbycon5](https://www.youtube.com/watch?v=NXTr4bomAxk)
		* [88MPH Digital tricks to bypass Physical security - ZaCon4 - Andrew MacPherson](https://vimeo.com/52865794)
		* [Attacking EvilCorp: Anatomy of a Corporate Hack](http://www.irongeek.com/i.php?page=videos/derbycon6/111-attacking-evilcorp-anatomy-of-a-corporate-hack-sean-metcalf-will-schroeder)
		* [Detect Me If You Can Ben Ten - Derbycon7](https://www.youtube.com/watch?v=AF3arWoKfKg&index=23&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
		* [Modern Evasion Techniques Jason Lang - Derbycon7](https://www.irongeek.com/i.php?page=videos/derbycon7/t110-modern-evasion-techniques-jason-lang)
			* As pentesters, we are often in need of working around security controls. In this talk, we will reveal ways that we bypass in-line network defenses, spam filters (in line and cloud based), as well as current endpoint solutions. Some techniques are old, some are new, but all work in helping to get a foothold established. Defenders: might want to come to this one.
		* [Red Team Techniques for Evading, Bypassing, and Disabling MS Advanced Threat Protection and Advanced Threat Analytics - Chris Thompson](https://www.youtube.com/watch?v=2HNuzUuVyv0&app=desktop)
		* [Slides](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
			* Windows Defender Advanced Threat Protection is now available for all Blue Teams to utilize within Windows 10 Enterprise and Server 2012/16, which includes detection of post breach tools, tactics and techniques commonly used by Red Teams, as well as behavior analytics.
	* **Keying Payloads**
		* [Context-keyed Payload Encoding](http://uninformed.org/?v=all&a=42&t=sumry)
			* A common goal of payload encoders is to evade a third-party detection mechanism which is actively observing attack traffic somewhere along the route from an attacker to their target, filtering on commonly used payload instructions. The use of a payload encoder may be easily detected and blocked as well as opening up the opportunity for the payload to be decoded for further analysis. Even so-called keyed encoders utilize easily observable, recoverable, or guessable key values in their encoding algorithm, thus making decoding on-the-fly trivial once the encoding algorithm is identified. It is feasible that an active observer may make use of the inherent functionality of the decoder stub to decode the payload of a suspected exploit in order to inspect the contents of that payload and make a control decision about the network traffic. This paper presents a new method of keying an encoder which is based entirely on contextual information that is predictable or known about the target by the attacker and constructible or recoverable by the decoder stub when executed at the target. An active observer of the attack traffic however should be unable to decode the payload due to lack of the contextual keying information.
		* [Keying Payloads for Scripting Languages](https://adapt-and-attack.com/2017/11/15/keying-payloads-for-scripting-languages/)
		* [GoGreen](https://github.com/leoloobeek/GoGreen/blob/master/README.md)
			* This project was created to bring environmental (and HTTP) keying to scripting languages. As its common place to use PowerShell/JScript/VBScript as an initial vector of code execution, as a result of phishing or lateral movement, I see value of the techniques for these languages.
* **Code Injection**
	* [injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings/)
		* Single Visual Studio project implementing multiple DLL injection techniques (actually 7 different techniques) that work both for 32 and 64 bits. Each technique has its own source code file to make it easy way to read and understand.
	* [Inject All the Things - Shut up and hack](http://blog.deniable.org/blog/2017/07/16/inject-all-the-things/)
* **Disk Encryption**
	* [attacking encrypted systems with qemu and volatility](https://diablohorn.com/2017/12/12/attacking-encrypted-systems-with-qemu-and-volatility/) 
	* [Attacking and Defending Full Disk Encryption - Tom Kopchak - BSides Cleveland2014](https://www.youtube.com/watch?v=-XLitSfOQ6U)
* **Lateral Movement**
	* **WMI**
		* [The Grammar of WMIC](https://isc.sans.edu/diary/The+Grammar+of+WMIC/2376)
		* [Abusing Windows Management Instrumentation (WMI) to Build a Persistent, Asyncronous, and Fileless Backdoor](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
		* [Creeping on Users with WMI Events: Introducing PowerLurk](https://pentestarmoury.com/2016/07/13/151/)
		* [PowerLurk](https://github.com/Sw4mpf0x/PowerLurk)
			* PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions. The goal is to make WMI events easier to fire off during a penetration test or red team engagement.
		* [Windows Security Center: Fooling WMI Consumers](https://www.opswat.com/blog/windows-security-center-fooling-wmi-consumers)
		* [CimSweep](https://github.com/PowerShellMafia/CimSweep)
			* CimSweep is a suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows. CimSweep may also be used to engage in offensive reconnaisance without the need to drop any payload to disk. Windows Management Instrumentation has been installed and its respective service running by default since Windows XP and Windows 2000 and is fully supported in the latest versions of Windows including Windows 10, Nano Server, and Server 2016.
	* **WinRM**
		* [Windows Remote Management (WinRM) for Ruby](https://github.com/WinRb/WinRM)
			* This is a SOAP library that uses the functionality in Windows Remote Management(WinRM) to call native object in Windows. This includes, but is not limited to, running batch scripts, powershell scripts and fetching WMI variables. 
* **Log Evasion/Deletion**
* **Process Unhooking**
	* [Universal Unhooking: Blinding Security Software - Jeffrey Tang](https://threatvector.cylance.com/en_us/home/universal-unhooking-blinding-security-software.html)
	* [You're Off the Hook: Blinding Security Software - Alex Matrosov, Jeff Tang](https://www.slideshare.net/cylance_inc/youre-off-the-hook-blinding-security-software)
* **Simulation**
	* [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire)
		* [Slides](https://github.com/TryCatchHCF/DumpsterFire/raw/master/CactusCon_2017_Presentation/DumpsterFire_CactusCon_2017_Slides.pdf)
		* The DumpsterFire Toolset is a modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor / alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations. Turn paper tabletop exercises into controlled "live fire" range events. Build event sequences ("narratives") to simulate realistic scenarios and generate corresponding network and filesystem artifacts.
	* [Caldera](https://github.com/mitre/caldera)
		* CALDERA is an automated adversary emulation system that performs post-compromise adversarial behavior within enterprise networks. It generates plans during operation using a planning system and a pre-configured adversary model based on the Adversarial Tactics, Techniques & Common Knowledge (ATT&CK™) project. These features allow CALDERA to dynamically operate over a set of systems using variable behavior, which better represents how human adversaries perform operations than systems that follow prescribed sequences of actions.
	* [Metta](https://github.com/uber-common/metta)
		* An information security preparedness tool to do adversarial simulation. This project uses Redis/Celery, python, and vagrant with virtualbox to do adversarial simulation. This allows you to test (mostly) your host based instrumentation but may also allow you to test any network based detection and controls depending on how you set up your vagrants. The project parses yaml files with actions and uses celery to queue these actions up and run them one at a time without interaction.
* **Powershell Scripts**
	* [Red Team Powershell Scripts - Mr-Un1k0d3r](https://github.com/Mr-Un1k0d3r/RedTeamPowershellScripts)
* **Toolmaking**
	* [An Introduction to Writing .NET Executables for Pentesters](https://www.peew.pw/blog/2017/11/24/an-introduction-to-writing-net-executables-for-pentesters)
	* [Quick Retooling in Net for Red Teams - Dimitry Snezhkov - Circle City Con 5.0](https://www.youtube.com/watch?v=C04TD4dVLSk)
		* [typhoon](https://github.com/dsnezhkov/typhoon)
	* [Windows-API-Hashing](https://github.com/LloydLabs/Windows-API-Hashing)
		* Windows API resolution via hashing
	* [WinPwnage](https://github.com/rootm0s/WinPwnage)
		* The meaning of this repo is to study the techniques. Techniques are found online, on different blogs and repos here on GitHub. I do not take credit for any of the findings, thanks to all the researchers.
* **User**
	* [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)
		* This resource contains wordlists for creating statistically likely usernames for use in username-enumeration, simulated password-attacks and other security testing tasks.
	* [cupp.py - Common User Passwords Profiler](https://github.com/Mebus/cupp)

































-----------------------
### <a name="unusual"></a> Pen Testing Specific (not-generally-encountered) Stuff
* **AIX<a name="aix"></a>
	* **General**
		* [AIX for Penetration Testers 2017 thevivi.net](https://thevivi.net/2017/03/19/aix-for-penetration-testers/)
		* [Hunting Bugs in AIX : Pentesting writeup](https://rhinosecuritylabs.com/2016/11/03/unix-nostalgia-hunting-zeroday-vulnerabilities-ibm-aix/)
		* [Penetration Testing Trends John Strand - Derbycon6](https://www.youtube.com/watch?v=QyxdUe1iMNk)
* **Embedded<a name="embedded"></a>
	* **General**
		* [War Stories on Embedded Security Pentesting IoT Building Managers and how to do Better Dr Jared - Derbycon7](https://www.youtube.com/watch?v=bnTWysHT0I4&index=8&list=PLNhlcxQZJSm-PKUZTYe1C94ymf0omysM3)
* **MainFrames** <a name="main"></a>
	* [Soldier of Fortran Tumblr](https://mainframed767.tumblr.com/)
	* [Internet Mainframe Project](https://mainframesproject.tumblr.com/)
	* **101**
		* [Introduction to z/OS and IBM mainframes world and security](https://www.whitewinterwolf.com/posts/2017/10/01/introduction-to-zos-and-ibm-mainframes-world-and-security/)
		* [mainframed767 - tumblr(Soldier of Fortran)](https://mainframed767.tumblr.com/post/43170687339/shmoocon-presentation-links?is_related_post=1)
		* [Everything you wanted to know about mainframe security, pen testing and vulnerability scanning .. But were  too afraid to ask!](http://www.newera.com/INFO/SEC_12_17_2015.pdf)
		* [Introduction to the New Mainframe z/OS Basics](https://www.redbooks.ibm.com/redbooks/pdfs/sg246366.pdf)
		* [Learning the Mainframe - Kurt's Blog](https://kurthaeusler.wordpress.com/2016/11/16/learning-the-mainframe/)
		* [So, you want your own mainframe? // Hercules z/Architecture Emulator Tutorial](https://modernmainframer.com/2017/01/30/so-you-want-your-own-mainframe-hercules-zarchitecture-emulator-tutorial/)
		* [Master the Mainframe - IBM](https://www.ibm.com/it-infrastructure/z/education/master-the-mainframe)
	* **Reference**
		* [MVS Commands](http://hansen-family.com/mvs/MVS%20Commands.htm)
		* [Command reference](https://www.redbooks.ibm.com/tips/TIPS0091/tips0091.pdf)
			* This summary lists many of the commonly used commands (with  brief descriptions) for FTP and TCP/IP, as well as related z/OS,  z/VM, VSE, Linux, and VTAM commands. 
		* [TimeShare400](http://www.timeshare400.com/products/individual-accounts/)
	* **Articles/Writeups**
		* [2017 - A New Look at Mainframe Hacking and Penetration Testing v2.2](https://www.slideshare.net/rmfeio/2017-a-new-look-at-mainframe-hacking-and-penetration-testing-v22)
			* Sequel to above link
			* [Re: PenTest for Mainframe - Seclists](http://seclists.org/basics/2012/Aug/26)
		* [Reduce Risk and Improve Security on IBM Mainframes: Volume 1 Architecture and Platform Security](https://www.redbooks.ibm.com/redbooks/pdfs/sg247803.pdf)
	* **Talks/Videos/Slides**
		* [Hacking Mainframes; Vulnerabilities in applications exposed over TN3270 - Dominic White](http://www.irongeek.com/i.php?page=videos/derbycon4/t217-hacking-mainframes-vulnerabilities-in-applications-exposed-over-tn3270-dominic-white)
			* IBM System Z Mainframes are in regular use in Fortune 500 companies. Far from being legacy these systems are running an actively maintained operating system (z/OS). Applications on these often occupy roles critical to the business processes they underpin, with much of the later technology built around them, rather than replacing them. However, these systems are often bypassed by security testing due to worried of availability or assumptions about legacy. This talk will introduce you to assessing mainframe applications, which turn out to be quite similar to web applications. For this purpose we built a tool, Big Iron Recon & Pwnage (BIRP), to assist with performing such assessments. Importantly, our research uncovered a family of mainframe application vulnerabilities introduced by the TN3270 protocol. We found numerous applications, but not all, vulnerable to these flaws. Applications running within the two most popular transaction managers (CICS and IMS) as well as one of IBM’s own applications. The tool released assists with the exploitation of these flaws.
		* [Learning Mainframe Hacking: Where the hell did all my free time go? - Chad Rikansrud - Derbycon5](https://www.irongeek.com/i.php?page=videos/derbycon5/stable31-learning-mainframe-hacking-where-the-hell-did-all-my-free-time-go-chad-rikansrud)
		* [Security Necromancy : Further Adventures in Mainframe Hacking - Phillip Young/Chad Rikansrud - Defcon23](https://www.youtube.com/watch?v=LgmqiugpVyU&feature=youtu.be)
			* [Slides](https://www.slideshare.net/bigendiansmalls/security-necromancy-publish)
		* [Smashing the Mainframe for Fun and Prison Time - Phillip Young - Hacktivity2014](https://www.youtube.com/watch?v=SjtyifWTqmc)
		* [How to Embrace Hacker Culture For z/OS | Phil Young at SHARE in Seattle2015](https://www.youtube.com/watch?v=5Ra4Ehmifh4)
		* [Hacking Mainframes Vulnerabilities in applications exposed over TN3270 - Dominic White - Derbycon4](https://www.youtube.com/watch?v=3HFiv7NvWrM)
		* [Why You Should (But Don't) Care About Mainframe Security - Northsec2015 - Phillip Young](https://www.youtube.com/watch?v=YLxvrklh2tM)
		* [Hack the Legacy: IBM I aka AS400 Revealed - Bart Kulach - Defcon23](https://www.youtube.com/watch?v=JsqUZ3xGdLc)
		* [From root to SPECIAL - Pwning IBM Mainframes - Defcon22 - Philip Young](https://www.youtube.com/watch?v=MZDIblU9pBw)
		* [Mainframed: The Secrets Inside that Black Box [Shmoocon 2013] - Philip Young](https://www.youtube.com/watch?v=KIavTQeQqSw)
		* [Mainframed - The Forgotten Fortress - Philip Young - BSidesLV2012](https://www.youtube.com/watch?v=tjYlXW2Dldc)
		* [we hacked the gibson now what - Philip Young - BSidesLV2014](https://www.youtube.com/watch?v=n_sXG0Ff2oM)
		* [Mainframes - Mopeds and Mischief; A PenTesters Year in Review](http://www.irongeek.com/i.php?page=videos/derbycon4/t203-mainframes-mopeds-and-mischief-a-pentesters-year-in-review-tyler-wrightson)
	* **Tools**
		* [The Hercules System/370, ESA/390, and z/Architecture Emulator](http://www.hercules-390.org/)
			* Hercules is an open source software implementation of the mainframe System/370 and ESA/390 architectures, in addition to the new 64-bit z/Architecture
		* [Privilege escalation on z/OS](https://github.com/ayoul3/Privesc)
			* Privilege escalation tools on Mainframe
		* [Nmap Mainframe Scripts](https://github.com/zedsec390/NMAP)
			* NMAP scripts for TN3270 interaction as well as NJE. Most notably TSO User Enumeration and Brute Force. CICS transaction ID enumeration and NJE node name brute forcing.
		* [shells-payloads - Source code for SystemZ Shells / Payloads](https://github.com/zedsec390/shells-payloads)
		* [TN3270 Python Library](https://github.com/zedsec390/tn3270lib)
			* This library is a pure python implemnation of a TN3270e emulator. To test this library you can issue the command python tn3270lib.py <hostname> <port>.
		* [REXX-tools](https://github.com/zedsec390/REXX-tools)
			* Various tools in REXX
		* [NJElib](https://github.com/zedsec390/NJElib)
			* z/OS (mainframe) Network Job Entry (NJE) python library and example scripts.
		* [Privilege escalation on z/OSINT - ayoul3 github](https://github.com/ayoul3/Privesc)
			* Some scripts to quickly escalate on z/OS given certain misconfigurations.
		* [REX_Scripts](https://github.com/ayoul3/Rexx_scripts)
			* A collection of interesting REXX scripts to ease the life a mainframe pentester
* **SAP** <a name="sap"></a>
	* **101**
		* [mySapAdventures](https://github.com/shipcod3/mySapAdventures)
			* A quick methodology on testing/hacking SAP Applications for n00bz and bug bounty hunters
	* **Articles/Papers/Talks/Writeups**
		* [Perfect SAP Penetration testing. Part 3: The Scope of Vulnerability Search](https://erpscan.com/press-center/blog/perfect-sap-penetration-testing-part-3-scope-vulnerability-search/)
		* [SAP NetWeaver ABAP security configuration part 3: Default passwords for access to the application](https://erpscan.com/press-center/blog/sap-netweaver-abap-security-configuration-part-2-default-passwords-for-access-to-the-application/)
		* [List of ABAP-transaction codes related to SAP security](https://wiki.scn.sap.com/wiki/display/Security/List+of+ABAP-transaction+codes+related+to+SAP+security)
		* [Breaking SAP Portal](https://erpscan.com/wp-content/uploads/presentations/2012-HackerHalted-Breaking-SAP-Portal.pdf)
		* [Top 10 most interesting SAP vulnerabilities and attacks](https://erpscan.com/wp-content/uploads/presentations/2012-Kuwait-InfoSecurity-Top-10-most-interesting-vulnerabilities-and-attacks-in-SAP.pdf)
		* [SAP Penetration Testing Using Metasploit](http://information.rapid7.com/rs/rapid7/images/SAP%20Penetration%20Testing%20Using%20Metasploit%20Final.pdf)
		* [Assessing the security of SAP ecosystems with bizploit: Discovery](https://www.onapsis.com/blog/assessing-security-sap-ecosystems-bizploit-discovery)
	* **Exploits**
		* [SAP_exploit](https://github.com/vah13/SAP_exploit)
			* CVE-2016-2386 SQL injection; CVE-2016-2388 Information disclosure; CVE-2016-1910 Crypto issue
	* **Tools**
		* [PowerSAP](https://github.com/airbus-seclab/powersap)
			* PowerSAP is a simple powershell re-implementation of popular & effective techniques of all public tools such as Bizploit, Metasploit auxiliary modules, or python scripts available on the Internet. This re-implementation does not contain any new or undisclosed vulnerability.
	* **Miscellaneous**
		* [pysap](https://github.com/CoreSecurity/pysap)
			* This Python library provides modules for crafting and sending packets using SAP's NI, Message Server, Router, RFC, SNC, Enqueue and Diag protocols.
* **SCADA/PLCs<a name="scada"></a>
	* **General**
		* [Industrial Control Systems : Pentesting PLCs 101 (Part 1/2)](https://www.youtube.com/watch?v=iGwm6-lyn2Y)
		* [Industrial Control Systems : Pentesting PLCs 101 (Part 2/2)](https://www.youtube.com/watch?v=rP_Jys1_OJk)
		* [Adventures in Attacking Wind Farm Control Networks - Jason Stagg](https://www.blackhat.com/docs/us-17/wednesday/us-17-Staggs-Adventures-In-Attacking-Wind-Farm-Control-Networks.pdf)
		* [Protocol Me Maybe? How to Date SCADA - Stephen Hilt](http://www.irongeek.com/i.php?page=videos/derbycon4/t124-protocol-me-maybe-how-to-date-scada-stephen-hilt)
		* [Offensive ICS Exploitation: A Description of an ICS CTF - MWR](https://labs.mwrinfosecurity.com/blog/offensive-ics-exploitation-a-technical-description/)
		* [Pen Testing a City](https://www.blackhat.com/docs/us-15/materials/us-15-Conti-Pen-Testing-A-City-wp.pdf)





------------------------
#### <a name="va"></a> Virtual Appliances
* **General**
	* [Hacking Virtual Appliances - Jeremy Brown - Derbycon2015](https://www.irongeek.com/i.php?page=videos/derbycon5/fix-me08-hacking-virtual-appliances-jeremy-brown)
		* Virtual Appliances have become very prevalent these days as virtualization is ubiquitous and hypervisors commonplace. More and more of the major vendors are providing literally virtual clones for many of their once physical-only products. Like IoT and the CAN bus, it's early in the game and vendors are late as usual. One thing that it catching these vendors off guard is the huge additional attack surface, ripe with vulnerabilities, added in the process. Also, many vendors see software appliances as an opportunity for the customer to easily evaluate the product before buying the physical one, making these editions more accessible and debuggable by utilizing features of the platform on which it runs. During this talk, I will provide real case studies for various vulnerabilities created by mistakes that many of the major players made when shipping their appliances. You'll learn how to find these bugs yourself and how the vendors went about fixing them, if at all. By the end of this talk, you should have a firm grasp of how one goes about getting remotes on these appliances.
	* [External Enumeration and Exploitation of Email and Web Security Solutions - Ben Williams](https://www.blackhat.com/docs/us-14/materials/us-14-Williams-I-Know-Your-Filtering-Policy-Better-Than-You-Do.pdf)
	* [Hacking Appliances: Ironic Exploitation Of Security Products - Ben Williams - BHEU 2013](https://www.youtube.com/watch?v=rrjSEkSwwOQ)
		* [Slides](https://www.blackhat.com/docs/webcast/07182013-Hacking-Appliances-Ironic-exploits-in-security-products.pdf)


* **Sort**
	* [PenTesting-Scripts - killswitch-GUI](https://github.com/killswitch-GUI/PenTesting-Scripts)
