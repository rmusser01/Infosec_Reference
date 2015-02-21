Anti-Forensics & Anti-Anti-Forensics – Michael Perkin
 
Techniques covered in talk
Most techniques are not sophisticated
Each can be defeated by an investigator
Goal of techniques is to add man hours and $$$
High costs increase chances of settlement
 
Typical methodologies in forensic investigations:
Copy first, ask questions later
Typical LEO
Assess relevance first, copy relevant
All types of investigators ? ME!
Remote analysis of live stream, copy targeted evidence only
Typically enterprise – private if they have help (like ME! - lol)
 
Six stages that all forensic investigators work through:
Create working copy of evidence
Process data for analysis
Separate wheat from chaff ? nice analogy
Analyze data for relevance
Prepare report on findings
Archive data for future (make sure you follow proper CoC procedures, even in archive state – chief)
 
There are several classic anti-forensic techniques:
HDD scrubbing / file wiping
Overwriting areas of disk over and over (DBAN FTW)
Encryption
TrueCrypt, et al
Physical Destruction (drive grinding FTW)
 
Examples for entertainment:
 
Attacking process step #1: Data Saturation
own a lot of media
stop throwing out devices
use each device/container regularly if possible
Investigators will need to go through everything (UGH I HATE THIS)
(Mitigating Data Saturation)
Parallelize the acquisition process (more duplicators, but assumes big budget)
Use their hardware against them
boot from a CD, plug in a USB HDD, mount – n – copy ad nauseum (he left out some detail here – write blocking, etc)
AFT #2: Non-Standard RAID
Common RAIDs share stripe patterns, block sizes, etc.
So use uncommon settings (lol)
Use uncommon hardware
Disk order, left synchronous? Right synchronous? Big Endian? Options are endless.
Mitigate problem – see Scottt Moulton's talk from DEFCON 17 (great talk btw)
De-RAID volumes on attacker's own system
use boot disks
Their hardware reassembles it for you
If RAID controller doesn't support linux, use Windows live CDs
Image Volumes, not HDDs
Attacking step #2: Screwing with processing: File Internals
Example: (JPG: FF D8 FF E0)
File sigs are identified by file headers/footers
hollow out a file, add data, tah-dah
(Personal note – this can create havoc with EnCase)
Mitigate problem
Use fuzzy hashing to identify potentially interesting files
FH identifies similar but not identical files ? FTW
Chances are, attacker picked a file from his systems
Why does this file have a 90% match with notepad.exe? ? LOL
Analyze all recent lists of common apps for curious entries
Why was rundll.dll recently opened in Wordpad?
Attacking step #3
Background: National Software Reference Library (NSRL)
Huge databases of hash values
Used by investigators
Attack: NSRL scrubbing
Modify all your system and program files
Modify a string or other part of the file
For EXEs and DLLs, recalculate and update the embedded CRCs
Turn off Data Execution Prevention (DEP) in Windows continues to run
boot.ini policy_level /noexecute=AlwaysOff
NSRL will no longer match ANYTHING ? Evil
Mitigate the attack
Search, don't filter
Identify useful files rather than eliminating useless files
Use a whitelist approach instead of a blacklist (ugh, time consuming)
(Background): Histograms
Investigators use histograms to identify which dates have higher-than-avergae activity
e.g. VPN Logins, Firewall alerts, even FileCreated times
Attacking Step #5: Scrambled MACE Times
All files store multiple timestamps
Modified – the last write
Accessed – the last read
Created – the files' birthday
Entry – the last time the MFT entry was updated
Randomize timestamp of every file
Randomize BIOS time regularly via daemon service ? I have actually seen this!
Disable LastAccess updates in registry
HKEY_LOCAL_MACHINE\system\currencontrolset\control\filesystem
set DWORD NtfsDisableLastAccessUpdate = 1


Mitigating scrambled MACE time
Ignore dates on all metadata
Look for logfiles that write dates as strings
logs are written sequentially
Order of sets of events in logs can reveal what really happened
When all timestamps are scrambled, you know to ignore the values
If all files appear normal, you will never know if a single file has been updated to appear consistent
Investigative reports typical cite time being consistent with other times. LOL
Attacking the Analyze Data step
Restricted Filenames
Even Windows 7 has holdovers from DOS: restricted filenames
CON, PRN, AUX, NUL, COM*, LPT*
Use these filenames liberally!
Access NTFS volume via UNC \\host\C$\Folder
Call Windows API function MoveFile manually from a custom app (kernel32.lib)
Circular References
Folders in folders have tpyical limit of 255 char
Junctions or Symbolic Links can point to a parent
c:\parent\child\parent\child... LOL
Store criminal data in multiple nested files/folders ? Seen this too
Tools that use HDD images don't bat an eye (FTK4, EnCase)
Many tools that recursively scan folders are affected by this attacker'sField Triage and Remote Analysis methods are affected
Mitigating Restricted Filenames
Never export files with native filenames
Always specify a different name
… (???)
Broken Log Files
Many investigators process log files with tools
These tools use string matching and REGEX
Use fun ascii characters in custom messages
Commas, quotes and pipes make parsing difficult
…
Mitigating broken log files
Do you need the log? Prove point w/o it
Parse the few records manually and document methodology
Write a small app to parse it the way you need it to be parse – (or just use Splunk people. Jeesus.)
Attacking E-mail
Use Lotus Notes! ? LMAOROTFL
NSF files and .id files are headaches
There are many tools to deal with NSFs
Pain in the ass
Most apps use IBMs own lotus notes dlls/API to work with NSF files
When opening each encrypted NSF, the API raises the password dialogue
Mitigating Lotus Notes
Just use Lotus Notes, avoid tools if possible
Dont rely on NSF conversion tools!
Attacking Reporting Phase
AF Technique #10: HASH Collisions
MD5 and SHA1 hashes are used to locate files
add dummy data to files
Try explaining why goodfile.doc and badfile.doc have same hash
could provide reasonable doubt? ? I dunno about that. Hash collisions are consuming by themselves.
Mitigating HASH Collisions
Use SHA256/Whirlpool
Doublecheck fings
Attack technique: Dummy HDD
PC with a HDD that isn't used
USB-boot and ignore the HDD for everyday use
Run dummy daemon to daily retrive and write crap to it (news, etc)
Sync mail with benign account
Execute at random intervals
Mitigating dummy HDD
Always check for USB drives
Pagefile on USB drive may point to network locations if the OS was paging of course
Monitor network traffic before seizure to detect remote drive location
Attacking the archive step
Data saturation
More data needed to be kept, higher cost for investigators
We've now come full circle :) 