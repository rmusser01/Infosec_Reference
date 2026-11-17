# Full reference-page improvement audit

Audit-start snapshot: `923f366`, compared with `af8b68e`. Audit and repair date: 2026-10-26. PR #74 remains draft. Link capture and Internet Archive submissions remain paused. Findings below describe that snapshot; each status records its repair disposition.

## Correction to the completion claim

The previous “all pages complete” claim was not supported. The branch implements broad navigation tooling and structural edits, but zero parser errors and passing preservation tests did not establish useful, finished page navigation. This audit found concrete unfinished work in migrated main pages and unchanged children, including the original pilot pages. The named navigation defects have since been repaired as recorded below. It does not claim that every resource description or factual statement has been checked.

## Scope and audit-start evidence

- All **102 reference pages** are individually accounted for: 50 managed topic pages, 3 topic landings, 45 child/reference pages, 2 homepages and 2 generated navigation pages. Fourteen additional tracked Markdown files are project/contributor documentation, outside this reader-corpus count.
- At the audit-start snapshot, **58 pages changed; 44 child/reference pages were unchanged** from the base. Unchanged does not automatically mean defective, but it contradicts interpreting the rollout as completed page-level improvement of the whole corpus.
- Resource/anchor preservation fixtures cover **50 main pages**. Every reader page received an outline/ToC and targeted-section review in this audit; long-page prose and external resource accuracy were not exhaustively reviewed.
- A fresh full-corpus parser/render census found zero internal parser errors, zero missing managed ToC targets, zero duplicate rendered IDs, and no lost explicit source anchors. The previous parser missed empty destinations; its guard now covers inline links, reference links and explicit HTML hrefs. Structural checks alone still cannot establish subject accuracy or catch every browsing omission.
- Rendered external-reference comparisons found no unexplained external resource removals. The differences are root GitHub navigation converted to local paths, corrected ATT&CK mapping links, and three sidebar standards links retained in the root README.
- The three independent page reviews recorded **33 finding groups**, with some overlap. Counts of heuristic marker/depth candidates are not presented as confirmed defects.

## Confirmed repair list

### A1: DFIR still leaves substantive subjects outside heading navigation

Affected: [Draft/DFIR.md](../Draft/DFIR.md).

ToC 6–20 exposes only broad sections. Cloud (57), Methodologies/Playbooks (142), On-Call (161), Platforms (169), Response Automation (184), and Windows artifact subjects including Registry (686) remain bold list labels with populated resource groups; none is an actual navigable heading. This is unlike the real subject-heading rollout on other main pages.

**Repair:** Promote substantive subject labels to correctly nested headings, keeping resource/format labels and bullets as appropriate; preserve existing resources/anchors.

**Status: Repaired: DFIR subjects are correctly nested headings; local ToC depth is four and seven populated subjects were added to the selective index. Covered by pilot-outline regressions and the full rendered ToC sweep.**

### A2: Bootkit Disk Forensics is presented as a child of Steganography

Affected: [Draft/DFIR.md](../Draft/DFIR.md).

Steganography is H2 at 867; unrelated Bootkit Disk Forensics is H3 at 887, reproduced as an indented ToC entry at 21. Its resources concern bootkit disk analysis, not steganography.

**Repair:** Make Bootkit Disk Forensics a peer forensic subject and regenerate ToC, retaining ref-dfir-16.

**Status: Repaired: Bootkit Disk Forensics is H2, a peer of Steganography, with ref-dfir-16 retained. Covered by the DFIR outline regression.**

### A3: Generated reader navigation still advertises empty subject placeholders

Affected: [Draft/Building_A_Lab.md](../Draft/Building_A_Lab.md), [Draft/Darknets.md](../Draft/Darknets.md), [Draft/Defense.md](../Draft/Defense.md), [Draft/Programming_Language_Security.md](../Draft/Programming_Language_Security.md), [Draft/threatmodel.md](../Draft/threatmodel.md).

Defense 90–96 contains four empty personal-action headings, and 102–114 seven more empty enterprise-action headings; all are included in the ToC. Threatmodel 38/40/48/50 advertises empty OCTAVE/PASTA/TRIKE/VAST; Building_A_Lab 120/129 empty VirtualBox/Xen; Programming_Language_Security 131 empty Application Logging & Monitoring; Darknets 58 empty Wikis. These are dead-end navigation destinations.

**Repair:** Exclude or consolidate empty placeholders in reader navigation without inventing resources, while retaining legacy anchors where needed and preserving planning notes separately.

**Status: Repaired: resource-free scaffolds were moved intact into the maintenance backlog; their stable and automatic fragments remain as aliases. No resources were invented.**

### A4: Selective subject index includes editorial categories as subjects

Affected: [Draft/Subject_Index.md](../Draft/Subject_Index.md).

Index entry Acknowledgements (23) points to REMath credits; Unsorted references (880) points to its unclassified bucket. Source targets at REMath 555 and 469 confirm their editorial role. Neither is an evidence-based subject for an alphabetical subject index.

**Repair:** Remove these subjects from navigation/topics.json selection; keep their page content/anchors and local ToC access.

**Status: Repaired: Acknowledgements and Unsorted references are excluded from selected subjects; their source content and local navigation remain.**

### A5: Execution labels signed-script technique as binary proxy execution

Affected: [Draft/ATT&CK-Stuff/ATT&CK/Execution.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Execution.md).

Second H2 Signed Binary Proxy Execution (369) actually links Signed Script Proxy Execution T1216 and discusses PubPrn.vbs. First Binary section at 352 covers T1218. Duplicate headings obscure two distinct techniques.

**Repair:** Rename second heading to Signed Script Proxy Execution and preserve old fragment compatibility where practical.

**Status: Repaired: the second technique is Signed Script Proxy Execution; the old binary-proxy suffix fragment remains compatible.**

### A6: Priority-definition child retains empty template headings and unrelated C2 section

Affected: [Draft/ATT&CK-Stuff/Pre-ATT&CK/Priority_Definition_Directive.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Priority_Definition_Directive.md).

Three literal empty H2 headings at 53, 57, 60 are followed at 66 by Commonly Used Port/T1043 and firewall/C2 description. This is unrelated to priority intelligence requirements and duplicates Command_and_Control Commonly Used Port resources.

**Repair:** Remove empty heading scaffolding and move/consolidate misplaced resources into their correct subject while preserving URLs and useful anchors.

**Status: Repaired: empty headings are removed, their meaningful aliases remain, and the two misplaced URL occurrences are moved to the existing C2 Commonly Used Port subject.**

### A7: Initial Access resources retain copied labels for different techniques

Affected: [Draft/ATT&CK-Stuff/ATT&CK/Initial_Access.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Initial_Access.md).

Hardware Additions H2 at 20 contains a Drive-by-Compromise label for T1200 (21). Spearphishing via Service at 41 also labels its T1194 resource Drive-by-Compromise (42). The heading and resource title disagree without needing a live-link check.

**Repair:** Correct these resource labels to their actual local section subjects; retain URLs.

**Status: Repaired: Hardware Additions and Spearphishing via Service resource labels now agree with their local sections; URLs are unchanged.**

### A8: Metasploit child has undiscoverable plain-text subjects and malformed resource link

Affected: [Draft/Cheat sheets reference pages Checklists -/metasploit.md](../Draft/Cheat%20sheets%20reference%20pages%20Checklists%20-/metasploit.md).

Writing Modules is plain prose at 21, alongside Cheat Sheet/General/Articles labels inside one General section, so subject navigation cannot expose them. Exploits - Linux at 49 is written [Exploits - Linux])https://... instead of Markdown link syntax, leaving a resource without usable link treatment.

**Repair:** Use real child subject headings with resource bullets and repair malformed Linux resource Markdown without changing its destination.

**Status: Repaired: Metasploit child subjects are real headings with a managed ToC, and the Linux resource is a working Markdown link to its original URL.**

### A9: Papers and software/hardware projects are nested under Talks/Videos

Affected: [Draft/Interesting_Things.md](../Draft/Interesting_Things.md).

Interesting Talks/Videos is H2 at 262. Interesting Papers (364), Interesting Software Projects (371), Interesting Hardware Projects (376) are H3 and therefore appear as children of Talks/Videos in generated ToC despite their resources being papers, GitHub projects and hardware resources.

**Repair:** Promote these resource-type sections to appropriate peers (or use a broader accurate parent) and regenerate ToC, preserving fragments.

**Status: Repaired: Papers, Software Projects and Hardware Projects are H2 peers of Talks/Videos, with legacy fragments retained.**

### A10: Windows reader content still contains an inline maintenance FIXME

Affected: [Draft/PrivEscPostExWin.md](../Draft/PrivEscPostExWin.md).

Within Un-Hooking, reader-facing label is Techniques(too lazy to actually sort these right now - FIXME) at 5563. This is an author task note mixed directly into the resource hierarchy. The ToC also exposes speculative label Zombify - herpaderping? at 7769.

**Repair:** Keep maintenance uncertainty in a separate note and give the reader-facing group a factual subject label supported by its existing resources.

**Status: Repaired: reader labels are Techniques and ZombifyProcess; the original author uncertainty is retained separately in the maintenance backlog.**

### B01: Replace the still-empty manual tables of contents

Affected: [Draft/ATT&CK-Stuff/Pre-ATT&CK/Build_Capabilities.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Build_Capabilities.md), [Draft/ATT&CK-Stuff/Pre-ATT&CK/Technical_Information_Gathering.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Technical_Information_Gathering.md), [Draft/ATT&CK-Stuff/Pre-ATT&CK/Technical_Weakness_Identification.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Technical_Weakness_Identification.md), [Draft/Policy_Compliance.md](../Draft/Policy_Compliance.md), [Draft/SCA.md](../Draft/SCA.md).

Build Capabilities, Technical Information Gathering, and Technical Weakness Identification retain lists of []() instead of any destination; the latter also ends with an empty ### heading and a [- Pre-ATT&CK]()() resource at 94-96. Policy & Compliance retains four []() entries. Side-Channel Attacks advertises a Table of Contents with no entries. These are actual topic pages/children, distinct from help.md (an author template), and none was editorially completed by adding the new directory landings.

**Repair:** Replace each placeholder ToC with real source-derived subjects (or remove an unnecessary ToC), preserve existing technique anchors, remove or segregate the empty author scaffold. No new resources needed.

**Status: Repaired: blank child ToCs are source-generated; the unnecessary SCA ToC is removed with its old fragment retained. The trailing empty author scaffold is fenced as an example.**

### B02: Do not advertise template-only sections as useful navigation destinations

Affected: [Draft/Active_Directory.md](../Draft/Active_Directory.md), [Draft/Courses_Training.md](../Draft/Courses_Training.md), [Draft/Docs_and_Reports.md](../Draft/Docs_and_Reports.md), [Draft/Embedded.md](../Draft/Embedded.md), [Draft/Games.md](../Draft/Games.md), [Draft/Phishing.md](../Draft/Phishing.md), [Draft/Rootkits.md](../Draft/Rootkits.md), [Draft/Web.md](../Draft/Web.md), [Draft/bios_uefi.md](../Draft/bios_uefi.md), [Draft/sysinternals.md](../Draft/sysinternals.md).

Source review finds 83 resource-free leaf headings across ten migrated pages when empty bold template labels are ignored. Embedded alone contributes 44 (e.g. Flash Memory General/Tools/Miscellaneous, Smart TVs 101/General/Tools/Miscellaneous, SPI and SD-card scaffolds). Eleven such destinations are selected as alphabetical subjects: AD LDAP/Abusing ACEs/Across Trusts; Games NES/SNES/WiiU/PS2/PS3; Phishing UNC; sysinternals File Systems/Processes. They lead to blank or template-only content. Full exact inventory is in empty_leaf_inventory. LDAP and WiiU are also hierarchy defects, discussed separately.

**Repair:** Keep useful content and stable aliases, but remove empty scaffold from reader headings/ToCs/index or point it at the existing relevant content. Keep author planning separately. Do not invent resources to fill it.

**Status: Repaired: the confirmed empty blocks are excluded from reader headings and selected subjects. Across the repair pass, 195 headings in 186 resource-free blocks are preserved in the maintenance backlog, with compatibility aliases retained in source.**

### B03: Restore the LDAP parent/child hierarchy

Affected: [Draft/Active_Directory.md](../Draft/Active_Directory.md).

LDAP, its 101 introduction, LDAP Recon, LDAP Relaying, and Request Signing are all H3 siblings. The generated ToC consequently shows a bare 101 as a peer technology and the LDAP destination itself has no content. In the base, 101/Recon/Relaying/Request Signing were nested list subjects within LDAP. General and C2 also remain partially indented bold list labels at 488/494, so the introductory resources appear inconsistently grouped.

**Repair:** Keep LDAP as H3 and its actual subsubjects as H4, preserving every existing explicit anchor; consistently group General/C2 without turning resource entries into headings; regenerate navigation.

**Status: Repaired: LDAP children are H4 under LDAP H3. The LDAP ancestry regression passes.**

### B04: Keep Kerberos attacks out of the Delegation and Relaying subtrees

Affected: [Draft/Active_Directory.md](../Draft/Active_Directory.md).

Delegation is H3, and Encryption Downgrade, FAST, Kerberoasting, Krbtgt, noPAC, and Relaying Kerberos remain H4 until Lateral Movement. They therefore render as delegation subtopics. Silver/Gold/Diamond/Saphire Tickets are H5 beneath Relaying Kerberos, while the intended Tickets parent is merely a bold bullet at 1619. This encodes false subject relationships and hides techniques behind the wrong parent in both source headings and generated navigation.

**Repair:** Create a consistent Kerberos techniques hierarchy with Delegation and Tickets at their proper levels; keep stable anchors and source resources.

**Status: Repaired: Kerberos attacks are peers; Delegation children and Ticket variants have distinct parents. The Kerberos ancestry regression passes.**

### B05: Finish AD subject conversion where unrelated topics still run into one heading

Affected: [Draft/Active_Directory.md](../Draft/Active_Directory.md).

PrivExchange and Shadow Credentials remain bold list markers inside the PKINITMustiness section; SharePoint (Attacking) remains a bold marker inside Volume Shadow Service (Attacking); SQL Server (Attacking) is a bold marker inside Skeleton Key Attack. The resources themselves clearly identify these separate subjects. They are absent as local navigable topics and get attributed to the preceding unrelated heading. This is beyond a selective alphabetical index choice: the page outline itself is incomplete.

**Repair:** Promote only these genuine subject labels to the appropriate peer headings, keeping resources as bullets and retaining URLs/aliases.

**Status: Repaired: the four named subjects are headings under their appropriate parents. Review also caught and corrected ADAPE-Script placement: the broad tool remains under direct Privilege Escalation content, outside Shadow Credentials.**

### B06: Separate the remaining Web maintenance backlog from reader content

Affected: [Draft/Web.md](../Draft/Web.md).

After Bug Bounty Writeups, the page still contains ToDo links and a 120-line fenced resource backlog (XSS, cookies, DOM, XSSI, XS-Leaks, XS-Search, XXE). It is not an executable code example. In a rendered reference these are code text, not normal clickable resource entries or separate maintenance notes, and the subject structure is not navigable. The nearby real XSS/XML sections make the existing intended placement evident without researching new material.

**Repair:** Move the backlog intact to an explicit maintenance document/section with a reader-visible link or integrate only the already identified subjects; preserve every URL and label it honestly as pending work.

**Status: Repaired: all 108 URL occurrences in the fenced backlog are clickable in an explicitly pending resource section with named subject headings. Only the two mistaken Web URL-backlog code-block fixture entries were removed; raw URL, parsed-resource, anchor and real code-example preservation checks remain enforced.**

### B07: Use reader titles rather than corrupted filenames in the generated Pre-ATT&CK landing

Affected: [Draft/ATT&CK-Stuff/Pre-ATT&CK/README.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/README.md).

The new landing displays # Establish & Maintain Infrastructure, Organizationa  Information Gathering, and Priority Definition  lanning. These are filename artifacts, not intended titles. The linked priority-planning page H1 is Priority Definition Planning, and the parent ATT&CK mappings landing already uses readable labels (lines 9 and 14). Paths need not change to repair the presentation.

**Repair:** Provide explicit display titles while preserving the existing encoded paths; correct the generator input/output together.

**Status: Repaired: Pre-ATT&CK landing labels use readable titles while keeping the encoded filenames and paths.**

### B08: Correct the misleading JS Frameworks subject label

Affected: [Draft/Web.md](../Draft/Web.md).

JS Frameworks contains Django, Groovy, H2, phpMyAdmin, Ruby-on-Rails, Spring/Springboot, Symfony, and Wordpress as H4 children alongside Angular/React. The existing resource titles themselves identify the disparate technologies; the new ToC repeats the misleading parent relation. This is a source-supported label/hierarchy cleanup, not a request to recategorize all Web resources.

**Repair:** At minimum rename the parent to accurately describe the existing mixed set while retaining the old anchor; moving just the obviously language-specific groups under existing appropriate headings is another bounded option.

**Status: Repaired: the reader label is Web Frameworks and Applications; ref-web-83, jsframeworks and js-frameworks remain compatible.**

### B09: Normalize the legacy ATT&CK Discovery outline

Affected: [Draft/ATT&CK-Stuff/ATT&CK/Discovery.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Discovery.md).

File and Directory Discovery and Network Service Scanning are H3 beneath the immediately preceding H2 Browser Bookmark Discovery, although each links to its own distinct MITRE technique. Other techniques in the same page are H2. Remote System Discovery also contains two consecutive Windows H4 blocks. This is incoherent reader navigation in an actual tactic child, regardless of whether it was migrated.

**Repair:** Make peer discovery techniques the same heading level and combine/label the two Windows blocks while preserving their existing automatic fragment aliases.

**Status: Repaired: Discovery techniques are H2 peers; duplicated Windows groups are consolidated while retaining old suffixed fragments and citation occurrences.**

### B10: Consolidate duplicate technique sections in the legacy privilege-escalation child

Affected: [Draft/ATT&CK-Stuff/ATT&CK/Privilege_Escalation.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Privilege_Escalation.md).

Plist Modification appears twice as H2 with the same T1150 reference and near-identical description; SID-History Injection likewise appears twice as H2 with the same T1178 description, with Windows resources only in the second copy. A reader cannot tell why these are separate subjects, and navigation produces numbered duplicate fragments rather than a deliberate subject distinction. The Scheduled Tasks tail at 414 is also visibly truncated into the next separator.

**Repair:** Consolidate the matching technique content once, preserving every unique resource and both historical fragment aliases; fix or explicitly segregate the truncated resource line without inventing its URL.

**Status: Repaired: duplicated Plist and SID-History sections are consolidated, legacy aliases and repeated citations are retained, and the Scheduled Tasks label is repaired using its already recorded URL.**

### B11: Keep the Wii U article under the Wii U subject

Affected: [Draft/Games.md](../Draft/Games.md).

Nintendo WiiU is H3 with only empty Emulators/Firmware/Homebrew bullets. Articles/Writeups is another H3, and its sole Anatomy of a Wii U article is therefore a sibling of all consoles. The ToC repeats this stray generic console-level entry. WiiU is also selected in the subject index despite leading to the empty shell.

**Repair:** Nest the article grouping under Nintendo WiiU (or make the resource a direct Wii U bullet); remove empty planning labels from reader navigation and preserve explicit IDs.

**Status: Repaired: the article group is H4 under WiiU H3. Covered by the AD/Games outline regression.**

### B12: Make existing cross-page pointers usable links

Affected: [Draft/Embedded.md](../Draft/Embedded.md), [Draft/RE.md](../Draft/RE.md).

Hardware Reverse Engineering contains only See Embedded Devices & Hardware Hacking; Firmware 101 says Check the BIOS/UEFI page and Check out the RE page; Printers says See Printers Section in Network Attacks & Scanning. All are plain text instead of links, and some use titles different from the actual navigation. These are dead ends for readers following an otherwise real subject index/ToC destination.

**Repair:** Turn the named existing page/subject references into verified relative Markdown links, retaining the original pointer text where useful.

**Status: Repaired: the existing BIOS/UEFI, RE, Embedded and printer pointers are relative Markdown links; targets resolve in the navigation regression.**

### B13: Move the wireless-keyboard tool out of Cable Modem tools

Affected: [Draft/Embedded.md](../Draft/Embedded.md).

The entire Cable Modem Hacking / Tools section consists of Keykeriki v2.0, whose checked-in description is Hardware to attack wireless keyboards and other such things. The source itself shows this is misfiled; generating a Tools destination under Cable Modem reinforces the error.

**Repair:** Move the existing resource to an appropriate existing wireless/hardware context (or clearly identified unsorted resources) without changing its URL or description; avoid advertising an empty Cable Modem Tools section afterward.

**Status: Repaired: Keykeriki is in Unsorted resources, outside Cable Modem. The resource-placement regression passes.**

### C1: Subject index sends CAPTCHA readers to an empty duplicate rather than existing resources

Affected: [Draft/Passwords.md](../Draft/Passwords.md), [Draft/Subject_Index.md](../Draft/Subject_Index.md), [navigation/topics.json](../navigation/topics.json).

CAPTCHA selects ref-passwords-7. The selected CAPTCHA heading is empty; the next heading is Default Credentials. The second CAPTCHA section ref-passwords-19 contains a talk and CAPTCHA22 tool. Generated alphabetical subject entry points to the empty first CAPTCHA section.

**Repair:** Select ref-passwords-19 and keep any legacy anchors while consolidating or suppressing the empty duplicate.

**Status: Repaired: the selected CAPTCHA destination points to populated ref-passwords-19. Empty duplicate aliases remain at that populated destination.**

### C2: The new Rants landing page does not expose the nested Writeups pages

Affected: [Draft/Exploit_Dev.md](../Draft/Exploit_Dev.md), [Draft/Rants&Writeups/README.md](../Draft/Rants%26Writeups/README.md), [Draft/Rants&Writeups/Writeups/Empire_and_Metasploit_101.md](../Draft/Rants%26Writeups/Writeups/Empire_and_Metasploit_101.md), [Draft/Rants&Writeups/Writeups/Lab_for_exploit_dev-basic.md](../Draft/Rants%26Writeups/Writeups/Lab_for_exploit_dev-basic.md).

Lists only the four immediate Markdown files; no Writeups directory or its children. 161-line tutorial exists but no Markdown navigation entry in this repository points to it. 49-line lab exists but is omitted from the Rants landing. Lab is discoverable only through an absolute GitHub resource link in Exploit Development; the sibling Empire tutorial is only in the generated search-path list, not browsing navigation.

**Repair:** Add a small Writeups group or a child landing link that exposes both existing files.

**Status: Repaired: the Rants landing exposes both nested writeups with their existing paths; no writeup text was rewritten.**

### C3: Five Pre-ATT&CK child pages still present blank, nonfunctional tables of contents

Affected: [Draft/ATT&CK-Stuff/Pre-ATT&CK/# Establish & Maintain Infrastructure.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/%23%20Establish%20%26%20Maintain%20Infrastructure.md), [Draft/ATT&CK-Stuff/Pre-ATT&CK/Adversary_OPSEC.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Adversary_OPSEC.md), [Draft/ATT&CK-Stuff/Pre-ATT&CK/Organizationa_ Information_Gathering.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Organizationa_%20Information_Gathering.md), [Draft/ATT&CK-Stuff/Pre-ATT&CK/Organizational_Weakness.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Organizational_Weakness.md), [Draft/ATT&CK-Stuff/Pre-ATT&CK/People_Information_Gathering.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/People_Information_Gathering.md).

Table of Contents contains 12 - []() entries despite 16 subject sections. Table of Contents contains 13 - []() entries. Table of Contents contains 14 - []() entries. Table of Contents contains 15 - []() entries. Table of Contents contains 9 - []() entries.

**Repair:** Generate these existing ToCs from their current headings, or remove empty placeholders while retaining actual content and anchors.

**Status: Repaired: all eight blank Pre-ATT&CK ToCs are managed. Two cross-renderer automatic-fragment differences are covered by explicit aliases and the expanded all-managed-ToC renderer regression.**

### C4: Exploit writeups acquire a misleading Temporal Return Address and MIPS hierarchy

Affected: [Draft/Exploit_Dev.md](../Draft/Exploit_Dev.md).

Temporal Return Address is an H2. Unsorted writeups is H3 under Temporal Return Address. iOS is another H3 under Temporal Return Address. MIPS is H3 and spans unrelated Flash, Windows kernel, IE11 and Objective-C resources through line 995. ROP writeups, UAF writeups and Extended: *alloc/Heap remain H3 children of Temporal Return Address.

**Repair:** Put these collections under an appropriately broad parent, make their hierarchy parallel to relevant existing subjects, and end MIPS grouping after the matching MIPS resource.

**Status: Repaired: Exploit writeups has its own broad parent; temporal and MIPS sections retain their matching resources, with unrelated existing resources moved to Unsorted writeups. URL occurrences and legacy fragments are preserved.**

### C5: Cloud logging conversion leaves provider names as list items outside the heading hierarchy

Affected: [Draft/L-SM-TH.md](../Draft/L-SM-TH.md).

AWS is - **AWS**, followed by H4 Logging at line 1132. Azure is - **Azure**, followed by H4 Logging at line 1145. At configured ToC depth 3 the Cloud-based entry has no AWS/Azure children. Monitoring, Detection Engineering and Threat Hunting are indented beneath 101 instead of being peer categories; actual CloudTrail hunting material sits in Logging.

**Repair:** Make provider names the H3 subjects (preserving awslog/azurelog anchors) and retain only useful resource/type labels beneath them; avoid publishing the empty category skeleton as content.

**Status: Repaired: AWS is a navigable H3 subject; empty Azure scaffolding is retained in maintenance rather than advertised to readers, with old provider aliases preserved.**

### C6: Additional selected index subjects are entirely empty placeholders

Affected: [Draft/CandE.md](../Draft/CandE.md), [Draft/Crypto_Encrypt.md](../Draft/Crypto_Encrypt.md), [Draft/L-SM-TH.md](../Draft/L-SM-TH.md), [Draft/PrivescPostExmac.md](../Draft/PrivescPostExmac.md), [Draft/Reverse Engineering - REMath Literature.md](../Draft/Reverse%20Engineering%20-%20REMath%20Literature.md), [navigation/topics.json](../navigation/topics.json).

Splunk is the last heading with no resources before EOF, but is selected at navigation/topics.json:2506 and Subject_Index.md:834. macOS Code Injection and every child heading through line 679 are empty, but selected at navigation/topics.json:3412 and Subject_Index.md:542. Monero and Zcash headings at 437 and 439 are empty yet both selected. Additional References Monero and Zcash headings at 452 and 454 are also empty yet both selected. Binary Manipulation Frameworks, Cryptography (543), and Anti-Debugging / Anti-Reversing (553) are empty leaf sections yet all selected.

**Repair:** Exclude empty leaf sections or empty entire section trees from selected subjects, preserving their source anchors if needed; do not invent new research to fill them. CAPTCHA has a stronger existing-target repair and is reported separately as C1.

**Status: Repaired: the confirmed empty selected subjects are removed from the index and reader headings; their aliases and original scaffold text remain available.**

### C7: ELK Stack has been flattened into empty sibling navigation

Affected: [Draft/L-SM-TH.md](../Draft/L-SM-TH.md).

ELK Stack is H3 immediately followed by H3 101 at 2613. Elasticsearch, Logstash (2647) and Kibana (2655) are also H3 siblings. Generated ToC displays ELK Stack, 101, Elasticsearch, LogStash and Kibana at identical indentation.

**Repair:** Restore the ELK parent/child relationship for introduction and component headings, retaining explicit legacy anchors.

**Status: Repaired: the ELK introduction and components are H4 children of ELK H3; local ToC depth is four. Covered by the logging ancestry regression.**

### C8: REMATH subject selection includes housekeeping and format labels as alphabetical subjects

Affected: [Draft/Subject_Index.md](../Draft/Subject_Index.md), [navigation/topics.json](../navigation/topics.json).

Acknowledgements is selected with fragment ref-remath-46. Unsorted references is selected with fragment ref-remath-33. Videos is selected with fragment ref-remath-21. Acknowledgements appears as a global alphabetical subject. Unsorted references appears as a global alphabetical subject.

**Repair:** Keep substantive REMATH subjects selected and remove housekeeping/type headings from subjects; they may remain in its local ToC.

**Status: Repaired: Acknowledgements, Unsorted references and Videos are excluded from the selective subject index; source content is retained.**

### C9: Wireless maintenance instructions remain mixed into reader resources

Affected: [Draft/Wireless.md](../Draft/Wireless.md).

Unsorted resources begins with Fix ToC, Add 101 stuff, Add SMS Standards/related, followed by actual URLs. Unsorted resources is exposed in generated reader ToC.

**Repair:** Keep resource URLs in Unsorted resources and move the three instructions into a separate maintenance note block excluded from reader navigation.

**Status: Repaired: the three Wireless author tasks are retained in the maintenance backlog; resource URLs remain in Unsorted resources.**

### C10: Network ToC exposes duplicate Pivoting and Vendor Specific Stuff destinations

Affected: [Draft/Network_Attacks.md](../Draft/Network_Attacks.md).

Pivoting with legacy pivot anchor appears first, followed by Vendor Specific Stuff at 1073. Duplicate Pivoting appears again followed by duplicate Vendor Specific Stuff at 1588. The first Cisco group has additional ACI, Smart Install and SD-WAN references not present in the later duplicated Cisco group.

**Repair:** Consolidate each duplicate subject without deleting unique resource URLs and preserve legacy anchors at the resulting destination.

**Status: Repaired: one Pivoting and one Vendor Specific Stuff heading remain, retaining both former stable IDs and automatic fragments. All duplicated citation occurrences and unique vendor resources remain.**

## Coverage matrix

“Reviewed” below means outline, ToC and targeted sections inspected, with the per-page depth recorded in the review reports. It is not a full prose/factual sign-off. “No specific finding” means no concrete issue identified in that bounded review, not proof of completeness.

| Page | Treatment at audit start | Preservation fixture | Confirmed finding groups | Repair pass source edit |
|---|---|---|---|---|
| [README.md](../README.md) | Changed; home | No | No specific finding | No; reviewed |
| [Draft/_sidebar.md](../Draft/_sidebar.md) | Changed; generated navigation | No | No specific finding | No; reviewed |
| [Draft/Active_Directory.md](../Draft/Active_Directory.md) | Changed; managed topic | Yes | B02, B03, B04, B05 | Yes |
| [Draft/AnonOpSecPrivacy.md](../Draft/AnonOpSecPrivacy.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/Archiving.md](../Draft/Archiving.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/ATT&CK/Collection.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Collection.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/ATT&CK/Command_and_Control.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Command_and_Control.md) | Unchanged; child/reference page | No | No specific finding | Yes |
| [Draft/ATT&CK-Stuff/ATT&CK/Credential_Access.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Credential_Access.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/ATT&CK/Defense_Evasion.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Defense_Evasion.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/ATT&CK/Discovery.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Discovery.md) | Unchanged; child/reference page | No | B09 | Yes |
| [Draft/ATT&CK-Stuff/ATT&CK/Execution.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Execution.md) | Unchanged; child/reference page | No | A5 | Yes |
| [Draft/ATT&CK-Stuff/ATT&CK/Exfiltration.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Exfiltration.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/ATT&CK/Initial_Access.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Initial_Access.md) | Unchanged; child/reference page | No | A7 | Yes |
| [Draft/ATT&CK-Stuff/ATT&CK/Lateral Movement.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Lateral%20Movement.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/ATT&CK/Persistence.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Persistence.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/ATT&CK/Privilege_Escalation.md](../Draft/ATT%26CK-Stuff/ATT%26CK/Privilege_Escalation.md) | Unchanged; child/reference page | No | B10 | Yes |
| [Draft/ATT&CK-Stuff/ATT&CK/README.md](../Draft/ATT%26CK-Stuff/ATT%26CK/README.md) | Changed; topic landing | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/# Establish & Maintain Infrastructure.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/%23%20Establish%20%26%20Maintain%20Infrastructure.md) | Unchanged; child/reference page | No | C3 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Adversary_OPSEC.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Adversary_OPSEC.md) | Unchanged; child/reference page | No | C3 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Build_Capabilities.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Build_Capabilities.md) | Unchanged; child/reference page | No | B01 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Organizationa_ Information_Gathering.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Organizationa_%20Information_Gathering.md) | Unchanged; child/reference page | No | C3 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Organizational_Weakness.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Organizational_Weakness.md) | Unchanged; child/reference page | No | C3 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/People_Information_Gathering.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/People_Information_Gathering.md) | Unchanged; child/reference page | No | C3 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/People_Weakness_Identification.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/People_Weakness_Identification.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Persona_Development.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Persona_Development.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Priority_Definition _lanning.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Priority_Definition%20_lanning.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Priority_Definition_Directive.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Priority_Definition_Directive.md) | Unchanged; child/reference page | No | A6 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/README.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/README.md) | Changed; topic landing | No | B07 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Stage_Capabilities.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Stage_Capabilities.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Target_Selection.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Target_Selection.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Technical_Information_Gathering.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Technical_Information_Gathering.md) | Unchanged; child/reference page | No | B01 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Technical_Weakness_Identification.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Technical_Weakness_Identification.md) | Unchanged; child/reference page | No | B01 | Yes |
| [Draft/ATT&CK-Stuff/Pre-ATT&CK/Test_Capabilities.md](../Draft/ATT%26CK-Stuff/Pre-ATT%26CK/Test_Capabilities.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/ATT&CK-Stuff/README.md](../Draft/ATT%26CK-Stuff/README.md) | Changed; child/reference page | No | No specific finding | No; reviewed |
| [Draft/Basic.md](../Draft/Basic.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/bios_uefi.md](../Draft/bios_uefi.md) | Changed; managed topic | Yes | B02 | Yes |
| [Draft/Building_A_Lab.md](../Draft/Building_A_Lab.md) | Changed; managed topic | Yes | A3 | Yes |
| [Draft/CandE.md](../Draft/CandE.md) | Changed; managed topic | Yes | C6 | Yes |
| [Draft/Career.md](../Draft/Career.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Cars.md](../Draft/Cars.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Cheat sheets reference pages Checklists -/list_of_emoji.md](../Draft/Cheat%20sheets%20reference%20pages%20Checklists%20-/list_of_emoji.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/Cheat sheets reference pages Checklists -/metasploit.md](../Draft/Cheat%20sheets%20reference%20pages%20Checklists%20-/metasploit.md) | Unchanged; child/reference page | No | A8 | Yes |
| [Draft/Cheat sheets reference pages Checklists -/Nmap Cheat Sheet.md](../Draft/Cheat%20sheets%20reference%20pages%20Checklists%20-/Nmap%20Cheat%20Sheet.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/Cheat sheets reference pages Checklists -/Radare2.md](../Draft/Cheat%20sheets%20reference%20pages%20Checklists%20-/Radare2.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/Cheats.md](../Draft/Cheats.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Cloud.md](../Draft/Cloud.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Conferences.md](../Draft/Conferences.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Containers.md](../Draft/Containers.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/Courses_Training.md](../Draft/Courses_Training.md) | Changed; managed topic | Yes | B02 | Yes |
| [Draft/Crypto_Encrypt.md](../Draft/Crypto_Encrypt.md) | Changed; managed topic | Yes | C6 | Yes |
| [Draft/CTFs_Wargames.md](../Draft/CTFs_Wargames.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Darknets.md](../Draft/Darknets.md) | Changed; managed topic | Yes | A3 | Yes |
| [Draft/DataVis.md](../Draft/DataVis.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Defense.md](../Draft/Defense.md) | Changed; managed topic | Yes | A3 | Yes |
| [Draft/DFIR.md](../Draft/DFIR.md) | Changed; managed topic | Yes | A1, A2 | Yes |
| [Draft/Docs_and_Reports.md](../Draft/Docs_and_Reports.md) | Changed; managed topic | Yes | B02 | Yes |
| [Draft/Embedded.md](../Draft/Embedded.md) | Changed; managed topic | Yes | B02, B12, B13 | Yes |
| [Draft/Exfiltration.md](../Draft/Exfiltration.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Exploit_Dev.md](../Draft/Exploit_Dev.md) | Changed; managed topic | Yes | C2, C4 | Yes |
| [Draft/Fuzzing.md](../Draft/Fuzzing.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/Games.md](../Draft/Games.md) | Changed; managed topic | Yes | B02, B11 | Yes |
| [Draft/help.md](../Draft/help.md) | Unchanged; child/reference page | No | No specific finding | Yes |
| [Draft/honeypot.md](../Draft/honeypot.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/index.md](../Draft/index.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/Interesting_Things.md](../Draft/Interesting_Things.md) | Changed; managed topic | Yes | A9 | Yes |
| [Draft/L-SM-TH.md](../Draft/L-SM-TH.md) | Changed; managed topic | Yes | C5, C6, C7 | Yes |
| [Draft/Malware.md](../Draft/Malware.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/Network_Attacks.md](../Draft/Network_Attacks.md) | Changed; managed topic | Yes | C10 | Yes |
| [Draft/Osint.md](../Draft/Osint.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/Passwords.md](../Draft/Passwords.md) | Changed; managed topic | Yes | C1 | Yes |
| [Draft/Phishing.md](../Draft/Phishing.md) | Changed; managed topic | Yes | B02 | Yes |
| [Draft/Physical_Security.md](../Draft/Physical_Security.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Policy_Compliance.md](../Draft/Policy_Compliance.md) | Unchanged; child/reference page | No | B01 | Yes |
| [Draft/Port_List.md](../Draft/Port_List.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/PrivescPostEx.md](../Draft/PrivescPostEx.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/PrivescPostExLin.md](../Draft/PrivescPostExLin.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/PrivescPostExmac.md](../Draft/PrivescPostExmac.md) | Changed; managed topic | Yes | C6 | Yes |
| [Draft/PrivEscPostExWin.md](../Draft/PrivEscPostExWin.md) | Changed; managed topic | Yes | A10 | Yes |
| [Draft/Programming_Language_Security.md](../Draft/Programming_Language_Security.md) | Changed; managed topic | Yes | A3 | Yes |
| [Draft/Rants&Writeups/Bitcoin_Hack.md](../Draft/Rants%26Writeups/Bitcoin_Hack.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/Rants&Writeups/Hacking Team Writeup.md](../Draft/Rants%26Writeups/Hacking%20Team%20Writeup.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/Rants&Writeups/Opsec_rant-alpraking.md](../Draft/Rants%26Writeups/Opsec_rant-alpraking.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/Rants&Writeups/Opsec_rant2-nachash.md](../Draft/Rants%26Writeups/Opsec_rant2-nachash.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/Rants&Writeups/README.md](../Draft/Rants%26Writeups/README.md) | Changed; topic landing | No | C2 | Yes |
| [Draft/Rants&Writeups/Writeups/Empire_and_Metasploit_101.md](../Draft/Rants%26Writeups/Writeups/Empire_and_Metasploit_101.md) | Unchanged; child/reference page | No | C2 | No; reviewed |
| [Draft/Rants&Writeups/Writeups/Lab_for_exploit_dev-basic.md](../Draft/Rants%26Writeups/Writeups/Lab_for_exploit_dev-basic.md) | Unchanged; child/reference page | No | C2 | No; reviewed |
| [Draft/Rants&Writeups/Writeups/Maps-Models-Martial_Arts.md](../Draft/Rants%26Writeups/Writeups/Maps-Models-Martial_Arts.md) | Unchanged; child/reference page | No | No specific finding | No; reviewed |
| [Draft/RE.md](../Draft/RE.md) | Changed; managed topic | Yes | B12 | Yes |
| [Draft/README.md](../Draft/README.md) | Changed; home | No | No specific finding | No; reviewed |
| [Draft/Reverse Engineering - REMath Literature.md](../Draft/Reverse%20Engineering%20-%20REMath%20Literature.md) | Changed; managed topic | Yes | C6 | Yes |
| [Draft/Rootkits.md](../Draft/Rootkits.md) | Changed; managed topic | Yes | B02 | Yes |
| [Draft/RT.md](../Draft/RT.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/SCA.md](../Draft/SCA.md) | Unchanged; child/reference page | No | B01 | Yes |
| [Draft/SCADA.md](../Draft/SCADA.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/SE.md](../Draft/SE.md) | Changed; managed topic | Yes | No specific finding | Yes |
| [Draft/Subject_Index.md](../Draft/Subject_Index.md) | Changed; generated navigation | No | A4, C1, C8 | Yes |
| [Draft/sysinternals.md](../Draft/sysinternals.md) | Changed; managed topic | Yes | B02 | Yes |
| [Draft/threatmodel.md](../Draft/threatmodel.md) | Changed; managed topic | Yes | A3 | Yes |
| [Draft/Unsorted-rt.md](../Draft/Unsorted-rt.md) | Unchanged; child/reference page | No | No specific finding | Yes |
| [Draft/UX.md](../Draft/UX.md) | Changed; managed topic | Yes | No specific finding | No; reviewed |
| [Draft/Web.md](../Draft/Web.md) | Changed; managed topic | Yes | B02, B06, B08 | Yes |
| [Draft/Wireless.md](../Draft/Wireless.md) | Changed; managed topic | Yes | C9 | Yes |

## Executed repair order

1. Finish pilot subject hierarchy and repair misleading main-page grouping; preserve resources and legacy anchors.
2. Replace empty child ToCs and correct child labels, template debris and browsing omissions.
3. Remove empty/template-only destinations from reader ToCs and selective index without inventing resources; retain planning notes separately and preserve compatible anchors.
4. Separate author maintenance instructions from resources, repair existing cross-page pointers and consolidate duplicated navigation without dropping resource occurrences.
5. Add focused regressions for the gaps that allowed a green audit to imply completion, regenerate outputs/inventories, and verify the entire affected corpus.
6. Reconcile every finding with evidence before reconsidering PR readiness. No merge, deployment, archival capture or source-URL submission is part of this repair pass.

## Integrated repair evidence — 2026-10-26

All **33 recorded finding groups** have a repair disposition above and received bounded independent review. All **102 reader pages** were reviewed for outline/ToC and targeted navigation issues; **77 now differ from the source base**, and 25 remain unchanged after review. This is a navigation/editorial-structure result, not a full factual review of the reference library.

- There are still **53 main topics**. **60 pages have managed ToCs**, including ten child/reference pages that are not promoted into the main sidebar. Selective subject entries are kept separate from empty scaffolds and housekeeping labels.
- Actual checked-in Docsify compilation of **every reader page** finds **zero duplicate rendered IDs and zero missing managed ToC targets**. Every explicit and nonempty automatic fragment from the pre-repair snapshot survives, including renamed subjects and moved empty scaffolds. The permanent renderer regression now derives its scope from all manifest ToCs, rather than a hardcoded list of 50 main pages.
- The global raw HTTP URL multiset is exactly preserved: **26,358 occurrences before and after**, compared with `923f366`. The only cross-page resource move is the two already recorded Commonly Used Port citations from Priority Definition Directive to Command and Control. Rendered external-link occurrences rise from **24,661 to 24,769**, with **zero losses**: the increase is the 108 pending Web URL occurrences exposed from the fenced backlog.
- Empty destination links now fail validation. Seven malformed citations are reattached to their recorded destinations, nine titles retain their linked parts/slides/video, and two unnamed blank bullets are removed. **18 remaining citation occurrences have no URL recorded in their local entry**; their names and descriptions remain, with follow-up recorded in [the maintenance backlog](maintenance-backlog.md). No destinations were invented or researched externally.
- The existing main-page resource/anchor/code fixtures remain enforced. Web's two fenced URL-backlog entries were adjudicated as resource text, not code examples; the broad preservation test was not weakened. Empty source scaffolds remain fenced in the maintenance backlog, including their original text.
- Regenerated inventories contain **21,838 provisional unique URL candidates**: 1,212 PDFs, 1,467 videos, 23 other non-text, and 19,136 unknown. These counts are source-derived candidates, not verified content types, downloads or captures.

Final automated verification and PR state are recorded in [implementation status](implementation-status.md). Archive triggers remain manual-only. No external availability batch, archive capture, Internet Archive submission, merge or deployment occurred during this repair pass.

## Remaining limits and follow-up

External URL availability, missing destination research, full prose/factual validation, production deployment/cache behavior, and paused archival work remain outside the verified result. Existing orphan-page and repeated-destination warnings are reported separately from navigation errors; source age or duplication was not grounds for deleting resources. The unchanged pages were reviewed, not silently marked migrated.
