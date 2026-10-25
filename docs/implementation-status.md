# Implementation status

Branch: `codex/generated-navigation` (desktop continuation; original export: `improve-generated-navigation`). Source base: `af8b68e2194e695c542eb76fba762d2f0a19a0dc`. Changes are local; nothing has been pushed, published, or archived externally.

## Implemented

- Shared Markdown parser and offline navigation audit, including explicit HTML anchors and GitHub heading fragments.
- One manifest for 53 main topics (the original 48, the three existing platform-specific post-exploitation pages, SCADA, and additional cryptography references), generated README/site topic navigation, sidebar, selective alphabetical subject index, and full reference search paths.
- Generated ToCs and real navigable headings for thirty-nine pages: AD, DFIR, logging/monitoring/threat hunting, Cloud, Containers, Basic, Building a Lab, Career, Classes/Training, Documentation/Reporting, Threat Modeling, OSINT, Exfiltration, Fuzzing, Exploit Development, Reverse Engineering, Programming Language Security, Defense, Web, Red Teaming, general/Windows/Linux/macOS post-exploitation, System Internals, Network Attacks, Physical Security, Phishing, Wireless, Anonymity/OpSec/Privacy, both cryptography collections, Embedded, Games, Malware, Rootkits, SCADA, UX, and BIOS/UEFI; original external URL tokens and explicit anchor names are regression-checked.
- Docsify configuration repair and narrow search-plugin fixes for empty heading bodies, HTML titles, and explicit-anchor result destinations.
- Internal navigation checks with individual legacy exemptions and stale-exemption detection; read-only CI workflow.
- Parser-generated processing lists and a separate progress ledger that survives regeneration.
- Bounded external availability checks and report-only workflow; archive job planning with separate non-text queues and verified-prior-capture eligibility.

## Measured results

Initial internal errors: 334. After pilot: 305 legacy errors remained. After Cloud/Containers: 296 remained. After foundations: 274 remained. After assessment references: 260 remained. After testing/development references: 200 remained. After defense/web/red-team references: 122 remained. After systems references: 80 remained. After network references: 46 remained. After the final legacy-debt group: zero internal navigation errors remain across all 102 audited pages, and the legacy-error baseline is empty. Warnings remain separate: 15 orphan-page and 22 repeated-destination findings.

Current provisional resource candidates: 1,200 PDFs, 1,458 videos, 23 other non-text; 19,057 URLs remain unknown until response/content confirmation. These are source-derived inventory counts, not verified content types or download counts.

Automated tests exercise the actual checked-in Docsify compiler and application in jsdom under `/docs/`, sidebar/deep routing, and distinct search phrases. Separate Chromium checks are recorded below; production deployment remains unverified.

## Remaining work

- Review the remaining 14 of 53 listed topics and migrate where useful. All legacy internal errors are repaired. Three existing directory landings remain functional without forced ToCs; eleven other topics still need rollout review.
- Complete collection-wide GitHub/Docsify navigation and search QA, and resolve inline-anchor duplicate IDs/empty heading permalinks and the missing favicon. The thirty-nine migrated pages have compiler/browser evidence; production deployment remains unverified.
- Configure Browsertrix on the available Docker runtime and choose a durable archive destination; implement the enforced capture adapter, article-image filtering, WARC verification, offline replay, and storage/retrieval pilot. The archive policy file describes intent, not implemented enforcement.
- Run external batches with evidence-aware capture/queue routing. No full external validation or web capture has run.
- Separately scoped later processing: PDF extraction/OCR, video captions/transcription, other extractors, and extracted-content search indexing. These are not prerequisites for completing navigation.

## Engineering decisions

- Original web session: used its isolated clone on a feature branch. Desktop continuation: use the explicitly requested local checkout on `codex/generated-navigation`.
- Maintain execution records directly rather than depend on downloaded bookkeeping scripts.
- Keep legacy debt explicit outside the pilot; do not mass-rewrite the remaining collection without pilot review.
- Use one initial main-topic category to avoid imposing a new taxonomy.
- Retain stable explicit content IDs and legacy anchor names for cross-renderer navigation.
- Check raw URL preservation as well as parser visibility because indentation repairs make previously code-rendered resources parseable.
- Index explicit routes for the full collection, accepting an initial corpus fetch for browser search.
- Patch the existing search plugin narrowly, with runtime regressions; future upgrades must retain or replace those fixes.
- Bound weekly external checks to a rotating sample, accurately labeled as a sample.
- Deliver honest archive planning rather than claim an unimplemented or unverified capture engine.

## Review and verification

Final review findings and latest verification evidence are recorded here when available.

The independent review identified six issues. The correction pass adds occurrence counts to the baseline; rejects unsafe/symlinked managed inputs and outputs; defers uncertain responses without replacing resource candidates with access-error MIME; aligns supported Node versions with the lockfile; preserves case in explicit search IDs despite Docsify query normalization; and applies first-definition-wins Markdown reference semantics. Each behavioral correction has a regression that failed before the fix. Production dependency audit reported zero known vulnerabilities at verification time.

One non-blocking presentation issue remains: inline legacy anchors can create duplicate same-subject DOM IDs and empty Docsify heading permalink wrappers. Heading text, generated ToC destinations, and search destinations remain functional in the tested DOM. A cleaner heading renderer/anchor layout is deferred; native-browser visual review remains outstanding.

Export verification (web environment): clean `npm ci --ignore-scripts` succeeded; `npm test` passed 35 tests with zero failures; `npm run nav:check` passed with no new/stale navigation diagnostics and 305 explicitly baselined legacy error occurrences. Resource lists regenerated successfully and `git diff --check` passed. No external availability batch or WARC capture was executed.

To use the exported patch, apply it to a compatible clean checkout of the source repository after checking it with `git apply --check infosec-navigation.patch`; then run `git apply infosec-navigation.patch`, `npm ci --ignore-scripts`, `npm test`, and `npm run nav:check`.

## Desktop continuation — 2026-10-25

- Verified a clean local checkout at the exact source base, checked and applied `/Users/macbook-dev/Downloads/infosec-navigation.patch`, and saved the imported state as local commit `8b21705`. The patch includes inherited trailing-whitespace warnings; its content was preserved at import.
- Continued on a feature branch in the requested local checkout. No additional worktree, push, publication, or archive capture was made.
- Installed locked dependencies with scripts disabled using the existing Node.js 24.18.0 installation. Added `.nvmrc` and contributor setup instructions; the shell's default 24.6.0 is below the locked dependencies' supported minimum.
- Baseline tests exposed a macOS filename-case bug: 34/35 passed. The resolver now checks exact directory-entry spelling on every path component. The pre-existing file-case test and added directory-case cases pass.
- Native Chromium exposed full-corpus search exceeding localStorage quota. Cache writes now preserve the in-memory index on quota failure, and an expiry without an index triggers rebuilding. Quota and incomplete-cache regressions failed before their fixes and now pass.
- Reviewed the three pilots in Chromium under `/docs/`: sidebar/deep routing, search results for `Kerberoasting`, `Introduction to DFIR`, and `Funnel of Fidelity`, destination heading text, and deep-route reload. The inherited missing favicon and empty heading permalink wrappers remain presentation issues.
- Migrated `Draft/Cloud.md` and `Draft/Containers.md` as one reviewable group. Generated ToCs use stable `ref-cloud-*`/`ref-containers-*` IDs; selected platforms and AWS IAM are indexed. Raw external URL multisets and previously parsed resource occurrences are regression-checked. Duplicate `c101` resolves to its first content section; the `containers` legacy destination resolves at the page title. Qualified Cloud Logging/Azure Compliance labels avoid collisions with legacy IDs.
- Retired all nine baseline errors for those two pages, leaving 296 occurrences / 288 keys. Regenerated inventories retain 21,745 URLs (1,199 PDF, 1,458 video, 23 other non-text candidates, 19,065 unknown). Offline archive planning accounts for all URLs and reports zero preserved captures.
- Checked Docker client/server 29.8.1 and existing images. Browsertrix is absent; about 233 GiB of host disk space was available. Durable storage is still unspecified. No container image installation, external availability batch, bulk download, OCR/transcription, or capture was run.

Ruling: resume in the requested checkout on a feature branch and keep execution records here — the portable handoff explicitly targets this checkout; an extra worktree and duplicate bookkeeping would complicate recovery. Remaining migrations stay grouped; this continuation does not claim repository-wide completion.

Desktop final verification: `npm ci --ignore-scripts --no-audit --no-fund` succeeded on Node.js 24.18.0; `npm test` passed 39/39; `npm run nav:check` reported 296 explicitly baselined errors and no new/stale diagnostics; a repeated `npm run nav:generate` returned no changed paths. Resource regeneration and offline archive planning succeeded. Chromium also verified Cloud's AWS IAM route at `/` and the new group's destinations under `/docs/`. The only observed browser resource error was the inherited missing favicon.

Independent review found no blockers. It identified a newly introduced S3 heading-text artifact; a rendering regression failed before correction and passed after, retaining the legacy `s3atk>` alias. The reviewer independently compared old/new Docsify output and confirmed every prior external-link occurrence and fixture legacy anchor remains rendered for Cloud/Containers. Deferred presentation issues remain the inline-anchor duplicate IDs/empty heading permalink spans and missing favicon. `git diff --check` still flags inherited trailing spaces carried through the imported patch and migrated content; no whitespace-only sweep was performed.

## Foundations navigation group — 2026-10-25

Starting checkpoint: `9b8f17a`; continued in the same requested checkout on `codex/generated-navigation`.

- Migrated `Draft/Basic.md`, `Draft/Building_A_Lab.md`, `Draft/Career.md`, and `Draft/Courses_Training.md`. ToCs use stable `ref-basic-*`, `ref-lab-*`, `ref-career-*`, and `ref-training-*` IDs; depth four includes existing nested basics, vulnerable-web-lab subjects, and cloud training providers. Added 39 selected subjects to the alphabetical index.
- Kept all linked resources from Basic's unsorted preamble on the Basic page under `ref-basic-notes`, after the organized content. Moved its 51 resource-free editorial blocks and the lab's resource-free To Do list to `docs/maintenance-backlog.md`. No resource acquisition or pruning was performed.
- Closed malformed legacy anchor markup, retained exact-case `AD`/`Industry` destinations, and kept `mgmt` at the first Management section while giving Management Skills its own canonical target.
- Repaired Basic's documentation link to `Docs_and_Reports.md` and malformed threat-model links to the existing `threatmodel.md`. Intentionally added `https://` to Career's `allengeer.com/how-to-handle-brent-in-the-phoenix-project/` destination; the existing host/path were retained, and availability remains unverified. The preservation fixture records this one exception explicitly.
- Reused the Cloud/Containers preservation checks as `tests/navigation/migration.test.mjs` and extended the fixture to all six rollout pages. Checks retain raw HTTP(S) URL multisets (reversing only the documented scheme correction), prior parsed external-link occurrences, and all legacy anchor destinations. They reject internal errors or baseline exemptions on migrated pages. The four migration tests and compiler coverage failed before the migration and now pass.
- Retired all 22 baseline errors for this group. The remaining debt is 274 occurrences / 266 distinct keys, with no new/stale diagnostics. Regenerated inventories contain 21,746 URLs: 1,199 PDF, 1,458 video, 23 other non-text candidates, and 19,066 unknown. The added URL is the corrected Career destination; these counts remain provisional.
- Chromium under `/docs/` verified exact search-result URLs and destination headings for `InfoSec Newbie List` (Basic), `BadBlood` (lab building), `Manager Tools` (Career), and `Learning How to Learn` (training), followed by deep-route reload. No browser console errors were observed.
- Independent review found no blockers, checked old/new actual Docsify output for resource occurrences and legacy anchors, and confirmed heading nesting/internal corrections. The known inherited heading-anchor/favicon presentation issues remain deferred. Trailing-space warnings inherited from the content remain; no whitespace-only rewrite was made.

Remaining work continues in reviewable page groups. Capture tooling, durable storage, external batches, and later extraction/search processing are unchanged and pending.

Foundations final verification: `npm test` passed 43/43 on Node.js 24.18.0; `npm run nav:check` passed with 274 baselined error occurrences and zero new/stale diagnostics; a repeated `npm run nav:generate` returned no changed paths. Resource inventories regenerated successfully. Actual Docsify comparisons after the editorial-note split retained all prior rendered external-link occurrences (Basic 468→468, lab 277→277, Career 465→466 with the intentional scheme repair, training 163→163) and all recorded legacy anchors. No external availability request or archive capture was run.

## Assessment references group — 2026-10-25

Starting checkpoint: `62e676c`; continued on `codex/generated-navigation` in the requested checkout.

- Migrated `Draft/Docs_and_Reports.md`, `Draft/threatmodel.md`, `Draft/Osint.md`, and `Draft/Exfiltration.md`. Added managed document-order ToCs, stable `ref-reports-*`, `ref-threat-*`, `ref-osint-*`, and `ref-exfil-*` IDs, and 27 selected alphabetical subjects. Depth four exposes the existing nested writing topics, threat-model methodologies, and site-specific OSINT categories.
- Replaced stale/empty manual ToCs, retained exact-case `Writingrfp`, and preserved the former Sort/End Sort destinations as aliases on the appropriate unsorted-resource sections. Corrected clear heading-label typos (Documentation Tools, Writing a Request for Proposal, LaTeX, Steganography) and the unclosed Import/Export title parenthesis.
- Kept all unsorted resource references on their original pages, after organized material. Threat modeling's unlinked resource names remain too. Only the reporting To Do, OSINT source-list planning note, and exfiltration sorting instruction moved to `docs/maintenance-backlog.md`; no new resource was added, removed, or fetched.
- Expanded preservation fixtures and actual-compiler coverage before migrating: the four migration tests and compiler test failed first, then passed. Raw HTTP(S) URL multisets, prior parsed external-link occurrences, and recorded legacy destinations are retained without a URL correction exception for this group.
- Retired all 14 legacy errors for this group; the debt is now 260 occurrences / 252 keys. All thirteen migrated pages and managed navigation remain free of internal errors. Resource regeneration retains 21,746 URLs (1,199 PDF, 1,458 video, 23 other non-text candidates, 19,066 unknown); type/availability remain provisional.
- Native Chromium under `/docs/` verified exact result hashes and destination headings for `Teach Technical Writing in Two Hours` → Technical Writing, `Guerrilla Threat Modelling` → STRIDE, `ExoneraTor` → Tor, and `Stegano` → Steganography. Deep-route reload succeeded; no console errors were observed.
- Independent review found no blockers. Actual Docsify old/new comparisons retain all prior rendered external-link occurrences: reporting 166→166, threat modeling 29→29, OSINT 211→211, exfiltration 70→70. Raw URL hashes and all fixture aliases, including `Writingrfp`, were also checked. Inherited same-heading inline-anchor presentation issues remain deferred.

Verification: `npm test` passed 47/47 on Node.js 24.18.0; `npm run nav:check` passed with 260 baselined errors and zero new/stale diagnostics; repeated `npm run nav:generate` reported no changes. Inventories regenerated successfully. Inherited trailing-space warnings remain; no whitespace-only sweep, external availability request, or archive capture was performed.


## Testing and development references group — 2026-10-25

Starting checkpoint: `1f2293c`; continued in the requested checkout on `codex/generated-navigation`.

- Migrated `Draft/Fuzzing.md`, `Draft/Exploit_Dev.md`, `Draft/RE.md`, and `Draft/Programming_Language_Security.md`, using managed ToCs, stable `ref-fuzz-*`, `ref-exploit-*`, `ref-reverse-*`, and `ref-appsec-*` destinations. Added 62 selected alphabetical subjects. Retained existing language hierarchy and qualified repeated labels to avoid legacy-anchor collisions.
- Kept linked unsorted notes on their source pages; only resource-free maintenance instructions moved to the backlog. Preserved the original fenced/indented code ranges byte-for-byte and all prior external URL occurrences/legacy aliases. Deduplicated `winspec` and `practice` at their first content destinations. The C# heading keeps its `c#` alias while its qualified title avoids the legacy C/C++ `c` fragment.
- Corrected the obsolete GitHub lab link to the existing tracked `Draft/Rants&Writeups/Writeups/Lab_for_exploit_dev-basic.md`; the preservation fixture records this sole intentional URL correction. Raw URL hashes reverse only recorded corrections, and parsed-occurrence checks map those same corrections before comparison.
- Retired all 60 group errors, leaving 200 occurrences / 192 keys across 23 other pages. Seventeen of the 48 main-topic pages now have managed ToCs; the remaining 31 require review/migration as appropriate, including existing functional directory landings. Inventories retain 21,746 unique URLs: 1,199 PDF, 1,458 video, 23 other non-text candidates and 19,066 unknown; content types and availability remain provisional.
- Independent review found an over-deep Windows shellcode heading that also absorbed general shellcode categories. A focused actual-compiler/ToC regression failed first; Windows Specific and the following Techniques, Reference, REPLs and Tools categories now have separate depth-four headings. Correction review confirmed the original three Windows resources remain in their section and all 531 rendered external-link occurrences are retained with the documented destination correction. No remaining review finding.
- Native Chromium under `/docs/` verified exact search-result hashes and headings for `american fuzzy lop` → AFL, `Rubik` → Corelan, `WinDbg` → Debuggers, and `Code Review` → Code Review. An additional `WinAPI for Hackers` search reaches `ref-exploit-27` at H4; its deep-route reload succeeds. No browser console errors were observed.

Verification: `npm test` passed 51/51 on Node.js 24.18.0; `npm run nav:check` passed with 200 explicitly baselined errors and no new/stale diagnostics; repeated `npm run nav:generate` returned no changed paths. Inventories regenerated successfully. Known inherited inline-anchor/favicon issues and trailing-space warnings remain; no broad whitespace rewrite, external availability batch, capture, push or publication was performed.


## Defense, web and red-team references group — 2026-10-25

Starting checkpoint: `344da8b`; continued on `codex/generated-navigation` in the requested checkout.

- Migrated `Draft/Defense.md`, `Draft/Web.md`, and `Draft/RT.md` with managed document-order ToCs and stable `ref-defense-*`, `ref-web-*`, and `ref-rt-*` IDs. Added 99 selected subject entries; asset inventories are qualified as personal/organization in the index. Headings stay within configured depth four, with complete sibling categories where needed to keep resource scope accurate.
- Replaced stale manual/mini-ToCs and relocated their explicit aliases to corresponding content (`1stand`, `1attack`, `first`, `c2ss`, `implants`). Defense's inherited duplicate ToC/merge marker was removed. Only resource-free To Do notes moved to the maintenance backlog; linked resource bodies and original code ranges remain.
- Corrected Web's mislabeled Protocol Buffers and Logic Flaws sections; retained `robots` at the actual robots.txt section and `log4j` at the actual Log4j section. Filled the blank File System Access API heading and qualified new titles that would otherwise collide with existing aliases. Repaired Linux/Rails resource indentation exposed by preservation tests.
- Intentionally added HTTPS to Web's existing `www.vsecurity.com/download/papers/XMLDTDEntityAttacks.pdf` destination, recorded as the sole URL correction. RT's unusable `[keyserver](keyserver)` placeholder remains as plain text with its description and a backlog item; no destination was invented or fetched.
- Expanded original-source snapshots and actual-compiler coverage before editing. The three migration tests and compiler check failed first, then passed. Raw external URL multisets, original parsed resource occurrences, explicit aliases, and original code blocks are preserved with the documented URL correction.
- Retired all 78 group errors. Remaining debt: 122 occurrences / 121 keys across 20 other pages. Twenty of 48 main topics have managed ToCs; the remaining 28 need review/migration where useful. Regenerated inventories contain 21,747 unique URLs: 1,200 PDF, 1,458 video, 23 other non-text candidates, and 19,066 unknown. The extra PDF candidate is the repaired scheme; classification/availability remain provisional.
- Independent review found no blockers. Actual Docsify comparisons retain every prior rendered external-link occurrence: Defense 176→178, Web 2,347→2,353, RT 1,946→1,950, accounting for the intended correction. Additional visible links come from repaired malformed list indentation. Code examples, legacy aliases, heading depth and relocated navigation targets were checked.
- Native Chromium under `/docs/` verified `Inventory-BrowserExts` → security baseline, `File System Access API - MDN` → File System Access API, and `Introducing RedELK` → Logging & Monitoring, followed by deep-route reload. Further searches confirm `Protocol Buffers - Google` and `The Art of Exploiting Logical Flaws` reach their corrected sections. No console errors were observed.

Verification: `npm test` passed 54/54 on Node.js 24.18.0; `npm run nav:check` passed with 122 explicitly baselined errors and no new/stale diagnostics; repeated generation reported no changed paths. Resource inventories regenerated successfully. Existing inline-anchor/favicon presentation issues and inherited trailing-space warnings remain. No external availability batch, archive capture, push or publication ran.


## Systems references group — 2026-10-25

Starting checkpoint: `2678f17`; continued on `codex/generated-navigation` in the requested checkout.

- Migrated general, Windows, Linux and macOS privilege escalation/post-exploitation plus System Internals, with stable `ref-postex-*`, `ref-winpost-*`, `ref-linpost-*`, `ref-macpost-*` and `ref-internals-*` IDs. Added 83 selected subject entries, qualifying platform/context where needed. Original platform links on the general page remain.
- Ruling: add the three existing platform pages to the shared topic manifest — the current generator requires listed pages for managed ToCs, and direct topic/sidebar access improves discovery without adding a second configuration mechanism. The manifest now has 51 topics; existing page paths remain. All three appear together after the general post-exploitation topic.
- Moved macOS's unsorted resource block intact to the bottom, retaining Begin/End destinations. Only System Internals' resource-free To Do list moved to the maintenance backlog. Nine Windows `1win*` navigation-only aliases now point at the same actual sections their old mini-ToC lines referenced. Kept duplicate `pads`, `pss`, and `wcreds` at first content destinations; later sections have distinct canonical IDs.
- Corrected a Chinese-label-prefixed Windows URL to its existing embedded HTTPS destination, and the bare Invoke-ReflectivePEInjection filename to the same PowerSploit URL already elsewhere on the page. Both exceptions are recorded in the preservation fixture. The existing body DLL-injection link now targets the actual code-injection section. No external destination was fetched or invented.
- Expanded snapshots/compiler coverage before migration; five migration cases and compiler coverage failed first. Preservation checks caught missing navigation-only aliases and indented resource lists; those were repaired. Reviewer caught Alaris/ScatterBrain content rendered as code only in Docsify. A focused compiler regression failed before their indentation repair and now passes.
- Retired 42 group errors, leaving 80 occurrences / 79 keys across 15 other pages. Twenty-five of 51 listed topics have managed ToCs; 26 remain to review/migrate as appropriate. Inventories contain 21,748 unique URLs: 1,200 PDF, 1,458 video, 23 other non-text candidates and 19,067 unknown; the repaired Chinese-prefixed URL is the additional unique web candidate.
- Independent review and its correction pass retain all prior rendered external-link occurrences: Windows 3,828→3,844, Linux 99→99, macOS 432→432, general post-exploitation 272→272 and System Internals 432→444, with the documented corrections. All fixture legacy aliases render; no remaining finding.
- Chromium under `/docs/` verified exact result hashes/headings for Alaris → Shellcode Stuff, GTFOBins → Linux Execution, SwiftBelt → macOS Discovery, Chisel → HTTP/HTTPS, and Callback Objects → Callbacks. Deep-route reload succeeded, all three new platform sidebar links were present, and no console errors were observed.

Verification: `npm test` passed 59/59 on Node.js 24.18.0; navigation check passed with 80 explicitly baselined errors and no new/stale diagnostics; repeated generation reported no changed paths. Inventories regenerated successfully. Known inline-anchor/favicon presentation issues and inherited trailing spaces remain; no external validation batch, archive capture, push or publication ran.


## Network references group — 2026-10-25

Starting checkpoint: `a573745`; continued on `codex/generated-navigation` in the requested checkout.

- Migrated `Draft/Network_Attacks.md`, `Draft/Physical_Security.md`, `Draft/Phishing.md`, and `Draft/Wireless.md` with stable `ref-network-*`, `ref-physical-*`, `ref-phish-*` and `ref-wireless-*` IDs. Added 111 selected subject entries: protocol/topic headings, selected phishing techniques and document formats, physical-security subjects and wireless technologies. Repeated/generic channel labels remain in page ToCs but are omitted from the selective index.
- Corrected Network Attacks' first mislabeled HNAP section to gRPC, with HNAP retained at its actual protocol section. Repaired the malformed Attacks heading. Duplicate pivot/vendor/lockpicking aliases retain their first content destination; repeated resource occurrences remain. No external URLs were changed.
- Moved Wireless's original unsorted block intact to the bottom, including its code example, and preserved its Sort destination. Moved Phishing's To Do list and Network Attacks' complete Need to Add planning list to the maintenance backlog. No linked resource was removed or acquired.
- Four new snapshot migration cases and compiler coverage failed before editing. Raw URL multisets, prior parsed resource occurrences, explicit legacy aliases and original code strings pass preservation checks. Qualified the new Excel heading to avoid collision with the existing legacy destination.
- Independent review confirmed all original rendered external links and aliases: Network 808→808, Physical Security 62→62, Phishing 566→566 and Wireless 302→302, including all four rendered code blocks. Its correction pass identified an inherited same-line SDR resource promoted into a heading and an omitted planning note. The resource is now a bullet below a clean heading; a focused compiler regression failed before correction and passes after. The planning note is preserved in the backlog and generic Wireless index entries were removed.
- Retired all 34 group errors, leaving 46 occurrences / 45 keys across 11 other pages. Twenty-nine of 51 listed topics have managed ToCs; 22 remain to review/migrate where useful, including functional directory landings. Inventories retain 21,748 URLs (1,200 PDF, 1,458 video, 23 other non-text candidates, 19,067 unknown).
- Native Chromium under `/docs/` verified exact result hashes and headings for Awesome gRPC → gRPC, Green Beret → General resources, evilginx → Built for 2FA, KillerBee → Zigbee articles and Introduction to SDR → SDR articles. Deep-route reload succeeded with no console errors. Chromium's HTTP cache initially showed pre-migration Markdown; these checks used a cleared/disabled HTTP cache to verify current files. Production cache behavior remains unverified.

Verification: `npm test` passed 63/63 on Node.js 24.18.0; final navigation check passed with 46 baselined errors and no new/stale diagnostics. The final subject-index selection was regenerated and checked; repeated generation reported no changed paths. Inventories regenerated successfully. Existing inline-anchor/favicon presentation issues and inherited trailing-space warnings remain. No external availability batch, archive capture, push or publication ran.


## Final legacy-debt group — 2026-10-25

Starting checkpoint: `d15b5a5`; continued on `codex/generated-navigation` in the requested checkout.

- Migrated Anonymity/OpSec/Privacy, CandE, Crypto_Encrypt, Embedded, Games, Malware, Rootkits, SCADA, UX and BIOS/UEFI with managed document-order ToCs and stable explicit content IDs. Added 166 selected subjects; generic resource channels stay in page ToCs rather than the alphabetical index. SCADA and the existing additional cryptography collection are now listed directly, bringing the manifest to 53 topics and 39 managed ToCs. The separate cryptography collections retain their own resources and are clearly distinguished.
- Repaired the ATT&CK collection portal without forcing a ToC on this short directory page. Eleven old GitHub URLs now point to actual local ATT&CK mapping files, including correcting Credential Access from Command and Control to Credential_Access. Filled thirteen empty pre-ATT&CK destinations using existing files, preserving all original framework/project external links and both Atomic Red Team occurrences. A semantic route regression failed before correction and now passes.
- Kept all linked and named unsorted references on their source pages, after organized material. Only resource-free cryptography/Embedded/Malware/firmware maintenance notes moved to the backlog. UX's introductory tagline remains a paragraph with its original implicit destination retained as an explicit alias. Rootkits' mixed-encoding punctuation bytes were converted to UTF-8 while retaining valid UTF-8 text.
- Expanded ten original-source preservation snapshots and compiler coverage before migration. Those ten tests, compiler coverage and the portal test failed first, then passed. Raw external URL multisets, prior parsed link occurrences, explicit aliases and original code strings are retained on all ten pages; the portal's intended internal path repairs are separately checked.
- Independent review caught two Embedded links rendered as code and stray markup in Malware's PDF title. Focused actual-compiler regressions failed before their fixes and now pass. The two moved resource bullets are clickable; the PDF heading retains its alias and clean text. Additional cryptography references have their own section rather than inheriting the last cryptocurrency topic. No remaining review finding.
- Actual Docsify old/new rendered external-link counts are unchanged: privacy 547, CandE 143, additional cryptography 175, Embedded 207, Games 104, Malware 315, Rootkits 79, SCADA 58, UX 19 and BIOS/UEFI 129. All recorded legacy aliases remain rendered.
- All remaining 46 legacy error occurrences were retired. The full audit now has zero internal errors and an empty baseline, with 15 orphan and 22 repeated-destination warnings. Inventory: 21,738 unique URLs (1,200 PDF, 1,458 video, 23 other non-text candidates and 19,057 unknown). Ten obsolete unique GitHub navigation URLs left the external inventory when repaired to local paths; resource references were not pruned.
- Chromium under `/docs/` verified exact result hashes/headings for Scuttlebutt Protocol Guide, Crypto 101, HTTPS in the real world, ArduPilot, TRIBES Engine Networking Model, Golem Malware, Jynx, Modbus interface tutorial, The Design of Everyday Things and CHIPSEC. Deep-route reload succeeded. The repaired portal routes for Credential Access and Priority Definition Planning reached their matching content, including encoded ampersand/space paths, and deep reload succeeded. No console errors were observed.

Verification: `npm test` passed 74/74 on Node.js 24.18.0; navigation check reported zero internal errors, no new/stale diagnostics and no changed managed paths; repeated generation made no changes. Inventories regenerated. Existing inline-anchor/favicon presentation issues and inherited trailing spaces remain. No external availability batch, capture, push or publication ran.
