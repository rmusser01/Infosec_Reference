# Navigation audit

Source commit: af8b68e2194e695c542eb76fba762d2f0a19a0dc. Offline parser/path audit; external URLs were not fetched.

## Initial findings

| Measure | Count |
|---|---:|
| Markdown pages | 98 |
| Parsed links and images | 27092 |
| Internal errors | 334 |
| orphan-page | 48 |
| missing-file | 22 |
| repeated-destination | 61 |
| missing-fragment | 290 |
| duplicate-anchor | 22 |

An orphan warning means no direct inbound file link was found, not that a page is necessarily inaccessible: directory navigation and external inbound links are not counted. Repeated destinations are review warnings, not automatic defects. Fragment checks use exact-case explicit anchors and GitHub-style heading slugs; deployed website behavior is checked separately.

The sidebar points to nonexistent `Stuff.md`; the corresponding topic exists at `Interesting_Things.md`. The root index duplicates the logging topic. The three pilot pages have stale ToC links; AD also links to nonexistent `Phishing.html`.

Initial findings are preserved in `navigation/initial-audit.json`. Run `npm run nav:audit` for current findings. Legacy errors outside migrated scope will be explicitly baselined, not silently ignored.

## After the three-page pilot

Current audit: 102 pages, 305 remaining internal errors, 297 distinct legacy error keys. Managed topic/index navigation and the three pilot pages have zero internal errors. Remaining legacy errors are recorded in navigation/legacy-errors.json; they are not repaired or hidden by a broad ignore rule.

The parser-generated resource inventory supersedes the preliminary regex scan: 1,199 PDF candidates, 1,458 video candidates, and 23 other non-text candidates. Types and availability remain unverified. Unknown URLs are retained for later confirmation.

Docsify configuration and the actual compiler were tested, followed by a local HTTP application smoke under /docs in jsdom: deep routing, sidebar, and distinct searches in each pilot. Native-browser visual review and production deployment were not performed.

## Desktop continuation — Cloud and Containers

The pilot received native Chromium review under `/docs/`, including sidebar/deep routes, search destinations for all three pilot phrases, and deep-route reload. This exposed browser cache quota exhaustion, now handled with an in-memory fallback and incomplete-cache recovery. The resolver also now enforces filename and ancestor-directory case on macOS, matching Linux checks.

Cloud and Containers now have generated ToCs and selected subject-index entries. Their raw external URL multisets, previously parsed resource occurrences, and legacy destinations are checked. All nine group errors were retired: 296 error occurrences / 288 distinct keys remain elsewhere. Both pages' managed fragments were verified in the actual Docsify compiler and Chromium. Full repository migration and production deployment remain outstanding.

## Foundations group

Basic, Building a Lab, Career, and Classes/Training now have managed ToCs and selected index subjects. Basic's linked unsorted resources remain on its page, while resource-free editorial placeholders and the lab's To Do list are in the maintenance backlog. Existing resource occurrences/legacy anchors are retained, apart from the explicit addition of an HTTPS scheme to Career's existing Allen Geer destination. Basic's documentation/threat-model paths point to real Markdown files.

All 22 group errors are retired; 274 error occurrences / 266 legacy keys remain elsewhere. Actual Docsify compiler checks and native Chromium search/deep routing cover these four pages. Inventories now have 21,746 unique URLs after the single intentional destination repair; provisional type counts are unchanged except unknown URLs increased to 19,066. External availability remains unverified.

## Assessment references group

Documentation/Reporting, Threat Modeling, OSINT, and Exfiltration now use generated ToCs and selected subject entries. Unsorted references remain on their respective pages; only maintenance instructions moved to the backlog. Existing URL multisets and legacy destinations are preserved, including Writingrfp and the former Sort/End Sort anchors. Native Chromium verified a search destination in each page and a deep-route reload.

All 14 group errors are retired: 260 error occurrences / 252 legacy keys remain elsewhere. The compiler comparison retained reporting 166, threat modeling 29, OSINT 211, and exfiltration 70 rendered external-link occurrences. Inventories still contain 21,746 unique URLs; no external validation or archive capture ran.


## Testing and development references group

Fuzzing, Exploit Development, Reverse Engineering and Programming Language Security now use managed ToCs and 62 selected index subjects. Linked unsorted notes, code examples and legacy destinations are retained. The obsolete exploit-lab GitHub path was intentionally corrected to the existing tracked writeup and recorded in the preservation fixture.

All 60 group errors are retired: 200 occurrences / 192 legacy keys remain across 23 other pages. Seventeen main topics have managed ToCs; 31 remain to review/migrate where useful. Compiler coverage and native Chromium search/deep routes cover all four new pages. Review caught and corrected the Windows shellcode heading depth/scope; its three original references are separate from general techniques, reference material, REPLs and tools. Corrected output retains all 531 rendered external-link occurrences on that page, with the one documented URL correction.

The full 51-test suite passes; navigation check has no new/stale diagnostics, and repeated generation reports no changes. Inventories still contain 21,746 unique URLs. External validation, capture and production deployment remain unverified.
