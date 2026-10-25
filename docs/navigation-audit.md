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
