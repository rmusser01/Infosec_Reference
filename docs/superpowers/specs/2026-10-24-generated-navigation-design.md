# Generated navigation design

## Intent and approval

Improve usability, discovery, editorial consistency, indexes, and tables of contents for an encyclopedic information-security reference. The maintainer selected Markdown plus generated navigation and approved the design in this conversation on 2026-10-24. This document records that design; the implementation choices below are proposed engineering decisions.

## Goals

- Keep Markdown authoritative and routine resource additions simple.
- Generate the main topic navigation from one page manifest.
- Generate page tables of contents from navigable headings, in document order.
- Generate a selective alphabetical subject index with aliases and subsection links.
- Check internal paths, fragments, duplicate anchors, and stale generated output.
- Report orphaned pages and ambiguous destinations separately from confirmed errors.
- Preserve existing paths and anchors where practical and check GitHub and website compatibility.
- Pilot on Active Directory, DFIR, and logging/monitoring/threat hunting before broad adoption.
- Keep external link availability checks separate from internal navigation validation.
- Archive the linked pages/content to WARC as external links are validated, per the maintainer's subsequent amendment. Track failures and partial captures explicitly.

## Non-goals and anti-goals

No resource database, learning curriculum, website redesign, bulk link import, mass pruning, or wholesale content rewrite. Do not delete resources because they are old or temporarily unreachable. Do not manufacture descriptions or aliases without evidence. Do not impose a new categorization of the whole collection during the pilot.

Archiving is preservation of referenced web content, not an unbounded recursive mirror of every linked site. The maintainer clarified that images are included only when part of an article. Preserve article/page HTML and text plus assets needed to read it, including article figures/screenshots and necessary styles or rendering scripts. Do not deliberately collect unrelated images, galleries, advertising/tracking assets, standalone video/audio libraries, binaries, or source repository snapshots. Inventory all references and report out-of-scope targets explicitly. The maintainer subsequently requested separate processing inventories for PDFs, videos, and other non-text resources; queue those for later acquisition, extraction, and search indexing rather than capturing their bytes in the web-page pipeline now. A repository or video landing page can be preserved as a web page without claiming to preserve the repository or video itself.

## Approaches considered

1. Manual cleanup: low initial effort but continued navigation drift.
2. Markdown plus generated navigation: selected by the maintainer; retains the contribution model and automates repetitive work.
3. Structured resource catalog generating pages: more filtering and reuse, but unnecessary migration and contributor overhead for this scope.

## Constraints

- Headings identify navigable subjects; bullets contain resources.
- ToCs follow document order; the subject index provides alphabetical discovery.
- Generated edits are confined to marked blocks and explicitly generated files.
- Existing URLs and anchors are preserved where practical.
- Maintenance notes remain available but are separate from reader navigation.
- GitHub and Docsify compatibility must be verified rather than assumed.
- External availability failures produce a review report, not resource deletion.
- WARC captures are immutable, indexed, and independently verifiable; a successful HTTP response alone does not establish capture completeness.

## Architecture: proposed engineering choices

Use a small Node-based command-line tool with a Markdown parser rather than regular expressions alone. Keep dependencies pinned. A JSON manifest stores page titles, repository-relative paths, categories, aliases, and explicitly selected subsection subjects. Resource entries stay in Markdown.

Generate repository-relative links for GitHub-facing documents and Docsify-compatible links for the website sidebar. Retain Docsify and its existing local assets. Generate the README topic block, a website homepage topic block, the sidebar, the subject index, and managed page ToCs from shared input.

Use the GitHub heading-slug algorithm for GitHub navigation. Inventory explicit HTML anchors, including legacy `name` anchors. Test the checked-in Docsify renderer separately; adapt website links or anchors if it differs. Do not remove legacy anchors simply because a generated heading has a new fragment.

Audit all Markdown initially. Enforce navigation correctness for migrated pages and managed navigation; baseline pre-existing failures elsewhere with their path, target, and reason. Fail on newly introduced internal errors. Retire baseline entries as pages are repaired, and fail on stale baseline entries.

## Repository evidence

Inspected commit: `af8b68e2194e695c542eb76fba762d2f0a19a0dc`.

- Navigation exists in root `README.md`, `Draft/_sidebar.md`, per-page ToCs, and website `Draft/README.md`.
- `Draft/index.html` loads local Docsify and search assets. Its second configuration assignment contains `paths: auto`, an unquoted identifier; investigate and regression-test this before asserting deployed behavior.
- Existing pages mix headings, anchored list labels, and manually maintained ToCs. The logging page also has navigation-only anchors and nested mini-ToCs.
- The sidebar links Interesting Things to `Stuff.md`, whereas the root README links `Interesting_Things.md`; validate the intended target against files before repairing.
- There are 97 Markdown files under `Draft` at this checkout. This is a file count, not a count of broken or orphaned pages.

## Remaining decisions for implementation

Determine exact heading conversions, category assignments, and indexed subjects from the audit and pilot. Confirm Docsify rendering behavior with the checked-in assets. No production publication, remote push, or external messages are included in this design.

## Archiving amendment: proposed implementation

Use compressed `.warc.gz` as the preservation format, with CDXJ indexes and an append-only capture manifest. Browsertrix Crawler is the proposed default for browser-rendered HTML and its loaded dependencies; non-text targets are classified into separate processing queues instead of downloaded by the web-page capture job. Optional WACZ packages bundle WARCs and replay indexes, rather than replacing the WARC requirement.

Validate and capture in one coordinated pipeline where possible: inventory -> capture/check -> verify records and replay -> persist -> report. Preserve the original URL, fragment for reference navigation, requested capture URL without fragment, redirect chain, capture timestamp, HTTP status, content type, WARC record IDs, object location, byte count, SHA-256, tool version, and capture/replay outcome. Preserve query strings unless equivalence has been established. Associate duplicate references with one captured URL without losing their original repository locations.

Retain earlier captures; resume interrupted batches; skip redundant initial captures only when a prior durable verified capture exists. Subsequent refreshes append new dated captures according to an explicit policy. Every URL has independent availability, capture, replay, and storage states. A login wall, CAPTCHA, or saved error page is not a successful content archive.

Keep bulky archive objects outside ordinary Git history; keep inventory, small metadata, checksums, configuration, and reporting code in the repository. Durable archive storage location and media/large-object budgets must be supplied before a full crawl; local bounded pilot capture can proceed independently. Do not rely on expiring CI artifacts as the permanent archive. Do not publish captures to the Internet Archive or another service automatically.

Capture publicly accessible content with an isolated browser profile. Network destination restrictions apply to redirects, browser subresources, and direct downloads. Record blocked or inaccessible content, rather than bypassing access controls. PDFs/slides, videos, and other non-text resources require type-confirmation and separate processing queues. Apply request filtering to exclude unrelated images and media, and verify article text and inline figures remain readable. A video landing page is not an archived video, and a repository web page is not a preserved source checkout; those underlying media/source objects are outside this clarified scope. Report capture limitations without broadening collection automatically.

Pilot static HTML with article images and unrelated image requests, JavaScript-rendered HTML, PDF/video queue routing, redirects, a duplicate URL with fragments, a page with excluded embedded media, and a failure case. Verify archive record readability/digests, image filtering, and offline replay before scaling. Report actual stored bytes and capture/replay success rates to size storage.

Technical references checked 2026-10-24:
- WARC format: https://www.loc.gov/preservation/digital/formats/fdd/fdd000236.shtml
- Browsertrix WARC/CDXJ/WACZ outputs: https://crawler.docs.browsertrix.com/user-guide/outputs/
- Browsertrix replay QA: https://crawler.docs.browsertrix.com/user-guide/qa/
- Wget WARC options: https://www.gnu.org/software/wget/manual/wget.html

## Non-text processing inventories amendment

Create separate lists for PDFs, videos, and other non-text resources. Keep a shared machine-readable inventory with stable IDs, original URLs, all repository references, provisional/confirmed type evidence, and processing status. Retain unknown URLs for later content-type confirmation and discovery; URL suffixes alone are not authoritative. Classify embedded media discovered during article capture into these queues while preserving article text and inline images in WARC.

Future search preparation: PDF text extraction/OCR with page numbers; video captions/transcripts with timestamps; other formats routed to suitable extractors after type confirmation. Store provenance, extractor versions, and extraction/index status separately. No bulk downloads, transcription, OCR, or searchable-content claim is implied by creation of these lists.

An initial source scan and inventories are in `docs/inventories/`. These are provisional URL candidates, not an audited Markdown-parser result or confirmed media counts. The implementation should replace/reconcile the preliminary scan using the shared parser, preserving stable IDs and source references where valid.
