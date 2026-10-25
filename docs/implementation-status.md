# Implementation status

Branch: `codex/generated-navigation` (desktop continuation; original export: `improve-generated-navigation`). Source base: `af8b68e2194e695c542eb76fba762d2f0a19a0dc`. Changes are local; nothing has been pushed, published, or archived externally.

## Implemented

- Shared Markdown parser and offline navigation audit, including explicit HTML anchors and GitHub heading fragments.
- One manifest for 48 main topics, generated README/site topic navigation, sidebar, selective alphabetical subject index, and full reference search paths.
- Generated ToCs and real navigable headings for nine pages: AD, DFIR, logging/monitoring/threat hunting, Cloud, Containers, Basic, Building a Lab, Career, and Classes/Training; original external URL tokens and explicit anchor names are regression-checked.
- Docsify configuration repair and narrow search-plugin fixes for empty heading bodies, HTML titles, and explicit-anchor result destinations.
- Internal navigation checks with individual legacy exemptions and stale-exemption detection; read-only CI workflow.
- Parser-generated processing lists and a separate progress ledger that survives regeneration.
- Bounded external availability checks and report-only workflow; archive job planning with separate non-text queues and verified-prior-capture eligibility.

## Measured results

Initial internal errors: 334. After pilot: 305 legacy errors remained. After Cloud/Containers: 296 remained. After the foundations group: 274 legacy error occurrences remain in other pages; managed navigation and all nine migrated pages have zero internal errors. The audit intentionally continues to report that debt.

Current provisional resource candidates: 1,199 PDFs, 1,458 videos, 23 other non-text; 19,066 URLs remain unknown until response/content confirmation. These are source-derived inventory counts, not verified content types or download counts.

Functional tests exercise the actual checked-in Docsify compiler and application in jsdom under `/docs/`, sidebar/deep routing, and distinct search phrases. This is not native-browser visual QA or a production deployment check.

## Remaining work

- Continue migrating remaining pages and retiring their legacy-error entries in reviewable groups. Pilot browser review, Cloud/Containers, and the four-page foundations group are complete.
- Configure Browsertrix on the available Docker runtime and choose a durable archive destination; implement the enforced capture adapter, article-image filtering, WARC verification, offline replay, and storage/retrieval pilot. The archive policy file describes intent, not implemented enforcement.
- Run external batches with evidence-aware capture/queue routing. No full external validation or web capture has run.
- Implement PDF extraction/OCR, video captions/transcription, other extractors, and search indexing in later processing stages.

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
