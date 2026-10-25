# Generated Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for inline execution, or superpowers:subagent-driven-development if the user explicitly chooses delegation. Steps use checkbox syntax for tracking.

**Goal:** Make the reference easier to navigate and discover through generated indexes and ToCs, and preserve linked pages/content in WARC during external validation.

**Architecture:** Preserve Markdown resources and the existing Docsify website. Parse documents once into a shared navigation model, generate navigation from a small manifest, and validate internal links using renderer-aware anchor handling. Pilot on three pages before repository-wide heading migration.

**Tech Stack:** Proposed Node.js 22+, JavaScript ES modules, Node's built-in test runner, `remark-parse`/`unified`, and `github-slugger`; retain the checked-in Docsify assets. Pin resolved dependencies with a lockfile. Confirm official package documentation and supported runtime versions before installation.

**Spec:** `docs/superpowers/specs/2026-10-24-generated-navigation-design.md`.

## Execution progress — desktop continuation, 2026-10-25

The unchecked implementation steps below are the original historical plan, not a claim that all work is pending. See `docs/implementation-status.md` for verification and current decisions.

| Task | Current state |
|---|---|
| 1–5 | Restored from the patch; parser, generator, pilot, Docsify, and CI/check tooling verified locally. Desktop review found and corrected filename-case and search-cache bugs. |
| 6 | Partial: external reporting exists; pilot browser review and Cloud/Containers migration are complete. 296 legacy error occurrences remain for later reviewable groups. No broad external validation ran. |
| 7 | Partial: inventory, classification, and offline archive planning exist. Browsertrix capture, enforced filtering/network scope, WARC verification, replay, and durable storage remain pending. Docker is available locally. |
| Later processing | PDF/OCR, captions/transcription, other extraction, and search deployment remain separate future work. |

## Global Constraints

- Headings identify navigable subjects; bullets contain resources.
- ToCs follow document order; the subject index provides alphabetical discovery.
- Generated edits are confined to marked blocks and explicitly generated files.
- Existing URLs and anchors are preserved where practical.
- Maintenance notes remain available but are separate from reader navigation.
- GitHub and Docsify compatibility must be verified rather than assumed.
- External availability failures produce a review report, not resource deletion.
- WARC captures are immutable, indexed, and independently verifiable; a successful HTTP response alone does not establish capture completeness.

## Review Focus

1. Encoded filenames, spaces, ampersands, mixed-case fragments, and same-repository absolute GitHub URLs must resolve accurately (Task 1).
2. Repeated headings, explicit anchors, HTML inside headings, and fenced examples must not produce false targets (Tasks 1 and 2).
3. Missing or repeated generation markers must stop writes; content outside managed regions must remain byte-identical (Task 2).
4. Links correct on GitHub must also reach their intended sections through the checked-in Docsify renderer (Tasks 3 and 4).
5. Existing broken links must not hide new errors or permanently exempt repaired links (Task 5).
6. An HTTP 200 error wall, misrouted PDF/video, missing article figure, unrelated captured image, or undurable archive object must not be reported as compliant preserved content (Task 7).

## Proposed files and responsibilities

| File | Responsibility |
|---|---|
| `package.json`, `package-lock.json` | Pinned tooling and audit/generate/check/test commands |
| `navigation/topics.json` | Canonical pages, categories, aliases, subject selections, ToC depth |
| `navigation/legacy-errors.json` | Explicit pre-existing errors outside migrated scope |
| `tools/navigation/parse.mjs` | Markdown headings, links, explicit anchors, source locations |
| `tools/navigation/resolve.mjs` | Internal URL/path and fragment resolution |
| `tools/navigation/generate.mjs` | Managed ToCs, topic lists, sidebar, alphabetical index |
| `tools/navigation/cli.mjs` | CLI entry point, diagnostics, check mode |
| `tests/navigation/*.test.mjs`, `tests/navigation/fixtures/` | Behavioral fixtures and regression tests |
| `docs/navigation-audit.md` | Baseline findings and migration inventory |
| `docs/navigation.md` | Contributor conventions and commands |
| `docs/maintenance-backlog.md` | Maintenance notes relocated from pilot pages |
| `Draft/Subject_Index.md` | Generated alphabetical subjects and aliases |
| `.github/workflows/navigation.yml` | Offline tests and navigation checks on changes |
| `.github/workflows/external-links.yml` | Scheduled, report-only external availability checks |
| `tools/archive/capture.mjs`, `tools/archive/verify.mjs` | Capture orchestration, immutable outputs, integrity/replay checks |
| `navigation/archive-policy.json` | Capture scope, resource bounds, backend configuration without secrets |
| `navigation/archive-captures.jsonl` | Append-only capture provenance, checksums, and durable object references |
| `tests/archive/` | Capture state, retry/resume, verification, and scope tests |
| `docs/archiving.md` | Capture/replay operations, storage requirements, preservation gaps |

Existing content touched: `README.md`, `Draft/README.md`, `Draft/_sidebar.md`, `Draft/index.html`, `Draft/Active_Directory.md`, `Draft/DFIR.md`, and `Draft/L-SM-TH.md`. Other pages migrate only in Task 6 after the pilot is reviewed.

## Task 1: Produce a trustworthy baseline audit

**Interfaces:** `parseDocument(source, path)` returns `{headings, anchors, links}` with line numbers; `resolveInternalLink(root, sourcePath, destination)` returns `{kind, path, fragment}` or a structured diagnostic. `audit(root)` returns deterministic findings with `code`, `path`, `line`, `target`, and `severity`.

- [ ] Verify checkout commit, read any applicable repository instructions, and inventory all navigation surfaces. Record the inspected commit in `docs/navigation-audit.md`.
- [ ] Add failing parser/resolver fixtures for named HTML anchors, malformed anchor markup, duplicate headings, inline HTML headings, nested/reference-style links, fenced code, encoded paths, case-sensitive filenames/fragments, and same-repository absolute links. Assert exact source locations and resolved destinations.
- [ ] Run `node --test tests/navigation/parse.test.mjs tests/navigation/resolve.test.mjs`; confirm failures before implementing the interfaces.
- [ ] Implement parser/resolver and `node tools/navigation/cli.mjs audit --root . --format json`. Treat links to directories as a separate case: valid GitHub directories do not automatically imply valid Docsify routes. Exclude external URLs from offline checks.
- [ ] Re-run fixtures, then audit the repository. Save counts and representative confirmed findings to `docs/navigation-audit.md`; distinguish broken targets, coverage warnings, duplicates, and editorial notes. Do not claim every repeated destination is wrong.
- [ ] Commit the audit/tooling task after its tests pass.

## Task 2: Generate navigation deterministically

**Files:** Create the manifest, generator, generator tests, and subject index; add managed blocks to root/site homepages. Sidebar becomes a fully generated file with a provenance comment.

**Interfaces:** `loadManifest(path)` validates schema version 1; `generate(root, {check})` returns `{changedPaths, diagnostics}`. CLI: `generate` writes; `check` compares without writing and exits nonzero on stale output.

Manifest shape: `{version: 1, pages: [{path, title, category, aliases: [], tocDepth: 3, subjects: [{label, fragment, aliases: []}]}]}`. Page paths are repository-relative; fragments refer to inventoried targets. Allow explicit landing pages for directory topics; never guess an `index.md`/`README.md` route. Seed page entries from existing navigation, checking targets. Alias labels may share a destination; duplicate canonical page records are errors.

- [ ] Add failing fixtures for stable document-order ToCs, case-insensitive alphabetical subject sorting with deterministic ties, alias targets, punctuation escaping, and differing repository/site-relative links.
- [ ] Add tests asserting missing/duplicate markers fail before any writes, fenced headings are excluded, external content is untouched, a second generation produces zero changes, and check mode never writes.
- [ ] Run `node --test tests/navigation/generate.test.mjs`; confirm failures, implement the manifest validation and generator, then rerun to pass.
- [ ] Use `<!-- nav:topics:start -->` / `<!-- nav:topics:end -->` and `<!-- nav:toc:start -->` / `<!-- nav:toc:end -->` blocks. Validate all planned edits before writing any. Preserve text outside blocks including line endings.
- [ ] Generate topic navigation for both homepages and the sidebar plus `Draft/Subject_Index.md`. Pilot subjects may be indexed first; mark coverage explicitly rather than suggesting completeness.
- [ ] Run generate twice and compare outputs; run check and all navigation tests. Commit.

## Task 3: Migrate the three pilot documents

**Files:** Modify `Draft/Active_Directory.md`, `Draft/DFIR.md`, `Draft/L-SM-TH.md`; update manifest and maintenance backlog.

**Interfaces:** Uses parser inventory and generator from Tasks 1–2. No new resource schema.

- [ ] Capture each pilot's existing explicit anchors and resource destinations as regression fixtures. Distinguish navigation-only anchors from content anchors and map each to its intended subject.
- [ ] Add failing tests asserting every managed ToC destination exists, retained legacy anchors resolve, subject entries point to content rather than old mini-ToCs, and the multiset of resource destinations is unchanged.
- [ ] Convert navigable subject labels to correctly nested headings, keeping resource bullets beneath them. Preserve explicit legacy anchors at meaningful targets; repair malformed anchor tags and ambiguous collisions deliberately. Replace manual ToCs with managed blocks. Do not promote every resource-type label into a global subject.
- [ ] Correct navigation labels and nesting, relocate maintenance notes with original page/section attribution, and add focused related-section links where there is an evidenced connection.
- [ ] Run generation and all tests. Inspect rendered headings, ToCs, and anchor destinations on GitHub-compatible output and local Docsify; record any remaining renderer differences.
- [ ] Commit the pilot and review its diff before extending heading conventions elsewhere.

## Task 4: Repair and verify Docsify navigation/search

**Files:** Modify `Draft/index.html`; add `tests/navigation/site-config.test.mjs` and renderer fixtures.

**Interfaces:** Consume generated sidebar/routes and pilot anchors. Retain local Docsify/search assets and existing site base paths.

- [ ] Add a failing configuration regression test that evaluates inline configuration in an isolated window object: no undefined identifiers, one effective configuration, preserved `loadSidebar`, `homepage`, and search settings.
- [ ] Run `node --test tests/navigation/site-config.test.mjs` and confirm the current source fails; then consolidate configuration and use a string value for automatic search paths. Avoid unrelated asset upgrades.
- [ ] Serve `Draft` locally and verify sidebar routing and fragment behavior with the actual checked-in renderer. Check explicit anchors and duplicate headings rather than assuming GitHub equivalence.
- [ ] Test searches for one distinctive existing phrase from each pilot page; each result must navigate to the relevant content. If heading-depth limits prevent useful matches, adjust search indexing depth and verify result volume before retaining the change.
- [ ] Repeat with the site mounted under `/docs/`, refresh a deep route, and check browser errors. Record tested URLs and observed results. A source fix does not prove the deployed site is fixed.
- [ ] Run tests and navigation check, then commit.

## Task 5: Enforce correctness without hiding legacy debt

**Files:** Create baseline, workflow, contributor documentation, and CLI enforcement tests; update `CONTRIBUTING.md`.

**Interfaces:** `check` exits 1 for broken managed navigation, stale generated output, new internal errors, or obsolete baseline entries. Legacy error keys contain source path, exact target, diagnostic code, and review reason, excluding unstable line numbers.

- [ ] Add failing tests for a new broken link, an unchanged legacy failure, a repaired legacy link with a stale exemption, and a broken manifest subject target. Assert expected exit codes and diagnostic locations.
- [ ] Implement baseline comparison. Permit only existing errors outside migrated scope; managed output and pilot documents must have no baseline exemptions.
- [ ] Add npm scripts `nav:audit`, `nav:generate`, `nav:check`, and `test`. Document one standard contributor command sequence and how to add an indexed subject or alias.
- [ ] Add pull-request/push CI with read-only permissions: install from lockfile, run tests, and run check. Pin action versions to reviewed full commit SHAs at implementation time. Do not give untrusted pull requests write credentials.
- [ ] Document authoritative versus generated files and how baseline debt is retired. Run the same commands locally as CI; commit.

## Task 6: Roll out and add external availability reporting

**Files:** Remaining Markdown pages as selected by audit; manifest; `tools/navigation/external-links.mjs`; external-link tests/workflow; audit report.

**Interfaces:** `checkExternal(urls, options)` returns per-URL status evidence, with bounded concurrency, timeout, retry limit, and timestamps. It never edits source documents.

**Amended dependency:** Implement Task 7 before broad external validation. External validation routes every unique referenced HTTP(S) URL to web capture, a non-text processing queue, or type confirmation and consumes capture response evidence where suitable, instead of performing an unnecessary second full download. Keep lightweight checks for URLs that cannot be captured. The 15-second availability timeout below is not a browser/media capture limit.

- [ ] After pilot review, migrate remaining pages in independently reviewable groups. For each group, preserve resource destinations and legacy anchors, update subjects, run generator/check/tests, retire repaired baseline entries, and commit.
- [ ] Add deterministic mocked tests for 200, redirects, 404/410, 403, 429, timeouts, and HEAD rejection with GET fallback. Treat rate limits, access restrictions, and temporary errors as uncertain; preserve original and final URL separately.
- [ ] Implement report-only checking: HTTPS/HTTP only, public destinations only, no credentials, no private/reserved network addresses including after redirects, concurrency 4, timeout 15 seconds, at most 2 attempts and 5 redirects. Tests cover redirect revalidation and bounds.
- [ ] Add a weekly/manual read-only workflow producing a downloadable report, without auto-deleting links, posting issues, or committing content. Exclude local/internal URLs and deliberate examples. Keep this workflow independent from pull-request navigation checks.
- [ ] Finish `docs/navigation-audit.md` with remaining known debt and measured results. Verify the completion criteria below before claiming repository-wide completion.

## Task 7: Preserve referenced content as validation proceeds

**Execution order:** After the baseline URL inventory in Task 1 and before the bulk external validation in Task 6. Numbering preserves the original plan's task references.

**Files:** Archive orchestration/verification modules, policy, append-only capture manifest, tests, and archiving guide listed above. Add archive-object patterns to `.gitignore` after inspecting existing rules.

**Interfaces:** `captureUrl(job, policy)` returns a capture attempt; `verifyCapture(attempt)` returns integrity and replay findings; `persistCapture(attempt, destination)` returns verified durable object references. `job` includes the original references and fragment-free fetch URL. Capture records include `captureId`, `sourceReferences`, `originalUrl`, `requestedUrl`, `finalUrl`, `redirectChain`, `capturedAt`, `httpStatus`, `contentType`, `warcRecordIds`, `objects`, `toolVersion`, `availabilityState`, `captureState`, `replayState`, and `storageState`. Each object includes `uri`, `bytes`, and `sha256`. Failed attempts preserve provenance without invented object references.

- [ ] Inventory every unique referenced HTTP(S) URL, retaining all repository source locations. Strip only fragments for fetch deduplication; retain queries and originals. Label examples/non-content references and document any intentional non-capture decisions rather than silently omitting them.
- [ ] Add failing tests for duplicate references with different fragments, distinct query strings, redirect provenance, HTTP 200 challenge pages, truncated payloads, retry/resume, unchanged prior durable captures, checksum mismatch, failed storage upload, and private-address redirects/subresources. Assert that availability, capture, replay, and storage outcomes remain independent.
- [ ] Run `node --test tests/archive/*.test.mjs` to confirm failures. Implement orchestration with a pinned Browsertrix container for HTML and a WARC-capable HTTP path for direct files. Reuse maintained capture implementations; do not hand-roll a WARC writer. Verify current official interfaces before pinning versions.
- [ ] Use `.warc.gz` and CDXJ outputs; permit optional WACZ replay bundles. Maintain per-record provenance and whole-object SHA-256 checksums. Write to unique immutable capture directories and finalize manifest records only after object verification. Failed attempts remain visible. Keep raw archives outside Git history.
- [ ] Scope HTML captures to referenced pages, article text, and required reading/rendering assets. Include images only when part of the article; filter unrelated images, advertising/tracking assets, and standalone media. Queue PDFs/slides, videos, audio, binaries, and other non-text resources in separate inventories for later processing; do not download them in the web-page pipeline. Preserve relevant landing pages as web content. Add fixtures asserting inline article images are preserved and unrelated image/media requests are excluded. Use an isolated, unauthenticated profile; enforce public-network restrictions at the browser/container network layer, including dependencies and redirects. Use per-host pacing and configurable bounds. Initial pilot defaults: 2 browser workers, 1 concurrent navigation per host, 120-second page budget, and a 1-GiB total pilot storage ceiling. Limits produce partial/deferred outcomes, not false success.
- [ ] Implement verification for readable WARC records, recorded digests, payload lengths, expected content type, article text/figures, filtering, and replay. Use Browsertrix replay QA for browser captures and byte/hash checks for direct files. Keep `not-tested` separate from replay success. A video landing page or GitHub page is preserved only as web content; do not claim underlying media/source preservation or schedule it automatically.
- [ ] Run a bounded pilot covering static HTML with inline figures and unrelated images, JS-rendered HTML, PDF/video queue routing, redirects, fragment duplicates, a page with excluded embedded media, and inaccessible content. Replay representative captures with live network access blocked. Document observed bytes, filtering results, failures, missing dependencies, and replay results. Check host capacity before any container installation or capture.
- [ ] Supply durable archive storage before the full run. Keep destination credentials out of Git. Verify stored object checksums and retrieval; keep a second copy or recoverable backup before declaring preservation complete. CI artifacts alone are not permanent storage. Do not publish to a third party automatically.
- [ ] Connect capture queue/state to external validation, with resumable batches and report categories for verified, partial, failed, inaccessible, deferred, and not-yet-attempted URLs. Do not delete old snapshots or overwrite prior records. Document refresh policy separately from the initial full capture.
- [ ] Run all archive/navigation tests and managed navigation checks; commit code, configuration, documentation, and small provenance metadata only. Report capture coverage honestly: every inventory item accounted for does not mean every item was successfully archived.

## Completion criteria

- All generated navigation resolves to intended content; full rollout has no unresolved internal navigation defects hidden by baseline entries.
- Generator is deterministic and a second run has no diff; check mode never writes.
- Existing resource destinations are preserved except documented intentional corrections.
- GitHub-compatible rendering and checked-in Docsify routing/search have explicit verification evidence.
- Internal CI and external availability reporting are separate.
- Contributor instructions make ordinary link additions possible without manually editing generated indexes.
- Every referenced URL is accounted for in the capture inventory; archive coverage and unresolved preservation gaps are reported separately.
- Captures declared preserved have readable WARC records, checked integrity, explicit replay/content verification, and verified durable storage. Prior captures remain available.

## Self-review and handoff

The plan covers topic indexes, ToCs, selective subjects/aliases, maintenance notes, compatibility, legacy debt, external reports, and the maintainer's WARC preservation amendment, narrowed to web content with images only when part of articles. Interfaces and command names are consistent across tasks. Six failure classes above have named test ownership. The approved design and amendment are recorded beside this plan. Proposed runtime/dependencies and exact heading/category choices remain engineering choices, not additional user requirements. Full-crawl durable storage remains a deployment input; the bounded pilot does not depend on that choice.

No implementation, remote push, PR, or deployment has been performed as part of producing this plan. Recommend inline execution: the tasks share the parser and generator interfaces, and the pilot should inform later migration. Review the plan before beginning implementation.

## Non-text inventory amendment and implementation delta

The maintainer requested separate lists for PDFs, videos, and other non-text resources for later processing and making them searchable. This supersedes earlier instructions to capture direct PDF payloads now. WARC capture remains for web-page text/HTML and article-associated images/assets. Non-text inventory creation is authorized; bulk acquisition, OCR/transcription, and search deployment are later work.

Initial provisional source-scan deliverables exist in `docs/inventories/{README.md,pdfs.md,videos.md,other-nontext.md,resource-inventory.jsonl}`. They are candidates inferred from URLs, not MIME-verified resources. Keep unknown URLs in the shared inventory for later classification. The scan is an analysis artifact, not the planned production parser.

Add to Task 1:
- [ ] Reconcile initial inventories with `parseDocument`, including reference-style links, nested destinations, bare examples, and embedded-resource relationships. Use confirmed response metadata where available; unknown or conflicting evidence stays unverified. Preserve all source references and query strings.
- [ ] Add tests for extensionless PDFs, video pages/playlists, direct media, mislabeled extensions, redirects changing type, and article inline images versus standalone images. Assert that candidates are never reported as confirmed solely from a suffix.

Add to Task 7:
- [ ] Implement `classifyResource(reference, responseEvidence)` returning `{type, confidence, evidence, processingQueue}`. Types include web page, PDF, video, audio, slides/document, image, archive/binary, dataset/capture, and unknown. Generate PDF/video/other views from one inventory rather than maintaining three copies by hand.
- [ ] Route non-text targets and discovered article embeds into their appropriate pending queues, without downloading their bodies in the article pipeline. Keep article image dependencies attached to their parent page; do not queue them as standalone processing jobs by default.
- [ ] Keep stable IDs, URL/title, source paths/sections, classification evidence, verification/processing status, and links between landing pages and underlying resources. Later extraction records include provenance, tool/version, hashes after acquisition, and page-number/timestamp text segments for search.
- [ ] Report inventory coverage separately from acquisition, extraction, and search-index coverage. Do not mark pending PDFs/videos as capture failures or successfully searchable content.

Future processing directions: PDF text extraction with OCR fallback; existing video captions before transcription where suitable; type-specific extraction for other formats. Select and implement these workflows separately after inventory review.
