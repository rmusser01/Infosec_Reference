# Archive implementation record

Plan: `docs/superpowers/plans/2026-10-24-generated-navigation.md`, Task 7 and its non-text amendment. Starting checkpoint: `804a0d9`, branch `codex/generated-navigation`.

The approved archive design is already recorded beside the plan; this continuation implements it in the requested checkout. The durable destination remains unspecified. A local bounded pilot is authorized independently; choosing a runtime did not authorize a full crawl or publication. The subsequent user amendment below authorizes source-URL submissions to Internet Archive.

## Implementation sequence

1. Enforce public destinations, response types and article-image scope before bodies reach the recorder.
2. Connect bounded Browsertrix discovery/capture with independent integrity/content/replay outcomes and append-only provenance.
3. Verify immutable object copies/retrieval and preserve resumability without treating local output as durable preservation.
4. Exercise controlled fixtures and a small public pilot, run the complete suite, obtain one fresh implementation review, and record limitations.

Scope reaches the existing planner, new capture/proxy/verification modules, policy/runtime configuration, npm commands, archive tests/fixtures, and contributor/status documentation. Raw output stays under ignored `archive-data/`; no source reference is deleted or silently marked preserved.

Pre-flight: inventory/planner jobs supply fragment-free URLs and source references; capture must retain original references and query distinctions. External classification evidence is advisory; response MIME and access walls must be checked again during capture. Existing preservation skips require verified integrity/replay/durable-storage metadata, not HTTP success.

Ruling: retain the approved local checkout and direct documentation ledger — the portable migration explicitly targeted this checkout and prior execution used this record format — an additional worktree/ledger would split recovery state.

Ruling: add an isolated filtering proxy alongside Browsertrix — seed validation and browser URL blocking cannot enforce MIME restrictions on redirects/subresources before download; the proxy must pin public addresses and reject non-text bodies — the extra pinned runtime is necessary for the existing public-network and non-text scope requirements.

Runtime preflight: Docker client/server 29.8.1, arm64, approximately 133 GiB host free and 16 GiB Docker memory. Selected Browsertrix 1.15.0 from the official release/API documentation; proxy and verifier dependencies are pinned separately. Capture output budget remains 1 GiB. Installation bytes are separate from capture bytes.

## Implementation and verification — 2026-10-25

- Installed the official Browsertrix 1.15.0 and mitmproxy 12.3.0 images, and built the pinned warcio 1.8.1 proxy/verifier image. Capture/replay containers use actual recorded image IDs. The browser mounts only the public proxy certificate; its private key stays in the ignored proxy state directory. No host trust settings changed.
- Added the capture/proxy/driver/verifier, immutable-copy adapter, offline recheck command, response-evidence reuse in archive planning, and append-only metadata. Non-text references/embeds keep parent provenance and processing queues; no media payload, PDF/OCR, transcript or extracted-content indexing pipeline ran.
- Discovery/capture and required-image decoding use actual Chromium; warcio verifies gzip/WARC digests/lengths; offline Browsertrix QA verifies article text and figure responses. A complete capture remains distinct from temporary storage, verified copies, and durable preservation. Raw archives remain ignored.
- RED→GREEN regressions cover article/figure scope, soft error walls, public DNS including IPv6 translation addresses, redirect MIME bodies, missing/undecodable figures, requested-versus-final metadata, pending non-text routing, content/integrity/replay independence, immutable copying/checksum/backup failures, policy limits, recheck evidence retention, and capture-response reuse in planning.

### Measured pilots

The final controlled Docker pilot passed all eight cases. Static HTML, a native lazy figure, JavaScript-rendered HTML and a redirected article each have complete capture plus verified WARC integrity and offline replay. Their WARCs retain the required figure and exclude navigation/advertising images, video and PDF bodies. The HTTP-200 challenge is inaccessible; the private redirect and header-confirmed PDF are deferred; the media-bearing redirect is blocked and fails without producing archive objects. All outcomes remain temporary. Total local output: **543,222 bytes** across the eight attempts. The four successful attempts used 112,867 / 119,178 / 122,313 / 117,583 bytes and contain 4 / 4 / 5 / 5 verified WARC response/resource records. A separate current-adapter private-redirect run confirmed the final certificate-only mount and connection guard.

Public pilot (two existing repository references):

| Reference | Capture/content | Integrity | Offline replay | Storage | Local output | Verified archive-object bytes |
|---|---|---|---|---|---|---|
| `https://danluu.com/sounds-easy/` | Complete/verified | Verified | Verified | Temporary | 16,291,016 | 920,455 |
| `https://eli.thegreenplace.net/2012/08/07/fundamental-concepts-of-plugin-infrastructures` | Partial/needs review | Verified | Verified | Temporary | 776,998 | 692,073 |

The first public run exposed that QA comparison evidence lives in WARC pageinfo records, and redirected text metadata uses the requested URL. Both received regressions and corrections; the Dan Luu recheck appends a verified outcome while retaining its original not-tested record. Its early local-output count includes an isolated browser profile that later retrieval excludes. Eli remains partial because strict source-article versus archived-text comparison does not match; replaying the same page successfully does not resolve that content check. No partial was silently promoted. Neither public reference qualifies as permanently preserved.

Final checks: **98/98** Node tests passed on Node.js 24.18.0 (the proxy-policy wrapper additionally runs five Python standard-library cases). Two real warcio corruption/truncation/length tests pass offline without warnings. Navigation remains 102 pages / 29,164 links / zero errors, with 15 orphan and 21 repeated-destination warnings. Formatting and `git diff --check` pass. Temporary archive containers/networks were removed; installed images and ignored local evidence remain.

### Review corrections and decisions

The one fresh review found four Important issues. All four have RED→GREEN regressions and are fixed: temporary copies cannot become durable verified storage; ordinary HTTP-200 unavailable/rate-limit/not-found walls cannot become complete articles; rechecks retain filtering/budget failures; redirect bodies obey MIME policy. Further focused checks preserve CDXJ-relative object paths, reject failed image decoding, and report header-confirmed PDFs as deferred processing rather than capture failures. No review minor was deferred.

Ruling: use one sequential browser worker rather than the proposed two-worker pilot default — this stays within the intended concurrency ceiling and avoids concurrent seed navigation on a host — the cost is lower throughput. The policy records and enforces the supported setting.

Ruling: classify uncertain layouts, image redirects, unknown third-party rendering dependencies and strict text mismatches conservatively — preserving known text/figures is preferable to claiming an unverified complete article or broadening collection — the cost is more manual review, including the Eli reference. Known error/tracker signatures are heuristics and need wider calibration before scale.

Ruling: retain a separate verified-copy state and require explicit durable configuration plus distinct mounted filesystems before emitting verified storage — two temporary directories are not a preservation destination — filesystem snapshots and remote object stores require a separate supported durability arrangement. No permanent storage was inferred or configured.

Ruling: count exact offline article-text replay and required figure responses while retaining failures for intentionally excluded trackers — those trackers are outside article preservation scope — this does not establish visual/pixel fidelity or minimal dependency correctness on every site.

### Review boundaries

Each behavior the reviewer set aside was assessed by the coordinator:

- Navigation focus items 1–5: prior native reviews plus the full current suite/check remain valid; no navigation source changed. Production routing/cache remains unverified.
- Complete Docker fixture result: the coordinator ran and read the final eight-case sweep, plus the final private-redirect check. Earlier partial logs were not used as proof of completion.
- Adversarial live DNS rebinding/private subresources/isolation: code, pinned-DNS cases and the actual private-redirect guard were exercised; an exhaustive network penetration test was not performed. Residual platform/network behavior requires validation before a broad crawl.
- Independent WARC corruption/replay execution: the coordinator ran actual warcio corruption/truncation tests and network-disabled Browsertrix QA; the reviewer did not repeat the containers. This is integration evidence, not a second independent preservation audit.
- Public-pilot visual fidelity: not claimed; text replay and required-image decoding/response evidence were checked. Pixel/layout fidelity still needs visual sampling before scale.
- Durable storage/backup independence/recovery: explicitly pending; temporary/copied states cannot qualify for initial-capture skips. Full collection preservation must wait for configured persistent storage and recovery/replay checks.
- Final docs/whole-task acceptance: the coordinator updated status, commands and pending work. The bounded implementation/pilot is delivered; broader validation/full preservation is not marked complete.
- Hostile local filesystem races, container escapes and upstream supply-chain auditing: outside this single-operator bounded pilot; inputs/outputs are confined, images/versions are pinned, and containers lack host sockets/capabilities. No claim of an exhaustive platform/security audit is made.
- Formatting/full navigation suite: the coordinator ran both; passing evidence is recorded above.

## Remaining work

The following paragraph describes full-collection prerequisites; the user amendment below authorizes continued local change batches independently.

The user chose local continuation without a durable destination or backup. Continue bounded local change batches without assuming permanent preservation. Choose persistent storage, verify object recovery/replay, calibrate more content/layout/figure/error cases, and only then design/run wider coordinated batches. Remote object-store upload and full-run scheduling are not implemented. Separate media acquisition/extraction/indexing remains future work. No remote push occurred.

## Compact retention and change-triggered Wayback amendment — 2026-10-25

User scope: keep text and article figures locally, discard duplicate bundles and temporary QA archives. Trigger archival from new links in repository changes/PRs against main, rather than browsing. Submit source URLs to Internet Archive and expose confirmed snapshot links for readers. Existing `master` is supported alongside `main`; no branch rename was inferred.

Ruling: reuse original compressed WARCs/CDXJ, extracted article JSON text and a hashed object manifest with the actual offline QA result. WACZ remains a temporary QA input only; discovery, replay archives, profiles/logs and proxy CA state are deleted. Rechecks verify the original objects/content again and explicitly identify recorded offline QA instead of claiming a fresh browser replay. Original attempt records remain historical. Manifest publication/replacement is atomic, and the original attempt is saved before compaction.

The two prior public pilots were reverified before compaction, shrinking from **17,096,264 to 207,995 bytes** including metadata. Primary WARC verification and recorded QA still pass; Dan remains complete and Eli remains partial. Twelve old synthetic/probe runs discarded **4,531,225 bytes**; final synthetic runs now remove payloads in `finally`, retaining the result summary. No duplicate WACZ, replay WARC or proxy private-key files remain in the local archive output.

`archive:changes` compares shared-parser resource sets against a Git base, optionally including the working tree, preserving queries and all source references. Repeated/moved/fragment-only links, images, code examples and generated/developer docs do not produce jobs. Bounded execution reuses rehashed local captures, preserves non-text queues, saves Wayback job IDs before polling, and generates `docs/archives/README.md` from confirmed successes only. Pending jobs resume without duplicate POSTs; HTTP429 and source-DNS failures retain retry times; uncertain submissions require review. Future retry times do not consume a ready batch slot. Fixed inputs/catalog outputs use the existing repository symlink guard.

The anonymous protocol was checked against Internet Archive's official extension and exercised live. Confirmed catalog entries now include Dan Luu's article and the GitHub exploit-development lab write-up. Of the four added/corrected resource URLs relative to `master`, the GitHub write-up has complete local capture/integrity/offline replay and a confirmed Wayback snapshot. AllenGeer and blogs.360.cn do not resolve and remain deferred; the VSecurity PDF remains queued rather than downloaded, and its Wayback submission is deferred on DNS failure. Original resource links remain unchanged. The inventory plan accounts for **21,738** URLs: two complete local captures, one partial, three deferred and 21,732 not yet attempted; **zero durably preserved**. Known HTML evidence routes three to web capture, with 19,054 type-confirmation / 1,200 PDF / 1,458 video / 23 other non-text jobs.

The read-only workflow submits up to ten added URLs on PRs or pushes to main/master, plus manual dispatch. It has no secrets or privileged PR execution, writes a job summary and uploads receipts, and does not commit changes or retain local WARCs. Authors run the local command for compact text/image retention and commit receipts/catalog for lasting discovery; CI artifact retention is not permanent reference storage. Hosted execution remains unverified until pushed.

Final review: one fresh reviewer found three Important issues, all accepted and fixed in one RED→GREEN pass: deferred-job resume/starvation, interrupted manifest replacement, and symlinked fixed catalog/metadata paths. A live DNS-failure case additionally received RED→GREEN retry coverage. No Critical or Minor finding was deferred.

Final review boundaries: hosted GitHub execution was not exercised; only its configuration and local comparison/submission path were checked. The coordinator ran actual Docker QA and anonymous Wayback requests independently of the reviewer's mocked-network tests. Primary-object rechecks preserve recorded QA rather than rerunning deleted replay artifacts. No broad/full-corpus crawl, durable backup/recovery qualification, media extraction or production site deployment is claimed.

Final: fixed deferred resume/starvation — `resume plans include due rate-limited receipts and do not let future jobs consume the batch` RED→GREEN; suite 105/105.

Final: fixed interrupted manifest replacement — `interrupted final manifest replacement preserves the published manifest after QA cleanup` RED→GREEN; suite 105/105.

Final: fixed unsafe fixed paths — `change CLI rejects symlinked catalog and metadata paths without touching unrelated files` RED→GREEN; suite 105/105.

Final verification: **105/105** Node tests pass, including five Python policy cases through the wrapper. Two actual warcio corruption/truncation/length tests pass offline. All eight real Docker fixture cases pass with payload cleanup; actual public captures exercise the final compact lifecycle. Navigation audits 102 pages / 29,165 links with zero errors and unchanged 15 orphan / 21 repeated-destination warnings. Formatting and `git diff --check` pass. Three retained public archives pass current primary-object integrity/content rechecks and retain their recorded QA outcomes; Eli remains partial.

## Next local batch — 2026-10-25

User authorized the next local batch with text/article figures retained and source URLs submitted to Internet Archive. Batch `2d5228a9-5892-4a7c-8579-a07cc585fefa` selects the next three unattempted webpage candidates in stable inventory order. It retains about **2.0 MB** including provenance and summaries; verified current objects total **1,457,515 bytes**, with 38,080 extracted text characters and 40 selected article images.

| Original reference | Local content / integrity / offline replay | Capture flag | Article figures | Confirmed Wayback timestamp |
|---|---|---|---|---|
| `http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html` | Verified / verified / verified | Complete | 7 | `20261025223550` |
| `http://0x90909090.blogspot.fr/2015/07/no-one-expect-command-execution.html` | Verified / verified / verified | Partial: excluded favicon requests | 1 | `20261025223614` |
| `http://0xbaadf00dsec.blogspot.com/2016/01/reverse-engineering-online-games.html` | Verified / verified / verified | Partial: excluded favicon requests | 32 | `20261025223747` |

All three confirmed links appear in `docs/archives/README.md`. The two `.fr` originals redirect to `.com` URLs; receipts preserve the original reference and use the actual confirmed canonical URL for the snapshot destination. Each source URL was submitted once; later checks resumed its existing job ID.

The batch exposed three small compatibility defects, fixed with RED→GREEN evidence:

- Legacy Blogger uses a single explicit `itemprop="description articleBody"` element, without article/main tags. The extractor now recognizes a unique articleBody fallback, with the existing article/figure exclusions and driver lazy-image waits. The extraction regression fails before the fix and passes after it; an actual Blogger-shaped Docker fixture passes text, figure, WARC and offline replay checks. Multiple ambiguous articleBody-only layouts remain review cases.
- Internet Archive may report a successful job under the final redirected URL. The client accepts a different identity only when it matches the final URL observed locally, retains that identity as `archivedUrl`, and renders the canonical destination in the catalog. Tests reject unrelated or unobserved identities. Both actual redirected jobs were confirmed by ID without another POST.
- Browsertrix can omit redirect bodies while retaining their original Content-Length headers. The strict verifier correctly rejected those recorded responses. Capture now starts at the validated final HTTP(S) URL after discovery, preserving original URLs and redirect chains in metadata. Recheck uses the recorded capture seed for text identity. The actual nonempty-redirect Docker fixture and canonical recheck regression both failed before the change and pass after it. Digest/length/truncation checks remain unchanged and their two offline corruption tests still pass.

After all current captures passed fresh primary/content/recorded-QA rechecks, 295,186 bytes of redundant failed retry payloads were removed only after comparing their article text and selected image URLs exactly with verified replacements and rehashing the objects. Their local manifests identify the verified replacement and discarded-superseded storage; original execution/hash receipts remain historical. Failed/deferred provenance remains visible. No WACZ bundles, replay archives, fixture payloads or temporary proxy private keys remain.

Verification: **107/107** Node tests pass, including wrapped Python policy checks. Real Docker Blogger and nonempty-redirect cases pass, including cleanup and compact-object rechecks; two offline warcio corruption/truncation tests pass. Navigation remains 102 pages / 29,165 links / zero errors, with unchanged warnings. Formatting and `git diff --check` pass. Fresh focused review of Blogger extraction/driver changes found no actionable issue; the later canonical-identity and capture-seed corrections were coordinator-verified through their failing/passing regressions, actual jobs and actual Docker fixture, rather than independently re-reviewed. The prior full eight-case sweep is historical; this batch reran the two relevant integration cases.

Inventory accounting now has three complete, three partial, three deferred and 21,729 unattempted URLs, with zero durable preservation claims. Six observed HTML pages route to web capture; 19,051 remain type-confirmation jobs, alongside the unchanged non-text queues. Five total Wayback snapshots are confirmed; three older DNS failures remain deferred. No push, hosted-CI execution, full collection run or durable backup qualification occurred.
