# Archive implementation record

Plan: `docs/superpowers/plans/2026-10-24-generated-navigation.md`, Task 7 and its non-text amendment. Starting checkpoint: `804a0d9`, branch `codex/generated-navigation`.

The approved archive design is already recorded beside the plan; this continuation implements it in the requested checkout. The durable destination remains unspecified. A local bounded pilot is authorized independently; no full crawl or publication is authorized by choosing a runtime.

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

No durable destination or backup was supplied; an optional storage-choice question remains pending. Finish the local pilot without assuming a permanent destination. Choose persistent storage, verify object recovery/replay, calibrate more content/layout/figure/error cases, and only then design/run wider coordinated batches. Remote object-store upload and full-run scheduling are not implemented. Separate media acquisition/extraction/indexing remains future work. No remote push or publication occurred.
