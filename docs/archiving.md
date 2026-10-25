# Preservation and non-text processing

Preserve web articles and article figures in WARC. Queue PDFs, videos, slides, audio and other non-text resources for later acquisition/extraction. Saving a video landing page does not preserve its media. No bulk media acquisition, OCR, transcription or extracted-content indexing has run.

## Commands

- `npm run resources:generate`: regenerate the shared inventory and separate non-text views.
- `npm run external:check -- --limit 100 --offset 0 --output external-report.json`: bounded availability evidence; one batch is not a full audit.
- `npm run archive:plan -- --evidence external-report.json --output archive-plan.json`: route inventory rows using optional response evidence. Planning does not capture or verify bytes.
- `npm run archive:pilot -- --url https://danluu.com/sounds-easy/ --limit 1`: capture an existing inventory URL. Without `--url`, select rows using `--offset`; `--limit` defaults to three and permits 1–10 rows.
- `npm run archive:verify -- archive-data/PILOT/ATTEMPT`: recheck existing objects and offline replay evidence, appending new metadata without refetching or replacing earlier records.

## New links in changes and PRs

The trigger is a repository change, not opening a page in a browser. Compare the resource links in `README.md` and `Draft/**/*.md` against a Git base. Generated indexes, image references and code examples are excluded. Fragment-only changes and moved/repeated links do not create new jobs; distinct queries do. Deleted links are not captured.

```sh
# Preview uncommitted and committed additions relative to main, without network requests.
npm run archive:changes -- --base main
# Capture locally and submit up to three added URLs to Internet Archive.
npm run archive:changes -- --base main --execute --limit 3
# Resume existing Wayback jobs without another submission or local recapture.
npm run archive:changes -- --resume --execute --wayback-only
```

This checkout currently names its base branch `master`, so substitute `--base master` for the `main` examples until renamed. The workflow accepts both branch names.

Use `--base HEAD` (the default) for uncommitted changes, or `--base BASE_SHA --head HEAD_SHA` for committed changes. Repeat the same comparison to process more links, at most ten per batch. Verified existing local captures are rehashed and reused without claiming durable preservation. Partial/failed attempts remain visible and are not automatically retried; use `archive:pilot -- --url URL` after reviewing the reason. Non-text resources keep their processing queues; they do not become local article captures.

Save Page Now is a separate public submission of the source URL, not an upload of the local WARC. Its capture scope is controlled by Internet Archive and is independent of local article-only filtering. The anonymous protocol follows the [official Internet Archive extension](https://github.com/internetarchive/wayback-machine-webextension/blob/master/webextension/scripts/background.js). No account keys or browser cookies are needed. Submitted job IDs are recorded before polling; a successful status with a matching requested URL (or the final URL observed by local capture) and snapshot timestamp produces a confirmed Wayback URL. Canonical snapshots retain their actual archived URL while the catalog keeps the original repository reference visible. A different URL without local redirect evidence remains unconfirmed. Rate limits retain a retry time, pending jobs resume by ID, and uncertain submissions are not blindly repeated. Review uncertain/failed records before explicitly retrying them. No HTTP-200 login page or pre-existing availability result is treated as a new successful save.

Commit `navigation/archive-captures.jsonl`, `navigation/wayback-captures.jsonl` and the generated [archive catalog](archives/README.md) with the link changes. Readers can use the catalog from the repository README when an original disappears. Local objects remain in ignored `archive-data/`; the catalog does not expose local filesystem links.

The added-link workflow runs on PRs against `main` or `master`, resource changes pushed to those branches, or manual dispatch. It anonymously submits up to ten new URLs and publishes a job summary plus downloadable receipts. It uses read-only repository permissions, no secrets, and no `pull_request_target` execution. CI does not retain local WARCs or commit results automatically: copy the artifact's metadata/catalog back into the PR, preserving any local records, or run the local command before committing. Artifacts expire after 30 days; commit confirmed references for lasting discovery. More than ten links require further local batches. Pending CI jobs require committing their receipts and resuming locally. Workflow execution on GitHub has not yet been tested from this local branch.

## Capture runtime and bounds

Docker is required for capture, not navigation. The desktop continuation installed Browsertrix Crawler 1.15.0 and mitmproxy 12.3.0. `navigation/archive-runtime.json` pins the browser image digest; `tools/archive/Proxy.Dockerfile` pins the proxy base digest and warcio 1.8.1. Actual image IDs are recorded per attempt. Build the proxy/verifier image first:

```sh
docker build -f tools/archive/Proxy.Dockerfile -t infosec-archive-proxy:12.3.0-warcio1.8.1 tools/archive
npm run archive:pilot -- --url https://danluu.com/sounds-easy/ --limit 1
```

Each attempt has a unique ignored `archive-data/` directory. After QA it retains the original compressed WARCs (HTML, article text, selected figures and required rendering dependencies), CDXJ indexes, `capture/article.json` containing extracted article text, and small provenance/QA summaries. Duplicate WACZ bundles, replay archives, discovery output, profiles, logs and temporary proxy certificate/key state are discarded. The local WARC is never uploaded by this command (`publishCaptures: false`); the separately authorized Wayback client submits only source URLs. The proxy CA is trusted only inside capture containers, never installed on the host.

Crawl containers use an internal Docker network without published ports. The sole egress proxy rejects non-public/translation addresses and pins checked DNS answers while retaining upstream TLS verification. These checks cover redirects and dependencies. Only bounded unauthenticated GET/HEAD requests are admitted. MIME checks, including redirect bodies, block non-text payloads before the recorder receives them. Blocked resources retain queue/provenance evidence.

Discovery blocks image bodies and identifies article/main text or a single explicit `articleBody` microdata element, selected image URLs, SVG figures, figure backgrounds and media embeds. Capture admits those article images, including native lazy images, while rejecting unrelated images, frames and media. Scripts/styles/fonts/data requests are conservatively limited to the article origin; known tracking assets are blocked. Unknown third-party rendering dependencies and ambiguous layouts need review. These are DOM/signature heuristics, not a general semantic classifier.

After discovery, capture starts at the validated final HTTP(S) URL. Original URLs and observed redirects remain in provenance. This avoids Browsertrix redirect records whose bodies are omitted but whose original Content-Length remains; strict payload-length checks stay enabled. Rechecks use the actual capture seed recorded in the snapshot for text metadata.

The enforced pilot uses one sequential browser navigation, one navigation per host, at most 120 seconds per crawl/QA phase, and a 1-GiB total batch ceiling shared by discovery/capture/replay. Output uses size-limited tmpfs and explicit streaming retrieval because Docker copy omits tmpfs mounts. Response size, network bytes, request count and proxy metadata are separately bounded. Image installation bytes are outside this capture budget. The CLI is a bounded pilot, not a full-crawl launcher.

## Verification and storage

warcio verifies readable WARC records, recorded digests and payload lengths; gzip trailers and HTTP Content-Length are checked too. Whole objects have SHA-256 checksums. Content verification requires successful HTML, matching archived article text and every selected figure. Browsertrix QA runs with Docker networking disabled, requiring exact text replay plus successful article/figure responses. Intentionally excluded trackers may fail offline; those failures remain visible. This does not test visual fidelity. Filtering/budget failures cannot be cleared merely by rechecking.

Keep availability, capture, integrity/content, replay, local storage and Wayback states independent. A known error/login/rate-limit page is not a complete article. Failed/partial attempts remain visible; retries create new attempts. The initial-capture CLI only skips complete, verified durable captures after rehashing their objects; the change command additionally reuses verified local captures for that change. Preserve original references, fragments and query distinctions. Full inventory accounting is not successful preservation.

`retained.json` is the current compact object manifest; earlier attempt/verification records remain historical. Rechecking hashes all retained objects, verifies the primary WARC again, and compares archived text/figures. It reports `replayEvidenceSource: recorded-offline-qa`: QA ran before cleanup and its result is bound to the retained object hashes. Recheck does not rerun a browser against deleted QA archives. Changed/missing primary objects invalidate integrity and the replay claim. Synthetic runtime tests discard their archive payloads after assertions and keep a summary only.

No durable destination is configured. `--primary PATH --backup PATH` verifies exclusive immutable copies and retrieval checksums, producing `copyState: verified` and `storageState: copied`; this does not qualify for preservation skips. Relative object paths preserve the CDXJ/archive layout. Durable eligibility additionally requires operator-configured `durableDestination` with `primary`, `backup` and `confirmedDurable: true`; this filesystem adapter requires distinct mounted filesystems. It verifies retrieved bytes, not physical backup independence or backup operations. Remote object-store uploads are not implemented. Never designate temporary test directories as durable.

Local change batches may continue now. They report `storageState: local`, not durable preservation. Before a full collection run, choose persistent destinations, verify recovery/replay from stored objects, and size storage with a representative sample. Maintain an independent second copy or recoverable backup. Expiring CI artifacts are insufficient. See `docs/archive-execution.md` for results and unresolved review cases.

## Tests and references

`npm test` includes navigation/archive tests and requires Python 3 for the standard-library-only policy tests. It does not download images or crawl live sites. `npm run archive:test-runtime` separately exercises synthetic static/JavaScript articles, figures versus ads/media, redirects, access walls, private redirects, MIME routing and offline replay through the actual containers. Synthetic URLs are served locally before upstream resolution; private destinations receive no production-guard exception. Run real warcio corruption/truncation tests offline:

```sh
docker run --rm --network none --entrypoint python3 -v "$PWD/tools/archive:/tools:ro" -v "$PWD/tests/archive:/tests:ro" infosec-archive-proxy:12.3.0-warcio1.8.1 -B /tests/verify_test.py
```

Interfaces checked against official sources: [Browsertrix releases](https://github.com/webrecorder/browsertrix-crawler/releases/tag/v1.15.0), [proxy support](https://crawler.docs.browsertrix.com/user-guide/proxies/), [offline QA](https://crawler.docs.browsertrix.com/user-guide/qa/), [mitmproxy hooks](https://docs.mitmproxy.org/stable/api/events.html), and [warcio](https://github.com/webrecorder/warcio/releases/tag/v1.8.1).

## Later search processing

PDFs: extract text with page numbers and OCR when needed. Videos: acquire available captions or transcripts and retain timestamps; add transcription where required. Other formats: confirm the type and route to the appropriate extractor without executing untrusted binaries. Preserve original URLs, all repository references, acquisition provenance, hashes after acquisition, extractor versions, and per-segment page/timestamp references. Search readiness requires verified extraction and indexing, not merely a queued URL.

The external workflow is a rotating weekly sample of up to 1,000 inventory rows, or a manually selected batch. Its report includes the checked offset and inventory size; it is not a complete weekly link audit. Artifact retention is 30 days for these availability reports only, not for WARC preservation.
