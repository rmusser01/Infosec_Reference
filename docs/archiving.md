# Preservation and non-text processing

Preserve web articles and article figures in WARC. Queue PDFs, videos, slides, audio and other non-text resources for later acquisition/extraction. Saving a video landing page does not preserve its media. No bulk media acquisition, OCR, transcription or extracted-content indexing has run.

## Commands

- `npm run resources:generate`: regenerate the shared inventory and separate non-text views.
- `npm run external:check -- --limit 100 --offset 0 --output external-report.json`: bounded availability evidence; one batch is not a full audit.
- `npm run archive:plan -- --evidence external-report.json --output archive-plan.json`: route inventory rows using optional response evidence. Planning does not capture or verify bytes.
- `npm run archive:pilot -- --url https://danluu.com/sounds-easy/ --limit 1`: capture an existing inventory URL. Without `--url`, select rows using `--offset`; `--limit` defaults to three and permits 1–10 rows.
- `npm run archive:verify -- archive-data/PILOT/ATTEMPT`: recheck existing objects and offline replay evidence, appending new metadata without refetching or replacing earlier records.

## Capture runtime and bounds

Docker is required for capture, not navigation. The desktop continuation installed Browsertrix Crawler 1.15.0 and mitmproxy 12.3.0. `navigation/archive-runtime.json` pins the browser image digest; `tools/archive/Proxy.Dockerfile` pins the proxy base digest and warcio 1.8.1. Actual image IDs are recorded per attempt. Build the proxy/verifier image first:

```sh
docker build -f tools/archive/Proxy.Dockerfile -t infosec-archive-proxy:12.3.0-warcio1.8.1 tools/archive
npm run archive:pilot -- --url https://danluu.com/sounds-easy/ --limit 1
```

Each attempt has a unique ignored `archive-data/` directory containing WARCs, CDXJ, WACZ, logs and small provenance. Metadata appends to `navigation/archive-captures.jsonl`; no capture is published. Isolated browser profiles are omitted from retrieved output. The temporary proxy CA is trusted only inside capture containers, never installed on the host. Keep the ignored state directory private: it contains that CA's private key.

Crawl containers use an internal Docker network without published ports. The sole egress proxy rejects non-public/translation addresses and pins checked DNS answers while retaining upstream TLS verification. These checks cover redirects and dependencies. Only bounded unauthenticated GET/HEAD requests are admitted. MIME checks, including redirect bodies, block non-text payloads before the recorder receives them. Blocked resources retain queue/provenance evidence.

Discovery blocks image bodies and identifies article/main text, selected image URLs, SVG figures, figure backgrounds and media embeds. Capture admits those article images, including native lazy images, while rejecting unrelated images, frames and media. Scripts/styles/fonts/data requests are conservatively limited to the article origin; known tracking assets are blocked. Unknown third-party rendering dependencies and ambiguous layouts need review. These are DOM/signature heuristics, not a general semantic classifier.

The enforced pilot uses one sequential browser navigation, one navigation per host, at most 120 seconds per crawl/QA phase, and a 1-GiB total batch ceiling shared by discovery/capture/replay. Output uses size-limited tmpfs and explicit streaming retrieval because Docker copy omits tmpfs mounts. Response size, network bytes, request count and proxy metadata are separately bounded. Image installation bytes are outside this capture budget. The CLI is a bounded pilot, not a full-crawl launcher.

## Verification and storage

warcio verifies readable WARC records, recorded digests and payload lengths; gzip trailers and HTTP Content-Length are checked too. Whole objects have SHA-256 checksums. Content verification requires successful HTML, matching archived article text and every selected figure. Browsertrix QA runs with Docker networking disabled, requiring exact text replay plus successful article/figure responses. Intentionally excluded trackers may fail offline; those failures remain visible. This does not test visual fidelity. Filtering/budget failures cannot be cleared merely by rechecking.

Keep availability, capture, integrity/content, replay and storage states independent. A known error/login/rate-limit page is not a complete article. Failed/partial attempts remain visible; retries create new attempts. The initial-capture CLI only skips complete, verified durable captures after rehashing their objects. Preserve original references, fragments and query distinctions. Full inventory accounting is not successful preservation.

No durable destination is configured. `--primary PATH --backup PATH` verifies exclusive immutable copies and retrieval checksums, producing `copyState: verified` and `storageState: copied`; this does not qualify for preservation skips. Relative object paths preserve the CDXJ/archive layout. Durable eligibility additionally requires operator-configured `durableDestination` with `primary`, `backup` and `confirmedDurable: true`; this filesystem adapter requires distinct mounted filesystems. It verifies retrieved bytes, not physical backup independence or backup operations. Remote object-store uploads are not implemented. Never designate temporary test directories as durable.

Before a full run, choose persistent destinations, verify recovery/replay from stored objects, and size storage with a representative sample. Maintain an independent second copy or recoverable backup. Expiring CI artifacts are insufficient. Current local pilots remain temporary evidence. See `docs/archive-execution.md` for results and unresolved review cases.

## Tests and references

`npm test` includes navigation/archive tests and requires Python 3 for the standard-library-only policy tests. It does not download images or crawl live sites. `npm run archive:test-runtime` separately exercises synthetic static/JavaScript articles, figures versus ads/media, redirects, access walls, private redirects, MIME routing and offline replay through the actual containers. Synthetic URLs are served locally before upstream resolution; private destinations receive no production-guard exception. Run real warcio corruption/truncation tests offline:

```sh
docker run --rm --network none --entrypoint python3 -v "$PWD/tools/archive:/tools:ro" -v "$PWD/tests/archive:/tests:ro" infosec-archive-proxy:12.3.0-warcio1.8.1 -B /tests/verify_test.py
```

Interfaces checked against official sources: [Browsertrix releases](https://github.com/webrecorder/browsertrix-crawler/releases/tag/v1.15.0), [proxy support](https://crawler.docs.browsertrix.com/user-guide/proxies/), [offline QA](https://crawler.docs.browsertrix.com/user-guide/qa/), [mitmproxy hooks](https://docs.mitmproxy.org/stable/api/events.html), and [warcio](https://github.com/webrecorder/warcio/releases/tag/v1.8.1).

## Later search processing

PDFs: extract text with page numbers and OCR when needed. Videos: acquire available captions or transcripts and retain timestamps; add transcription where required. Other formats: confirm the type and route to the appropriate extractor without executing untrusted binaries. Preserve original URLs, all repository references, acquisition provenance, hashes after acquisition, extractor versions, and per-segment page/timestamp references. Search readiness requires verified extraction and indexing, not merely a queued URL.

The external workflow is a rotating weekly sample of up to 1,000 inventory rows, or a manually selected batch. Its report includes the checked offset and inventory size; it is not a complete weekly link audit. Artifact retention is 30 days for these availability reports only, not for WARC preservation.
