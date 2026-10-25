# Preservation and non-text processing

Web articles belong in WARC, including article text and inline article figures. PDFs, videos, slides, audio, and other non-text resources go into separate processing queues for later acquisition/extraction. A saved video landing page is not an archived video. No media download, OCR, transcription, or search indexing has been performed by this change.

## Available now

- `npm run resources:generate`: regenerate the resource inventory and separate non-text lists.
- `npm run external:check -- --limit 100 --offset 0 --output external-report.json`: check a bounded batch of URLs and record response evidence. Default batch size is 100; explicit maximum is 1,000. Offset makes coverage explicit; one batch is not a full audit. External checks are independent of offline navigation CI.
- `npm run archive:plan -- --evidence external-report.json --output archive-plan.json`: route resources to article capture, non-text processing, type confirmation, or review using the inventory and optional validation evidence. Omit `--evidence` for an offline plan. It plans jobs; it does not capture content.

External requests use pinned DNS resolution for each hop, reject non-public addresses and embedded credentials, revalidate redirects, and bound concurrency/time/retries. GET fallback reads headers only. A reachable URL is not proof that its article content is available; challenge/login/error pages require later content verification.

The archive planner only treats a prior snapshot as already preserved when its manifest explicitly records complete capture, verified integrity, verified durable storage, verified replay, and object checksums/lengths. Planning does not itself verify those bytes.

## Required before real WARC captures

At the 2026-10-25 desktop continuation, Docker client/server 29.8.1 are available, but the Browsertrix image is not installed and no durable archive destination is configured. The capture adapter, article-image request filtering, WARC record/digest checks, offline replay QA, and durable upload/retrieval pilot remain unimplemented and unverified. `navigation/archive-policy.json` records intended bounds; it is not an enforcement engine. No captures are claimed and `navigation/archive-captures.jsonl` is empty.

The navigation tooling does not need Docker or Browsertrix. The selected Browsertrix Crawler runs in Docker ([official user guide](https://crawler.docs.browsertrix.com/user-guide/)); another engine would need equivalent capture, filtering, and replay verification. A bounded local pilot can use local output before durable storage is chosen. Implement those pieces against a pinned maintained capture engine before running a crawl. Network restrictions must cover browser subresources and redirects, not just seed URLs. Determine article images from article/main content and rendered references; classify uncertain pages for review rather than capturing every image on the host. Keep screenshots, advertising/tracking images, standalone media, and unrelated galleries outside article-image scope unless separately requested.

Store immutable `.warc.gz` objects and CDXJ indexes outside ordinary Git history. WACZ replay packages may accompany WARCs. Keep provenance, hashes, storage references, statuses, and small metadata in the repository. Do not use expiring CI artifacts as the only archive copy; do not publish to the Internet Archive automatically.

Before a full run, validate a bounded pilot: static and JavaScript articles, article images versus unrelated images, redirects, non-text queue routing, and failures. Verify WARC records/digests and offline replay, record actual stored bytes, and test retrieval from durable storage. Keep capture, availability, replay, and storage states separate; preserve earlier snapshots.

## Later search processing

PDFs: extract text with page numbers and OCR when needed. Videos: acquire available captions or transcripts and retain timestamps; add transcription where required. Other formats: confirm the type and route to the appropriate extractor without executing untrusted binaries. Preserve original URLs, all repository references, acquisition provenance, hashes after acquisition, extractor versions, and per-segment page/timestamp references. Search readiness requires verified extraction and indexing, not merely a queued URL.

The external workflow is a rotating weekly sample of up to 1,000 inventory rows, or a manually selected batch. Its report includes the checked offset and inventory size; it is not a complete weekly link audit. Artifact retention is 30 days for these availability reports only, not for WARC preservation.
