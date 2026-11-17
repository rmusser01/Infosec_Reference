# Resource processing inventories

Regenerate with `npm run resources:generate`. Update processing statuses in `navigation/resource-progress.json`; generated views are not edited by hand.

These inventories separate non-text resources from the web-page WARC pipeline. They are a preliminary URL scan, not verified MIME classification or a complete media-discovery crawl.

- [PDFs](pdfs.md): later text extraction, with OCR where needed.
- [Videos](videos.md): later metadata/caption extraction or transcription; timestamps retained for search results.
- [Other non-text resources](other-nontext.md): route by confirmed type, such as slides, audio, datasets, packet captures, and archives.
- [Full machine-readable inventory](resource-inventory.jsonl): includes unknown URLs for subsequent classification, deduplicated fetch URLs, and all source references.

PDFs, videos, and other non-text targets are queued for later processing rather than automatically archived/downloaded now. Preserve article HTML/text and article images in the WARC pipeline. Do not execute linked binaries. A landing page capture does not establish that its underlying media was processed.

Classification status, processing status, and availability are separate. Confirm type using headers/content and media-host metadata during validation; do not trust extensions alone. The source scan skips fenced examples and inline image syntax but can still include bare example URLs and miss complex Markdown or runtime-discovered embeds. Retain source evidence and review before capture.

Later extracted records should retain resource ID, original URL, title, author/date when available, source location, acquisition provenance, extractor/version, extraction status, and the page number or timestamp for each searchable text segment. Keep original and extracted-text hashes once actual bytes exist; do not invent them for queued resources. Do not claim search readiness before extraction and indexing verification.
