# Implementation status

Branch: `improve-generated-navigation`. Source base: `af8b68e2194e695c542eb76fba762d2f0a19a0dc`. Changes are local; nothing has been pushed, published, or archived externally.

## Implemented

- Shared Markdown parser and offline navigation audit, including explicit HTML anchors and GitHub heading fragments.
- One manifest for 48 main topics, generated README/site topic navigation, sidebar, selective alphabetical subject index, and full reference search paths.
- Generated ToCs and real navigable headings for AD, DFIR, and logging/monitoring/threat hunting; original external URL tokens and explicit anchor names are regression-checked.
- Docsify configuration repair and narrow search-plugin fixes for empty heading bodies, HTML titles, and explicit-anchor result destinations.
- Internal navigation checks with individual legacy exemptions and stale-exemption detection; read-only CI workflow.
- Parser-generated processing lists and a separate progress ledger that survives regeneration.
- Bounded external availability checks and report-only workflow; archive job planning with separate non-text queues and verified-prior-capture eligibility.

## Measured results

Initial internal errors: 334. After pilot: 305 legacy errors remain in other pages; managed navigation and all three pilot pages have zero internal errors. The audit intentionally continues to report that debt.

Current provisional resource candidates: 1,199 PDFs, 1,458 videos, 23 other non-text; 19,065 URLs remain unknown until response/content confirmation. These are source-derived inventory counts, not verified content types or download counts.

Functional tests exercise the actual checked-in Docsify compiler and application in jsdom under `/docs/`, sidebar/deep routing, and distinct search phrases. This is not native-browser visual QA or a production deployment check.

## Remaining work

- Review the pilot, then migrate the remaining pages and retire their legacy-error entries in reviewable groups.
- Provide a Browsertrix-capable runtime and durable archive destination; implement the enforced capture adapter, article-image filtering, WARC verification, offline replay, and storage/retrieval pilot. The archive policy file describes intent, not implemented enforcement.
- Run external batches with evidence-aware capture/queue routing. No full external validation or web capture has run.
- Implement PDF extraction/OCR, video captions/transcription, other extractors, and search indexing in later processing stages.

## Engineering decisions

- Use the conversation's isolated clone on a feature branch rather than create another linked worktree; no user checkout was modified.
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

Final verification: clean `npm ci --ignore-scripts` succeeded; `npm test` passed 35 tests with zero failures; `npm run nav:check` passed with no new/stale navigation diagnostics and 305 explicitly baselined legacy error occurrences. Resource lists regenerated successfully and `git diff --check` passed. No external availability batch or WARC capture was executed.

To use the exported patch, apply it to a compatible clean checkout of the source repository after checking it with `git apply --check infosec-navigation.patch`; then run `git apply infosec-navigation.patch`, `npm ci --ignore-scripts`, `npm test`, and `npm run nav:check`.
