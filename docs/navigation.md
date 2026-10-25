# Maintaining reference navigation

Markdown content remains authoritative. Edit `navigation/topics.json` to add a main topic or an alphabetical subject/alias. Topic paths are relative to the repository root; subject fragments must exist in their target page. A page has one canonical topic record. Aliases provide alternate discovery labels.

Use real headings for navigable subjects and bullets for resource entries. Keep a stable explicit `id` at each migrated heading; keep existing legacy anchors when renaming a heading. Explicit IDs are used for compatibility between GitHub and the checked-in Docsify renderer. Avoid duplicate IDs. Do not renumber the pilot's `ref-*` IDs when inserting new headings; assign a new unique ID instead.

Tables of contents follow document order and depth, while the subject index is alphabetical. Generic labels can remain in a local ToC but should not clutter the subject index.

## Commands

Requires a supported Node.js release: 22.22.2+ on the 22 branch, 24.15.0+ on the 24 branch, or 26+. These match the locked test-runtime dependencies. The original implementation was tested with Node.js 24.22.1; the desktop continuation uses Node.js 24.18.0, pinned in `.nvmrc`. With nvm installed, run `nvm install && nvm use` before the commands below.

```sh
npm ci
npm test
npm run nav:audit
npm run nav:generate
npm run nav:check
```

`nav:audit` prints findings without fetching external URLs. `nav:generate` edits only marked blocks and generated files. `nav:check` never writes: it checks output freshness and compares internal errors with the explicit legacy baseline.

Do not hand-edit `Draft/_sidebar.md`, `Draft/Subject_Index.md`, `Draft/search-paths.js`, or text between `nav:*:start` and `nav:*:end` markers. Missing or duplicated markers stop all generated writes.

The root README, website homepage, sidebar, and every page in `navigation/topics.json`’s `tocPages` must be free of internal navigation errors. `navigation/legacy-errors.json` records pre-existing defects in other pages, with individual reasons. New defects fail checks. Each baseline key records its allowed occurrence count. Adding another occurrence fails even for an already-exempt target. When repairing occurrences, reduce the count or remove the entry; stale exemptions also fail. Broad heading migration remains a follow-up to the pilot, not an automated destructive rewrite.

## Resource processing inventories

```sh
npm run resources:generate
```

The shared parser handles inline links, reference-style links, HTML links, and GFM bare URLs. It excludes fenced examples and inline images. Bare example URLs can still require editorial review. PDF/video/other lists are generated from the shared inventory; extensionless and uncertain resources stay in the machine-readable inventory for type confirmation.

Keep processing changes in `navigation/resource-progress.json`, keyed by resource ID, for example:

```json
{"resource-id-from-inventory": {"processing_status": "extracted"}}
```

Allowed statuses: `pending`, `acquired`, `extracted`, `indexed`, `failed`, and `deferred`. Regeneration preserves those statuses from this separate ledger. Do not infer successful extraction or indexing from availability alone.

## Docsify compatibility fixes

The existing Docsify 4.12.1 assets remain in place. Configuration is consolidated, automatic search paths are a string value, and `Draft/search-paths.js` supplies explicit routes for all reference Markdown pages, including directory children.

The bundled search plugin has local fixes: empty heading bodies no longer crash snippet generation; heading HTML is stripped from displayed search titles; explicit heading IDs are used for search destinations; and cache quota failures retain the in-memory search index. Incomplete cache entries trigger rebuilding rather than disabling search. A corpus larger than browser storage is fetched again on reload. Preserve these fixes or re-run the runtime regression tests when upgrading the plugin.

Tests run the actual checked-in compiler and the application under `/docs/` in jsdom. They exercise sidebar/deep routing and distinct search phrases. This is functional DOM verification, not proof of production deployment. Desktop Chromium review also verified pilot search result destinations, deep-route reload, and Cloud/Containers ToC routing under `/docs/`.

Managed navigation files and their ancestors must be regular repository paths. Symlinked Markdown inputs and symlinked managed outputs are rejected before reading/writing; generation must never follow a link into unrelated files. Explicit search destination IDs retain their exact case even though the bundled Docsify router normally lowercases serialized query values.
