If you wish to contribute, simply fork the project, add your links/information/pages and make a pull request. 
As long as the links are non-malicious, I'll probably accept your pull request. Any help/contributions are welcomed.

For navigation changes, use the Node version in `.nvmrc` (`nvm install && nvm use`), then run `npm ci --ignore-scripts`, `npm run nav:generate`, `npm test`, and `npm run nav:check`. See [Maintaining reference navigation](docs/navigation.md) for authoritative files, generated indexes, and subject/alias conventions.

The test suite also requires Python 3 for standard-library archive-policy checks. Docker is only required for archive capture and the separate runtime pilot; see [Archiving](docs/archiving.md). Routine navigation tests do not download images or capture external sites.

When adding resource links, preview `npm run archive:changes -- --base master`, then run the same command with `--execute --limit 3` locally before opening the PR. This checkout currently has `master`; use `main` after a branch rename. This retains article text/figures locally and submits the new URLs to Internet Archive. Commit the metadata and generated `docs/archives/README.md`, keeping raw captures ignored. Repeat bounded batches as needed; `--resume --execute --wayback-only` polls recorded pending jobs. See the archive guide for comparison refs, partial results and CI receipt handling.
