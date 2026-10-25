If you wish to contribute, simply fork the project, add your links/information/pages and make a pull request. 
As long as the links are non-malicious, I'll probably accept your pull request. Any help/contributions are welcomed.

For navigation changes, use the Node version in `.nvmrc` (`nvm install && nvm use`), then run `npm ci --ignore-scripts`, `npm run nav:generate`, `npm test`, and `npm run nav:check`. See [Maintaining reference navigation](docs/navigation.md) for authoritative files, generated indexes, and subject/alias conventions.

The test suite also requires Python 3 for standard-library archive-policy checks. Docker is only required for archive capture and the separate runtime pilot; see [Archiving](docs/archiving.md). Routine navigation tests do not download images or capture external sites.
