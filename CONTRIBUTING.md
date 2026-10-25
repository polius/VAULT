# Contributing

Thanks for helping. Bug reports, fixes and small improvements are welcome. For larger changes, please open an issue first so we can agree on the approach.

Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Setup

You need Node.js 22 or later, and Docker if you want to test the image.

```bash
npm ci
npm run serve        # http://127.0.0.1:8080, with the same headers as production
```

There's no build step and no runtime dependencies to install: `src/` is the site. Reload the page after a change.

## Checks

Run these before opening a pull request; CI runs them too.

```bash
npm run lint         # Biome (npm run format fixes most issues)
npm test             # unit tests (node --test)
npm run vendor:check # vendored files match their pinned sources
```

End-to-end tests run the app in Chromium, Firefox and WebKit:

```bash
cd e2e
npm ci
npx playwright install --with-deps
npx playwright test                    # starts the dev server itself
npx playwright test --project=chromium # one browser
```

CI runs them against the Docker image instead:

```bash
docker build -t vault:dev .
docker run -d --rm -p 127.0.0.1:8080:8080 vault:dev
cd e2e && BASE_URL=http://127.0.0.1:8080 npx playwright test
```

## Guidelines

- **The file format is a promise.** Anything that changes how files are written needs a new format version, an update to [FORMAT.md](FORMAT.md), and new vectors in `test/vectors/`. Existing vectors must keep decrypting; never edit or regenerate them.
- **No network, no third parties.** The app must not load anything from another origin or send data anywhere. Keep the Content-Security-Policy as strict as it is.
- **Headers live in two places.** `nginx.conf` and `scripts/serve.mjs` must send the same headers, and the CSP is also in `src/index.html`; a unit test checks they match.
- **Vendored files are generated.** Don't edit `src/js/vendor/` by hand. Change `scripts/vendor.mjs` and run `npm run vendor`.
- **Keep it small.** No frameworks and no build step. Plain ES modules, written to match the surrounding code.
- Add or update tests for what you change, and check the page with a keyboard and in both themes if you touch the UI.

## Releases

Maintainers only:

1. Update `version` in `package.json` and move the changelog entries under a dated heading.
2. Merge to `main`.
3. Publish a GitHub release with the tag `vX.Y.Z` (for example `v2.1.0`, no dot after the `v`). The release workflow runs the tests, checks the tag matches `package.json`, and pushes the multi-arch image with tags `X.Y.Z`, `X.Y`, `X` and `latest`. Pre-releases (`v2.1.0-rc.1`) only get their exact tag.
