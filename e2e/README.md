# VAULT end-to-end tests

Playwright specs in [`tests/`](tests) drive the real app in Chromium, Firefox and WebKit: round trips through every saving method, failures, accessibility (axe), the CSP and the layout. They run on the host and are not part of the Docker image.

## Run them

```bash
npm ci
npx playwright install --with-deps
npx playwright test                    # starts the dev server itself, on port 4517
npx playwright test --project=chromium # one browser
```

CI runs the same specs against the hardened container instead of the dev server:

```bash
docker build -t vault:dev ..
docker run -d --rm -p 127.0.0.1:8080:8080 vault:dev
BASE_URL=http://127.0.0.1:8080 npx playwright test
```

## Notes

- **The save dialog is shimmed.** `showSaveFilePicker` has no automation surface, so `installFsShim()` in [`tests/helpers.js`](tests/helpers.js) replaces it with a shim that streams each written chunk to Node and enforces the real writable contract (no overlapping writes, closed streams reject, aborts are recorded). The real `fs` code path in `sink.js` still runs.
- **Downloads** from the Service Worker and in-memory methods are captured through Playwright's download event.
- `?sink=fs|sw|blob` in the address forces one saving method for a page load.
- `127.0.0.1` is a secure context, so the Service Worker and the crypto APIs work over plain HTTP.
- Every test fails if the page logs an error, breaks the CSP or Trusted Types, or requests anything from another origin.
