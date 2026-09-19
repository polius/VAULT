# VAULT E2E tests

Drives **real Chromium** against the real container and round-trips a randomly
generated file through encrypt → decrypt, verifying SHA-256 equality — once per
sink mode (`sw`, `fs`, `blob`). Not packaged into the Docker image; tests run
on the host.

## Run locally

```bash
docker build -t vault:e2e .. && docker run -d --name vault-e2e -p 127.0.0.1:8080:80 vault:e2e
npm ci && npx playwright install chromium
node run.mjs --base-url=http://127.0.0.1:8080 --size=16M        # all cells
node run.mjs --sink=sw --size=100M --base-url=http://127.0.0.1:8080   # one cell
docker rm -f vault-e2e
```

## Notes

- **sw / blob** capture output through Playwright's download event.
- **fs**: the OS save dialog has no automation surface, so `showSaveFilePicker`
  is shimmed in the page (init script + exposed binding, mirroring FileSync's
  approach). The real `sink.js` fs branch still runs; chunks stream to Node,
  and the captured ciphertext is fed back through a blob-mode decrypt.
- 127.0.0.1 is a secure context, so Service Worker + File System Access APIs
  work against the plain-HTTP container.
- CI: the `e2e-smoke` job in `.github/workflows/tests.yml` runs all three
  cells at 16 MB on every PR.
