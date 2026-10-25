# Security

## Reporting a vulnerability

Please report vulnerabilities privately through [GitHub Security Advisories](https://github.com/polius/vault/security/advisories/new), not in a public issue. Include the steps to reproduce, the browser and VAULT version, and a sample `.vault` file if one is involved (made with a throwaway password).

You can expect a first reply within a week. Fixes are released as soon as they're ready, and reporters are credited in the changelog unless they'd rather not be.

Only the latest release is supported.

## Security model

### What VAULT does

- Files are encrypted and decrypted entirely in the browser with the Web Crypto API and Argon2id (WebAssembly). Nothing you drop on the page, and no password, leaves the device.
- The server only serves static files. The page's Content-Security-Policy allows connections to its own origin only (`connect-src 'self'`) and no third-party scripts, styles or frames, so even injected code couldn't send data elsewhere through the usual channels.
- Data is encrypted with AES-256-GCM under a key derived by Argon2id (64 MiB, 3 passes) and HKDF-SHA-256. A key commitment rejects a wrong password before anything is written. See [FORMAT.md](FORMAT.md).
- Every frame is authenticated together with the header, its position and an end-of-file flag, so edits, reordering, truncation and appended bytes are all detected.
- The original file name, size and type are encrypted. The `.vault` file's own size still reveals the approximate size of the content, and its name reveals the original name unless you choose the neutral-name option.
- Output is written straight to the chosen file (Chromium) or streamed to a browser download through a Service Worker (Firefox, Safari). Plaintext is never written to browser storage. Leftover files from VAULT 1.x, which could stage plaintext in the origin-private file system, are deleted when the page loads.
- Trusted Types are enforced, so the page can't turn strings into HTML or scripts by accident.

### What VAULT can't protect against

- **Weak passwords.** Argon2id makes each guess expensive, but a short or common password can still be guessed. VAULT estimates strength assuming a well-funded attacker (about 100,000 guesses per second) and asks for confirmation below about 50 bits. A generated 6-word passphrase gives about 77 bits.
- **A compromised device or browser.** Malware, a malicious browser extension or someone with access to your unlocked machine can read files and passwords as you use them.
- **A compromised server.** Like every web app, VAULT runs the code the server sends. Someone who controls the server (or a CDN in front of it) could serve code that leaks your data. If that's in your threat model, host VAULT yourself, pin the image by digest, and verify its [build provenance](https://github.com/polius/vault/attestations).
- **Output of a failed decryption.** When decrypting a large file straight to disk, data is written before the end of the file has been verified. If verification fails later, VAULT stops and reports the file as damaged. In Chromium the partial file is never committed; in other browsers the download is marked as failed. Don't use a partial or failed download.
- **Lost passwords.** There's no recovery and no back door.

### Deployment notes

- Serve VAULT over HTTPS. Browsers disable the Web Crypto API on insecure origins (other than `localhost`), and without HTTPS the code you receive can be modified in transit.
- Keep the headers in [`nginx.conf`](nginx.conf), and turn off any feature of a CDN or proxy that rewrites pages or injects scripts (for example Cloudflare's Rocket Loader, Email Address Obfuscation or Web Analytics auto-injection): the CSP will block the injected code and parts of the page may break.
- The container runs as an unprivileged user and works with a read-only root filesystem; [`deploy/docker-compose.yml`](deploy/docker-compose.yml) shows the recommended hardening.
