<div align="center">
<img src="src/assets/logo.svg" alt="VAULT Logo" width="45">
<h1 align="center">VAULT</h1>

**Securely <span style="color: #0d6dfd">encrypt</span> and <span style="color: #198754">decrypt</span> your files directly in your browser**

<p align="center">
<a href="https://github.com/polius/vault/actions/workflows/release.yml"><img src="https://github.com/polius/vault/actions/workflows/release.yml/badge.svg"></a>&nbsp;<a href="https://github.com/polius/vault/releases"><img alt="GitHub Release" src="https://img.shields.io/github/v/release/polius/vault"></a>&nbsp;<a href="https://hub.docker.com/r/poliuscorp/vault"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/poliuscorp/vault"></a>
</p>

<br>

_All processing happens **<span style="color: #ffad32">locally</span>** on your device — no uploads, no servers involved._

<br>

![VAULT](src/assets/screenshot.png)
</div>

## See it in action

<p align="center">
  <a href="https://vault.alzina.dev/video.mp4">
    <img src="docs/assets/video-poster.png" width="720"
      alt="Watch the VAULT video: a one-minute walkthrough of encrypting and decrypting a file">
  </a>
</p>

<p align="center"><em>One minute: encrypting a file, what happens under the hood, and getting it back.
Plays as an MP4 in your browser. The video is built from code in <a href="scripts/explainer">scripts/explainer</a>.</em></p>

## Features

- **Files, many files, or whole folders.** Several files or a folder are packed into a single ZIP and encrypted as one `.vault` file.
- **One drop zone.** Drop anything anywhere on the page. `.vault` files switch VAULT to decrypt; you can override it.
- **Strong, modern crypto.** AES-256-GCM with a key derived by Argon2id (64 MiB, 3 passes). The original file name and size are encrypted too.
- **Wrong passwords are caught early**, before any save dialog opens. Truncated, extended or edited files are rejected.
- **Large files.** Output streams straight to disk where the browser allows it, so file size is limited by your disk, not your memory.
- **Better passwords.** A strength estimate with a guess-time, a confirmation field, and a 6-word passphrase generator.
- **Reads older files.** Files made by VAULT 1.x still decrypt.
- **Light and dark themes**, keyboard and screen-reader friendly.

The `.vault` format is documented in [FORMAT.md](FORMAT.md), and the threat model in [SECURITY.md](SECURITY.md).

## Installation

The recommended installation method is **Docker**. The image is a static nginx site that runs as a non-root user and listens on port **8080** inside the container.

> **Upgrading from 1.x?** The container port changed from 80 to 8080. Change `-p 80:80` to `-p 80:8080` (or `"80:80"` to `"80:8080"` in Compose).

#### Run with Docker CLI

```bash
docker run -d --name vault -p 80:8080 --read-only --tmpfs /tmp poliuscorp/vault
```

#### Run with Docker Compose

```yaml
services:
  vault:
    image: poliuscorp/vault
    container_name: vault
    ports:
      - "80:8080"
    read_only: true
    tmpfs:
      - /tmp
    restart: unless-stopped
```

> [!IMPORTANT]
> Browsers only allow the cryptography VAULT needs on **HTTPS** pages (or `http://localhost`). Served over plain HTTP from another machine, VAULT shows a notice instead of working. For anything beyond your own computer, use the HTTPS setup below or put VAULT behind your existing reverse proxy.

## Run it with HTTPS

The [`deploy`](deploy) folder runs VAULT behind [Caddy](https://caddyserver.com), which gets and renews a Let's Encrypt certificate automatically.

1. Point a DNS record for your domain at the server, and open ports 80 and 443.
2. Download [`docker-compose.yml`](deploy/docker-compose.yml) and [`Caddyfile`](deploy/Caddyfile) into one folder.
3. In the `Caddyfile`, replace `yourdomain.com` with your domain.
4. Start the stack:

   ```bash
   docker compose up -d
   ```

5. Open `https://yourdomain.com`.

To stop and remove the stack: `docker compose down`.

#### Behind your own reverse proxy

Proxy to the container's port 8080. VAULT sends its own security headers (Content-Security-Policy, `X-Frame-Options`, and so on); don't strip them, and don't let the proxy or a CDN inject scripts into the page, as the CSP will block them. Add `Strict-Transport-Security` at the proxy.

#### Static hosting

`src/` is a plain static site with no build step, so you can serve it from any static host. The CSP is also set in a `<meta>` tag, but for the full set of headers copy the ones in [`nginx.conf`](nginx.conf) into your host's configuration.

## Using VAULT

Once deployed, visit `http://localhost/` (or your HTTPS domain).

- **Encrypt:** drop files or a folder, type a password twice (or generate a passphrase and copy it somewhere safe), and click **Encrypt**. Under **Options** you can give the output a neutral name so the file name doesn't reveal what's inside.
- **Decrypt:** drop a `.vault` file, type the password, and click **Decrypt**. Multi-file vaults come back as a ZIP.

There is no password recovery. If you lose the password, the data is gone.

## Security model

In short: everything happens in your browser, and nothing you drop on the page is sent anywhere. The server only delivers static files, and the page's Content-Security-Policy forbids it from connecting anywhere but its own origin. VAULT protects your files at rest and in transit; it can't protect against a compromised device or browser, or against a server that's been changed to deliver malicious code. Read [SECURITY.md](SECURITY.md) for the details and for how to report a vulnerability.

## Development

Requires Node.js 22 or later. No build step: `src/` is served as is.

```bash
npm ci
npm run serve      # http://127.0.0.1:8080 with production headers
npm test           # unit tests
npm run lint       # Biome
```

End-to-end tests run in Chromium, Firefox and WebKit with Playwright. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Third-party components are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
