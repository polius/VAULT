# Changelog

All notable changes to VAULT. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Releases are tagged `vX.Y.Z`.

## [2.0.0] - Unreleased

A redesign of the app and a new file format. Files from VAULT 1.x still decrypt.

### Breaking

- **The container listens on port 8080**, not 80, and runs as a non-root user. Change `-p 80:80` to `-p 80:8080` (or `"80:80"` to `"80:8080"` in Compose).
- **New file format (version 3).** Files encrypted by 2.0 can't be opened by VAULT 1.x.
- Empty files encrypted by VAULT 1.x are refused, because that format couldn't authenticate them: any password would have "opened" them.

### Added

- Encrypt several files or a whole folder at once: they're packed into a single ZIP (ZIP64 for large archives) inside one `.vault` file.
- One drop zone for everything, and dropping anywhere on the page works. `.vault` files switch to decrypt automatically, with a manual override.
- Password confirmation field, a strength estimate with an estimated guess-time, and a second click to confirm a weak password.
- 6-word passphrase generator (EFF wordlist, about 77 bits) with a Copy button.
- Option to give the encrypted file a neutral name.
- Light and dark themes with an Auto/Light/Dark switch.
- Specific error messages for a wrong password, a damaged file, a file from a newer version, and so on.
- Over plain HTTP the page explains that it needs HTTPS instead of failing.
- [FORMAT.md](FORMAT.md) specifies the file format, with test vectors in `test/vectors/`.
- A one-minute video in the README shows VAULT at work. It is generated from code in `scripts/explainer`.

### Changed

- Keys are derived with **Argon2id** (64 MiB, 3 passes) and HKDF-SHA-256 instead of PBKDF2-SHA-512.
- The original file name and size are encrypted, and the metadata is padded to hide the name's exact length.
- A key commitment rejects a wrong password before any save dialog opens.
- Downloads in Firefox and Safari stream through the Service Worker with backpressure, and never write data to browser storage.
- Cancel works in every download mode.
- New interface without Bootstrap; accessibility checked with axe in both themes.
- Strict Content-Security-Policy with Trusted Types, also set in a `<meta>` tag for static hosts.
- The nginx base image is pinned by digest and works with a read-only root filesystem. All responses are sent with `Cache-Control: no-cache` so upgrades are never mixed with cached files.
- The HTTPS compose file pins Caddy and adds container hardening.
- Docker images are tagged by semver (`2.0.0`, `2.0`, `2`, `latest`) and published only after the full test suite passes.

### Fixed

- Truncated files, extra bytes after the end, and edited headers are all rejected.
- The browser no longer opens a file dropped outside the drop zone instead of encrypting it.

### Security

- Leftover files staged by VAULT 1.x in the origin-private file system, which could contain plaintext, are deleted when the page loads.

## Earlier versions

See the [GitHub releases](https://github.com/polius/vault/releases) for 1.x.

[2.0.0]: https://github.com/polius/vault/compare/v.1.6.1...v2.0.0
