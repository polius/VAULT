# The `.vault` file format

This document specifies the files VAULT writes and reads. It is enough to write an independent decrypter. The reference implementation is [`src/js/format.js`](src/js/format.js), and [`test/vectors/`](test/vectors) has sample files with their passwords and plaintext hashes.

VAULT 2.x writes **version 3**. It still reads versions 1 and 2, written by VAULT 1.x.

## Conventions

- Integers are unsigned little-endian. `u8`, `u32` are 1 and 4 bytes.
- `base64` is standard base64 with padding (RFC 4648 §4).
- `||` is byte concatenation.
- AES-256-GCM uses a 12-byte IV and a 16-byte tag.

## Layout

Every version shares this outer layout:

```
header  = magic || version || paramsLen || params
magic   = "AES1"                  4 bytes, ASCII
version = u8                      1, 2 or 3
paramsLen = u32                   1 ..= 4096
params  = UTF-8 JSON object       paramsLen bytes
frames  = frame*
frame   = iv || ciphertext || tag  12 + n + 16 bytes
```

`header` below always means these bytes exactly as stored in the file, from `magic` through the end of `params`.

A reader that finds a version higher than it supports must refuse the file rather than guess.

## Version 3

### Parameters

| Field    | Type    | Meaning                                | Valid range       | Written by 2.0  |
| -------- | ------- | -------------------------------------- | ----------------- | --------------- |
| `kdf`    | string  | Key derivation function                | `"argon2id"`      | `"argon2id"`    |
| `m`      | integer | Argon2 memory, KiB                     | 19456 ..= 262144  | 65536 (64 MiB)  |
| `t`      | integer | Argon2 passes                          | 1 ..= 10          | 3               |
| `p`      | integer | Argon2 lanes                           | 1 ..= 4           | 1               |
| `salt`   | base64  | Random salt                            | 16 ..= 64 bytes   | 16 bytes        |
| `chunk`  | integer | Plaintext bytes per data frame         | 4096 ..= 67108864 | 1048576 (1 MiB) |
| `meta`   | integer | Plaintext length of the metadata frame | 2 ..= 65536       | multiple of 256 |
| `commit` | base64  | Key commitment                         | exactly 32 bytes  |                 |

Readers must reject a header whose fields are missing, of the wrong type, or out of range. The ranges bound the work an attacker-supplied file can make a reader do.

### Keys

```
pw     = UTF-8(NFC(password))
master = Argon2id(pw, salt, m, t, p, version 0x13, output 32 bytes)   no secret, no associated data
key    = HKDF-SHA-256(IKM = master, salt = salt, info = "VAULT v3 data key",       L = 32)
commit = HKDF-SHA-256(IKM = master, salt = salt, info = "VAULT v3 key commitment", L = 32)
```

`key` is the AES-256-GCM key. `commit` is stored in the header. A reader derives both and compares `commit` with the stored value in constant time. A mismatch means the password is wrong, which a reader can report before decrypting or writing anything. The commitment also binds the file to a single key, so one ciphertext can't be made to decrypt validly under two passwords.

### Frames

Each frame is sealed independently with a fresh random 12-byte IV and this associated data:

```
AAD(index, isLast) = header || u32(index) || u8(isLast ? 1 : 0)
```

Binding the header to every frame stops parameters from being changed. The index stops frames from being reordered, dropped or duplicated, and `isLast` stops the file from being truncated at a frame boundary.

**Frame 0** holds the metadata, with `index = 0` and `isLast = 0`. Its plaintext is exactly `meta` bytes: a UTF-8 JSON object followed by spaces (0x20) as padding. VAULT pads to the next multiple of 256 bytes, with at least one byte of padding, so the length of the name is not revealed exactly. Fields:

| Field   | Type    | Meaning                                                                                |
| ------- | ------- | -------------------------------------------------------------------------------------- |
| `name`  | string  | Original file name, 1 to 4096 characters. For a multi-file vault, the name of the ZIP. |
| `size`  | integer | Plaintext size in bytes.                                                               |
| `type`  | string  | `"file"`, or `"zip"` when several files or a folder were packed into a ZIP archive.    |
| `mtime` | integer | Optional. Last-modified time, milliseconds since the Unix epoch.                       |
| `count` | integer | Optional, `"zip"` only. Number of files in the archive.                                |

Readers must ignore fields they don't know. They must treat `name` as untrusted: strip path separators and control characters before using it as a file name.

**Frames 1 to N** hold the data, with `N = max(1, ceil(size / chunk))`. Frame `i` holds plaintext bytes `(i-1)·chunk` up to `i·chunk`, so every data frame but the last carries exactly `chunk` bytes. Only frame N has `isLast = 1`. An empty file has one data frame with an empty plaintext, so it is still authenticated.

ZIP archives inside a vault use the STORE method (no compression), UTF-8 names, data descriptors, and ZIP64 records only where sizes or offsets require them.

### Length

The total length of a valid file is exactly:

```
9 + paramsLen + (28 + meta) + 28·N + size
```

Readers must reject a file of any other length after decrypting frame 0, and must also check that no bytes remain after frame N.

### Decrypting

1. Read and validate the header.
2. Derive `key` and `commit`. If `commit` doesn't match, the password is wrong: stop.
3. Decrypt frame 0 and validate the metadata. If it fails to verify, the file is corrupted.
4. Check the total length against the formula above.
5. Decrypt frames 1 to N in order, with the AAD above. Any failure means the file is corrupted.

An implementation that writes output while it decrypts (as VAULT does for large files) has produced unverified plaintext if a later frame fails. It must tell the user the output is incomplete and should delete it.

## Versions 1 and 2 (VAULT 1.x, read-only)

These are documented so old files stay readable. Don't write them.

Parameters:

| Field        | Type    | Meaning                                                      |
| ------------ | ------- | ------------------------------------------------------------ |
| `filename`   | string  | Original file name, in cleartext.                            |
| `size`       | integer | Plaintext size, in cleartext.                                |
| `salt`       | base64  | Random salt (16 bytes).                                      |
| `iterations` | integer | PBKDF2 iterations (250000 up to VAULT 1.4, 600000 from 1.5). |
| `chunk`      | integer | Plaintext bytes per frame (1 MiB).                           |
| `kdf`        | string  | Optional, `"PBKDF2"`.                                        |
| `hash`       | string  | Optional, `"SHA-512"`.                                       |

```
key = PBKDF2-HMAC-SHA-512(UTF-8(password), salt, iterations, 32 bytes)      no NFC normalization
```

There is no metadata frame and no key commitment. Data frames are numbered from 0, `N = ceil(size / chunk)`, and the file length is `9 + paramsLen + 28·N + size`. Version 2 uses the same AAD as version 3; version 1 uses no AAD at all, so its frames can be reordered or the file truncated at a frame boundary without detection. A wrong password shows up as frame 0 failing to verify.

An empty version 1 or 2 file has no frames, so nothing in it is authenticated and any password "opens" it. VAULT 2 refuses to decrypt these and explains why.

## Changes

| Version | VAULT | Changes                                                                                                                |
| ------- | ----- | ---------------------------------------------------------------------------------------------------------------------- |
| 3       | 2.0   | Argon2id with HKDF; key commitment; encrypted metadata (name, size, type); padded metadata; empty files authenticated. |
| 2       | 1.5   | Header, frame index and last-frame flag bound to each frame as AAD.                                                    |
| 1       | 1.0   | First version: PBKDF2-SHA-512 and AES-256-GCM per 1 MiB chunk.                                                         |
