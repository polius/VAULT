// The .vault file format. Pure: no DOM, no sinks. Specified in FORMAT.md.
//
//   header   "AES1" | version (1 B) | paramsLen (u32 LE) | params JSON
//   frames   iv (12 B) | AES-256-GCM ciphertext | tag (16 B)
//
// Version 3 (written by this release):
//   params   { kdf:"argon2id", m, t, p, salt, chunk, meta, commit }
//   master   Argon2id(NFC(password), salt) -> 32 bytes
//   key      HKDF-SHA-256(master, salt, "VAULT v3 data key")       AES-256-GCM
//   commit   HKDF-SHA-256(master, salt, "VAULT v3 key commitment") stored in params
//   frame 0  encrypted metadata { name, size, type, ... } padded to `meta` bytes
//   frame 1+ file data in `chunk`-sized pieces; always at least one (possibly empty)
//   AAD      header bytes | frame index (u32 LE) | isLast (1 B)
//
// Versions 1 and 2 (VAULT 1.x) are read-only: PBKDF2-SHA-512, cleartext
// metadata, and (v2 only) the same AAD. v1 has no AAD at all.

import { ARGON2_DEFAULTS, argon2id, pbkdf2Key } from './kdf.js';

export const MAGIC = 'AES1';
export const VERSION = 3;
export const CHUNK = 1_048_576;

const IV = 12;
const TAG = 16;
const FRAME = IV + TAG;
const MAX_PARAMS = 4096;
const META_BLOCK = 256; // metadata is padded to a multiple of this, hiding the exact name length
const MAX_META = 64 * 1024;
const MIN_CHUNK = 4096;
const MAX_CHUNK = 64 * 1024 * 1024;
const MAX_FRAMES = 0xffffffff;
const ARGON2_BOUNDS = { m: [19456, 262144], t: [1, 10], p: [1, 4] }; // m in KiB: 19 MiB .. 256 MiB
const LEGACY_MAX_ITERATIONS = 5_000_000;

const te = new TextEncoder();
const utf8 = new TextDecoder('utf-8', { fatal: true });
const subtle = globalThis.crypto.subtle;

export class VaultError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'VaultError';
    this.code = code;
  }
}

export const E = Object.freeze({
  NOT_VAULT: 'NOT_VAULT', // no VAULT magic: not one of our files
  UNSUPPORTED: 'UNSUPPORTED', // made by a newer VAULT
  BAD_HEADER: 'BAD_HEADER', // our magic, but the header is malformed
  WRONG_PASSWORD: 'WRONG_PASSWORD', // v3: commitment mismatch; legacy: first frame fails
  CORRUPTED: 'CORRUPTED', // authenticated data failed to verify, or the length is wrong
  LEGACY_EMPTY: 'LEGACY_EMPTY', // VAULT 1.x empty file: nothing authenticates it
  SOURCE_CHANGED: 'SOURCE_CHANGED', // the input changed size while it was being read
  TOO_LARGE: 'TOO_LARGE',
});

const fail = (code, message, cause) => {
  throw new VaultError(code, message, cause ? { cause } : undefined);
};

// ---------- bytes ----------

export function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

const u32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));

function unb64(s, field) {
  try {
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  } catch (err) {
    return fail(E.BAD_HEADER, `Invalid header field: ${field}`, err);
  }
}

const random = (n) => crypto.getRandomValues(new Uint8Array(n));

async function readBytes(blob, start, end) {
  return new Uint8Array(await blob.slice(start, end).arrayBuffer());
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function buildAAD(header, index, isLast) {
  const aad = new Uint8Array(header.length + 5);
  aad.set(header, 0);
  new DataView(aad.buffer).setUint32(header.length, index, true);
  aad[header.length + 4] = isLast ? 1 : 0;
  return aad;
}

const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
const frameCount = (size, chunk) => Math.max(1, Math.ceil(size / chunk));

// ---------- header ----------

function validateV3(p) {
  if (p.kdf !== 'argon2id') fail(E.BAD_HEADER, 'Invalid header field: kdf');
  for (const [k, [lo, hi]] of Object.entries(ARGON2_BOUNDS)) {
    if (!isInt(p[k], lo, hi)) fail(E.BAD_HEADER, `Invalid header field: ${k}`);
  }
  if (typeof p.salt !== 'string') fail(E.BAD_HEADER, 'Invalid header field: salt');
  const salt = unb64(p.salt, 'salt');
  if (salt.length < 16 || salt.length > 64) fail(E.BAD_HEADER, 'Invalid header field: salt');
  if (!isInt(p.chunk, MIN_CHUNK, MAX_CHUNK)) fail(E.BAD_HEADER, 'Invalid header field: chunk');
  if (!isInt(p.meta, 2, MAX_META)) fail(E.BAD_HEADER, 'Invalid header field: meta');
  if (typeof p.commit !== 'string') fail(E.BAD_HEADER, 'Invalid header field: commit');
  const commit = unb64(p.commit, 'commit');
  if (commit.length !== 32) fail(E.BAD_HEADER, 'Invalid header field: commit');
  return { salt, commit };
}

function validateLegacy(p, blobSize) {
  if (typeof p.salt !== 'string' || p.salt.length === 0) fail(E.BAD_HEADER, 'Invalid header field: salt');
  if (!isInt(p.iterations, 1, LEGACY_MAX_ITERATIONS)) fail(E.BAD_HEADER, 'Invalid header field: iterations');
  if (!isInt(p.size, 0, blobSize)) fail(E.BAD_HEADER, 'Invalid header field: size');
  if (!isInt(p.chunk, MIN_CHUNK, MAX_CHUNK)) fail(E.BAD_HEADER, 'Invalid header field: chunk');
  if (typeof p.filename !== 'string' || p.filename.length === 0) fail(E.BAD_HEADER, 'Invalid header field: filename');
  if (p.kdf !== undefined && p.kdf !== 'PBKDF2') fail(E.BAD_HEADER, 'Invalid header field: kdf');
  if (p.hash !== undefined && p.hash !== 'SHA-512') fail(E.BAD_HEADER, 'Invalid header field: hash');
  return { salt: unb64(p.salt, 'salt') };
}

// Reads and validates the header only. Cheap: safe to call as soon as a file is
// picked, before any password is typed.
export async function inspect(blob) {
  if (blob.size < 9) fail(E.NOT_VAULT, 'File is too short to be a VAULT file');
  const head = await readBytes(blob, 0, 9);
  if (String.fromCharCode(...head.subarray(0, 4)) !== MAGIC) fail(E.NOT_VAULT, 'Missing VAULT signature');
  const version = head[4];
  if (version > VERSION) fail(E.UNSUPPORTED, `Format version ${version} is newer than this app supports`);
  if (version < 1) fail(E.BAD_HEADER, 'Invalid format version');
  const len = new DataView(head.buffer).getUint32(5, true);
  if (len === 0 || len > MAX_PARAMS || 9 + len > blob.size) fail(E.BAD_HEADER, 'Invalid header length');
  const json = await readBytes(blob, 9, 9 + len);
  let params;
  try {
    params = JSON.parse(utf8.decode(json));
  } catch (err) {
    fail(E.BAD_HEADER, 'Header is not valid JSON', err);
  }
  if (!params || typeof params !== 'object' || Array.isArray(params)) fail(E.BAD_HEADER, 'Header is not an object');
  const decoded = version === 3 ? validateV3(params) : validateLegacy(params, blob.size);
  return {
    version,
    params,
    ...decoded,
    header: concatBytes(head, json),
    dataOffset: 9 + len,
    kdf: version === 3 ? 'Argon2id' : 'PBKDF2-SHA-512',
    // VAULT 1.x stored these in cleartext; v3 keeps them inside frame 0.
    legacy: version < 3 ? { name: params.filename, size: params.size } : null,
  };
}

// ---------- v3 keys ----------

async function deriveV3(password, salt, { m, t, p }) {
  const pw = te.encode(password.normalize('NFC'));
  let master;
  try {
    master = await argon2id(pw, salt, { m, t, p });
  } finally {
    pw.fill(0);
  }
  const base = await subtle.importKey('raw', master, 'HKDF', false, ['deriveKey', 'deriveBits']);
  master.fill(0);
  const hkdf = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) });
  const key = await subtle.deriveKey(hkdf('VAULT v3 data key'), base, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const commit = new Uint8Array(await subtle.deriveBits(hkdf('VAULT v3 key commitment'), base, 256));
  return { key, commit };
}

async function seal(key, header, index, isLast, plain) {
  const iv = random(IV);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: buildAAD(header, index, isLast) }, key, plain);
  return concatBytes(iv, new Uint8Array(ct));
}

async function open(key, header, index, isLast, frame, aad = true) {
  const iv = frame.subarray(0, IV);
  const params = aad
    ? { name: 'AES-GCM', iv, additionalData: buildAAD(header, index, isLast) }
    : { name: 'AES-GCM', iv };
  return new Uint8Array(await subtle.decrypt(params, key, frame.subarray(IV)));
}

// ---------- encrypt ----------

function encodeMeta(meta) {
  const json = te.encode(JSON.stringify(meta));
  const padded = Math.ceil((json.length + 1) / META_BLOCK) * META_BLOCK;
  if (padded > MAX_META) fail(E.TOO_LARGE, 'File name is too long');
  const out = new Uint8Array(padded).fill(0x20); // JSON allows trailing spaces
  out.set(json);
  return out;
}

function paramsFor(kdf, salt, chunk, metaLen, commit) {
  return { kdf: 'argon2id', m: kdf.m, t: kdf.t, p: kdf.p, salt: b64(salt), chunk, meta: metaLen, commit: b64(commit) };
}

// Exact output size, known before the (slow) key derivation so a sink can be
// opened first and announce Content-Length.
export function encryptedSize({ meta, size, kdf = ARGON2_DEFAULTS, chunk = CHUNK }) {
  const metaLen = encodeMeta({ ...meta, size }).length;
  const params = te.encode(JSON.stringify(paramsFor(kdf, new Uint8Array(16), chunk, metaLen, new Uint8Array(32))));
  return 9 + params.length + FRAME + metaLen + frameCount(size, chunk) * FRAME + size;
}

// Splits any async iterable of byte arrays into exact `size`-byte blocks.
async function* rechunk(source, size) {
  let buf = new Uint8Array(size);
  let fill = 0;
  for await (let piece of source) {
    if (fill === 0 && piece.length === size) {
      yield piece;
      continue;
    }
    while (piece.length) {
      const n = Math.min(size - fill, piece.length);
      buf.set(piece.subarray(0, n), fill);
      fill += n;
      piece = piece.subarray(n);
      if (fill === size) {
        yield buf;
        buf = new Uint8Array(size);
        fill = 0;
      }
    }
  }
  if (fill) yield buf.subarray(0, fill);
}

export async function* fileSource(blob, chunk = CHUNK) {
  for (let offset = 0; offset < blob.size; offset += chunk) {
    yield await readBytes(blob, offset, offset + chunk);
  }
}

// Yields the encrypted file as byte arrays. `source` is an async iterable of
// exactly `size` plaintext bytes; `meta` is { name, type, ... }.
export async function* encrypt({
  password,
  meta,
  size,
  source,
  kdf = ARGON2_DEFAULTS,
  chunk = CHUNK,
  onPhase,
  onProgress,
  signal,
}) {
  if (frameCount(size, chunk) + 1 > MAX_FRAMES) fail(E.TOO_LARGE, 'File is too large');
  const metaPlain = encodeMeta({ ...meta, size });
  const salt = random(16);
  onPhase?.('kdf');
  const { key, commit } = await deriveV3(password, salt, kdf);
  signal?.throwIfAborted();
  const params = te.encode(JSON.stringify(paramsFor(kdf, salt, chunk, metaPlain.length, commit)));
  const header = concatBytes(te.encode(MAGIC), [VERSION], u32(params.length), params);
  onPhase?.('encrypt');
  yield header;
  yield await seal(key, header, 0, false, metaPlain);

  let index = 1;
  let done = 0;
  for await (const block of rechunk(source, chunk)) {
    signal?.throwIfAborted();
    done += block.length;
    if (done > size) fail(E.SOURCE_CHANGED, 'The input grew while it was being read');
    yield await seal(key, header, index++, done === size, block);
    onProgress?.(done, size);
  }
  if (done !== size) fail(E.SOURCE_CHANGED, 'The input shrank while it was being read');
  if (size === 0) {
    yield await seal(key, header, 1, true, new Uint8Array(0));
    onProgress?.(0, 0);
  }
}

// ---------- decrypt ----------

function validateMeta(meta, blobSize) {
  if (!meta || typeof meta !== 'object') fail(E.CORRUPTED, 'Invalid metadata');
  if (typeof meta.name !== 'string' || meta.name.length === 0 || meta.name.length > 4096)
    fail(E.CORRUPTED, 'Invalid metadata: name');
  if (!isInt(meta.size, 0, blobSize)) fail(E.CORRUPTED, 'Invalid metadata: size');
  if (meta.type !== 'file' && meta.type !== 'zip') fail(E.CORRUPTED, 'Invalid metadata: type');
}

async function unlockV3(blob, password, info, onPhase) {
  const { params, header, salt, commit } = info;
  onPhase?.('kdf');
  const { key, commit: derived } = await deriveV3(password, salt, params);
  if (!constantTimeEqual(derived, commit)) fail(E.WRONG_PASSWORD, 'Key commitment does not match');

  const metaFrame = await readBytes(blob, info.dataOffset, info.dataOffset + FRAME + params.meta);
  let meta;
  try {
    meta = JSON.parse(utf8.decode(await open(key, header, 0, false, metaFrame)));
  } catch (err) {
    fail(E.CORRUPTED, 'Metadata frame failed to verify', err);
  }
  validateMeta(meta, blob.size);

  const start = info.dataOffset + FRAME + params.meta;
  const expected = start + frameCount(meta.size, params.chunk) * FRAME + meta.size;
  if (blob.size !== expected) fail(E.CORRUPTED, `File length is ${blob.size}, expected ${expected}`);

  return {
    version: 3,
    meta: { name: meta.name, size: meta.size, type: meta.type, count: meta.count },
    warnings: [],
    async *chunks({ signal, onProgress } = {}) {
      let offset = start;
      let done = 0;
      let index = 1;
      do {
        signal?.throwIfAborted();
        const len = Math.min(params.chunk, meta.size - done);
        const isLast = done + len >= meta.size;
        const frame = await readBytes(blob, offset, offset + FRAME + len);
        let plain;
        try {
          plain = await open(key, header, index, isLast, frame);
        } catch (err) {
          fail(E.CORRUPTED, `Frame ${index} failed to verify`, err);
        }
        offset += FRAME + len;
        done += len;
        index++;
        yield plain;
        onProgress?.(done, meta.size);
      } while (done < meta.size);
      if (offset !== blob.size) fail(E.CORRUPTED, 'Unexpected data after the last frame');
    },
  };
}

async function unlockLegacy(blob, password, info, onPhase) {
  const { params, header, salt, version } = info;
  const { size, chunk } = params;
  if (size === 0) fail(E.LEGACY_EMPTY, 'Empty VAULT 1.x files carry no authentication tag');
  const expected = info.dataOffset + Math.ceil(size / chunk) * FRAME + size;
  if (blob.size !== expected) fail(E.CORRUPTED, `File length is ${blob.size}, expected ${expected}`);

  onPhase?.('kdf');
  const key = await pbkdf2Key(password, salt, params.iterations);
  const aad = version === 2;
  const firstLen = Math.min(chunk, size);
  const firstFrame = await readBytes(blob, info.dataOffset, info.dataOffset + FRAME + firstLen);
  let first;
  try {
    first = await open(key, header, 0, firstLen >= size, firstFrame, aad);
  } catch (err) {
    fail(E.WRONG_PASSWORD, 'First frame failed to verify', err);
  }

  return {
    version,
    meta: { name: params.filename, size, type: 'file' },
    warnings: [version === 1 ? 'legacy-v1' : 'legacy-v2'],
    async *chunks({ signal, onProgress } = {}) {
      let offset = info.dataOffset + FRAME + firstLen;
      let done = firstLen;
      let index = 1;
      yield first;
      onProgress?.(done, size);
      while (done < size) {
        signal?.throwIfAborted();
        const len = Math.min(chunk, size - done);
        const frame = await readBytes(blob, offset, offset + FRAME + len);
        let plain;
        try {
          plain = await open(key, header, index, done + len >= size, frame, aad);
        } catch (err) {
          fail(E.CORRUPTED, `Frame ${index} failed to verify`, err);
        }
        offset += FRAME + len;
        done += len;
        index++;
        yield plain;
        onProgress?.(done, size);
      }
      if (offset !== blob.size) fail(E.CORRUPTED, 'Unexpected data after the last frame');
    },
  };
}

// Verifies the password (and, for v3, decrypts the metadata) without producing
// any output. Returns a session whose chunks() yields the plaintext.
export async function unlock(blob, password, { info, onPhase } = {}) {
  const header = info ?? (await inspect(blob));
  return header.version === 3
    ? unlockV3(blob, password, header, onPhase)
    : unlockLegacy(blob, password, header, onPhase);
}
