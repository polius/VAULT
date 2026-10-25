import { strict as assert } from 'node:assert';
import { encrypt, unlock } from '../src/js/format.js';

// Smallest Argon2id cost the decoder accepts, so tests stay fast. One test in
// format.test.mjs exercises the real defaults.
export const FAST = Object.freeze({ m: 19456, t: 1, p: 1 });
export const MIB = 1_048_576;

export function randU8(n) {
  const a = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(a.subarray(i, Math.min(i + 65536, n)));
  return a;
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

export async function collect(iterable) {
  const parts = [];
  for await (const p of iterable) parts.push(p.slice());
  return concat(...parts);
}

// Yields `bytes` in pieces of `piece` bytes (to exercise re-chunking).
export async function* bytesSource(bytes, piece = 7777) {
  for (let i = 0; i < bytes.length; i += piece) yield bytes.subarray(i, i + piece);
}

export async function encryptBytes(
  plain,
  { password = 'pw', name = 'file.bin', type = 'file', chunk = 4096, kdf = FAST, source } = {},
) {
  return collect(
    encrypt({ password, meta: { name, type }, size: plain.length, source: source ?? bytesSource(plain), kdf, chunk }),
  );
}

export async function decryptBytes(bytes, password = 'pw') {
  const session = await unlock(new Blob([bytes]), password);
  return { session, plain: await collect(session.chunks()) };
}

export async function rejectsWith(promise, code) {
  await assert.rejects(promise, (err) => {
    assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err.message}`);
    return true;
  });
}

// Parses a v3 file into its pieces, for tamper tests.
export function parseV3(bytes) {
  const len = new DataView(bytes.buffer, bytes.byteOffset + 5, 4).getUint32(0, true);
  const params = JSON.parse(new TextDecoder().decode(bytes.subarray(9, 9 + len)));
  const frames = [];
  let off = 9 + len;
  frames.push([off, off + 28 + params.meta]);
  off += 28 + params.meta;
  while (off < bytes.length) {
    const end = Math.min(off + 28 + params.chunk, bytes.length);
    frames.push([off, end]);
    off = end;
  }
  return { params, headerLen: 9 + len, frames };
}
