// Crypto plumbing shared by encrypt.js and decrypt.js — keep in sync with the
// on-disk format documented in the header construction below.

export function concatBytes(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) { out.set(a, pos); pos += a.length; }
  return out;
}

export function b64u8(b) {
  return Uint8Array.from(atob(b), c => c.charCodeAt(0));
}

// Per-chunk Additional Authenticated Data. Binding the full header, the chunk
// index and an "is last chunk" flag into the GCM tag makes the metadata
// tamper-evident and prevents chunk reordering, duplication and truncation.
export function buildAAD(header, index, isLast) {
  const aad = new Uint8Array(header.length + 5);
  aad.set(header, 0);
  new DataView(aad.buffer).setUint32(header.length, index, true);
  aad[header.length + 4] = isLast ? 1 : 0;
  return aad;
}

export async function deriveKey(pw, salt, iter, usage) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: iter,
      hash: 'SHA-512'
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage]
  );
}
