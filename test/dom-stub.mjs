// Minimal DOM/browser stub + helpers so the REAL src/js modules run under Node.
import { fileURLToPath } from 'node:url';

const SRC_DIR = fileURLToPath(new URL('../src/js/', import.meta.url));

export const MIB = 1048576;

function makeEl(id) {
  const el = {
    id, value: '', files: [], disabled: false, innerHTML: '', textContent: '',
    title: '', className: '', download: '',
    style: {},
    classList: {
      _s: new Set(),
      add(...c) { c.forEach(x => this._s.add(x)); },
      remove(...c) { c.forEach(x => this._s.delete(x)); },
      contains(c) { return this._s.has(c); },
    },
    addEventListener() {},
    closest() { return makeEl('closest:' + id); },
    querySelector() { return makeEl('q:' + id); },
    replaceChildren() {}, appendChild() {}, append() {},
    focus() {}, click() { el._clicked = true; }, remove() {},
    setAttribute() {},
  };
  return el;
}

const els = {};
const created = [];
export const blobStore = new Map();
export const getEl = (id) => (els[id] ||= makeEl(id));

globalThis.document = {
  body: makeEl('body'),
  getElementById: getEl,
  createElement: (tag) => { const e = makeEl('created-' + tag); created.push(e); return e; },
  querySelector: () => makeEl('qs'),
};

let urlN = 0;
globalThis.URL.createObjectURL = (b) => { const u = 'blob:fake-' + (++urlN); blobStore.set(u, b); return u; };
globalThis.URL.revokeObjectURL = () => {};
globalThis.window = { confirm: () => true };
Object.defineProperty(globalThis, 'navigator', {
  value: { clipboard: { writeText: async () => {} } }, configurable: true,
});

// App code leaves 60s revoke timers behind; unref them so the test process exits.
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => {
  const t = realSetTimeout(fn, ms, ...args);
  t?.unref?.();
  return t;
};

await import('file://' + SRC_DIR + 'encrypt.js');
await import('file://' + SRC_DIR + 'decrypt.js');

export function randU8(n) {
  const a = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(a.subarray(i, Math.min(i + 65536, n)));
  return a;
}

export function concat(...arrs) {
  const t = arrs.reduce((n, a) => n + a.length, 0), out = new Uint8Array(t);
  let p = 0; for (const a of arrs) { out.set(a, p); p += a.length; } return out;
}

export async function encryptRun(bytes, name, pw) {
  const file = new File([bytes], name);
  getEl('encFile').files = [file];
  getEl('encPwd').value = pw;
  blobStore.clear(); created.length = 0;
  await getEl('encBtn').onclick();
  const url = [...blobStore.keys()].at(-1);
  const blob = url ? blobStore.get(url) : undefined;
  const anchor = created.find(e => e.id === 'created-a');
  return { blob, outName: anchor ? anchor.download : null };
}

export async function decryptRun(bytes, pw) {
  const file = new File([bytes], 'x.vault');
  getEl('decFile').files = [file];
  getEl('decPwd').value = pw;
  blobStore.clear(); created.length = 0;
  await getEl('decBtn').onclick();
  const url = [...blobStore.keys()].at(-1);
  return url ? blobStore.get(url) : undefined;
}

export async function decryptOk(bytes, pw, expected) {
  const dec = await decryptRun(bytes, pw);
  if (!dec) return false;
  const out = new Uint8Array(await dec.arrayBuffer());
  return expected ? Buffer.from(out).equals(Buffer.from(expected)) : out.length > 0;
}

// Independent v2-format fixture builder (does NOT reuse app code, so the tests
// also catch regressions in buildAAD/header construction itself).
export async function craft(pt, pw, overrides = {}, iterations = 1000, chunk = 4096) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-512' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const meta = {
    filename: 'f.bin', size: pt.length,
    salt: btoa(String.fromCharCode(...salt)),
    iterations, chunk, kdf: 'PBKDF2', hash: 'SHA-512', ...overrides,
  };
  const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
  const lenBuf = new Uint8Array(4);
  new DataView(lenBuf.buffer).setUint32(0, metaBytes.length, true);
  const header = concat(new TextEncoder().encode('AES1'), new Uint8Array([2]), lenBuf, metaBytes);
  const parts = [header];
  let off = 0, idx = 0;
  while (off < pt.length) {
    const c = pt.slice(off, Math.min(off + chunk, pt.length));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = concat(header, new Uint8Array(new Uint32Array([idx]).buffer),
      new Uint8Array([off + c.length >= pt.length ? 1 : 0]));
    parts.push(iv, new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, c)));
    off += c.length; idx++;
  }
  return concat(...parts);
}
