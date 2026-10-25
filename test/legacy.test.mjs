// Files written by VAULT 1.x (formats 1 and 2) must keep decrypting, and the
// weaknesses the audit found in how they were read must stay closed.
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import { E, inspect, unlock } from '../src/js/format.js';
import { collect, concat, decryptBytes, rejectsWith } from './helpers.mjs';

const manifest = JSON.parse(await readFile(new URL('./vectors/legacy.json', import.meta.url), 'utf8'));
const load = async (file) => new Uint8Array(await readFile(new URL(`./vectors/${file}`, import.meta.url)));
const sha = (b) => createHash('sha256').update(b).digest('hex');
const te = new TextEncoder();

describe('VAULT 1.x vectors', () => {
  for (const v of manifest.vectors.filter((x) => x.size > 0)) {
    it(`${v.file} (format ${v.version}, ${v.size} bytes) decrypts`, async () => {
      const bytes = await load(v.file);
      const info = await inspect(new Blob([bytes]));
      assert.equal(info.version, v.version);
      assert.deepEqual(info.legacy, { name: v.filename, size: v.size });
      const { session, plain } = await decryptBytes(bytes, v.password);
      assert.equal(session.meta.name, v.filename);
      assert.equal(sha(plain), v.sha256);
      assert.deepEqual(session.warnings, [v.version === 1 ? 'legacy-v1' : 'legacy-v2']);
    });
  }

  it('wrong password fails at unlock, before any output', async () => {
    const v = manifest.vectors.find((x) => x.size === 1000);
    await rejectsWith(unlock(new Blob([await load(v.file)]), 'wrong'), E.WRONG_PASSWORD);
  });

  it('an empty format-2 file is refused: nothing authenticates it (audit H1)', async () => {
    const v = manifest.vectors.find((x) => x.size === 0);
    await rejectsWith(unlock(new Blob([await load(v.file)]), v.password), E.LEGACY_EMPTY);
    await rejectsWith(unlock(new Blob([await load(v.file)]), 'any password at all'), E.LEGACY_EMPTY);
  });

  it('a forged header-only format-2 file is refused (audit H1)', async () => {
    const meta = te.encode(
      JSON.stringify({ filename: 'forged-invoice.pdf', size: 0, salt: 'AAAA', iterations: 1, chunk: 1048576 }),
    );
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, meta.length, true);
    const forged = concat(te.encode('AES1'), new Uint8Array([2]), len, meta);
    await rejectsWith(unlock(new Blob([forged]), 'anything'), E.LEGACY_EMPTY);
  });

  it('trailing bytes are rejected (audit M2)', async () => {
    const v = manifest.vectors.find((x) => x.size === 1000);
    const bytes = concat(await load(v.file), new Uint8Array(1024));
    await rejectsWith(unlock(new Blob([bytes]), v.password), E.CORRUPTED);
  });

  it('format 1: editing the size field no longer truncates silently (audit M3)', async () => {
    const v = manifest.vectors.find((x) => x.version === 1);
    const bytes = await load(v.file);
    const text = Buffer.from(bytes);
    const at = text.indexOf('"size":5000');
    assert.ok(at > 0);
    const edited = Buffer.concat([text.subarray(0, at), Buffer.from('"size":4096'), text.subarray(at + 11)]);
    await rejectsWith(unlock(new Blob([new Uint8Array(edited)]), v.password), E.CORRUPTED);
  });

  it('format 2: a flipped bit mid-file is rejected while streaming', async () => {
    const v = manifest.vectors.find((x) => x.size > 1_000_000);
    const bytes = await load(v.file);
    bytes[bytes.length - 50] ^= 1;
    const session = await unlock(new Blob([bytes]), v.password);
    await rejectsWith(collect(session.chunks()), E.CORRUPTED);
  });
});

describe('VAULT 1.x header validation', () => {
  const build = (meta, version = 2) => {
    const json = te.encode(JSON.stringify(meta));
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, json.length, true);
    return new Blob([concat(te.encode('AES1'), new Uint8Array([version]), len, json, new Uint8Array(600))]);
  };
  const good = {
    filename: 'f.bin',
    size: 500,
    salt: btoa('s'.repeat(16)),
    iterations: 1000,
    chunk: 4096,
    kdf: 'PBKDF2',
    hash: 'SHA-512',
  };
  const cases = [
    ['iterations=99999999 (DoS)', { iterations: 99999999 }],
    ['iterations=0', { iterations: 0 }],
    ['chunk=1 (tiny-chunk DoS)', { chunk: 1 }],
    ['chunk=999999999', { chunk: 999999999 }],
    ['empty salt', { salt: '' }],
    ['empty filename', { filename: '' }],
    ['negative size', { size: -1 }],
    ['size larger than the file', { size: 10_000_000 }],
    ['wrong kdf', { kdf: 'PBKDF1' }],
    ['wrong hash', { hash: 'SHA-256' }],
  ];
  for (const [name, override] of cases) {
    it(`rejects ${name}`, async () => {
      await rejectsWith(inspect(build({ ...good, ...override })), E.BAD_HEADER);
    });
  }
  it('accepts metadata without kdf/hash fields', async () => {
    const info = await inspect(build({ ...good, kdf: undefined, hash: undefined }));
    assert.equal(info.version, 2);
  });
});
