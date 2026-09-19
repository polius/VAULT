// Round-trip correctness, negative cases, and v1 legacy compatibility.
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { MIB, randU8, encryptRun, decryptOk, concat, craft } from './dom-stub.mjs';

describe('round-trip (real KDF)', () => {
  for (const size of [0, 1, 1000, MIB - 1, MIB, MIB + 1, 2 * MIB + 137]) {
    it(`size=${size}`, async () => {
      const pt = randU8(size);
      const { blob, outName } = await encryptRun(pt, 'doc-' + size + '.bin', 'P@ssw0rd-тest!');
      assert.ok(blob, 'encrypt produced no output');
      assert.equal(outName, 'doc-' + size + '.bin.vault');
      const enc = new Uint8Array(await blob.arrayBuffer());
      assert.ok(await decryptOk(enc, 'P@ssw0rd-тest!', pt));
    });
  }
});

describe('negative cases', () => {
  it('wrong password rejected', async () => {
    const { blob } = await encryptRun(randU8(2048), 'a.bin', 'right');
    const enc = new Uint8Array(await blob.arrayBuffer());
    assert.equal(await decryptOk(enc, 'wrong'), false);
  });

  it('garbage input rejected', async () => {
    assert.equal(await decryptOk(randU8(500), 'x'), false);
  });
});

describe('v1 legacy format compatibility', () => {
  it('v1 file decrypts', async () => {
    const pt = randU8(3000), pw = 'legacy-pw';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-512' }, base,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const meta = {
      filename: 'old.txt', size: pt.length,
      salt: btoa(String.fromCharCode(...salt)),
      iterations: 1000, chunk: 1_048_576, kdf: 'PBKDF2', hash: 'SHA-512',
    };
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    const lenBuf = new Uint8Array(4);
    new DataView(lenBuf.buffer).setUint32(0, metaBytes.length, true);
    const header = concat(new TextEncoder().encode('AES1'), new Uint8Array([1]), lenBuf, metaBytes);
    const parts = [header];
    for (let off = 0; off < pt.length; off += 1_048_576) {
      const c = pt.slice(off, Math.min(off + 1_048_576, pt.length));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      parts.push(iv, new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, c)));
    }
    assert.ok(await decryptOk(concat(...parts), pw, pt));
  });
});

describe('chunk size floor acceptance', () => {
  it('legitimate 4096-byte chunks still decrypt', async () => {
    const pt = randU8(10000);
    const enc = await craft(pt, 'x', {}, 1000, 4096);
    assert.ok(await decryptOk(enc, 'x', pt));
  });
});
