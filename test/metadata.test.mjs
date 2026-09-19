// validateMeta must reject attacker-crafted metadata, including the tiny-chunk DoS floor.
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { randU8, decryptOk, craft } from './dom-stub.mjs';

describe('malicious metadata validation', () => {
  const cases = [
    ['iterations=99999999 rejected', { iterations: 99999999 }],
    ['iterations=0 rejected', { iterations: 0 }],
    ['chunk=0 rejected', { chunk: 0 }],
    ['chunk=1 rejected (tiny-chunk DoS floor)', { chunk: 1 }],
    ['chunk=4095 rejected', { chunk: 4095 }],
    ['chunk=999999999 rejected', { chunk: 999999999 }],
    ['empty salt rejected', { salt: '' }],
    ['empty filename rejected', { filename: '' }],
    ['negative size rejected', { size: -1 }],
    ['wrong kdf rejected', { kdf: 'PBKDF1' }],
    ['wrong hash rejected', { hash: 'SHA-256' }],
  ];

  for (const [name, meta] of cases) {
    it(name, async () => {
      const pt = randU8(500);
      const enc = await craft(pt, 'x', meta);
      assert.equal(await decryptOk(enc, 'x'), false);
    });
  }

  it('metadata without kdf/hash fields still accepted', async () => {
    const pt = randU8(500);
    const enc = await craft(pt, 'x', { kdf: undefined, hash: undefined });
    assert.ok(await decryptOk(enc, 'x', pt));
  });
});
