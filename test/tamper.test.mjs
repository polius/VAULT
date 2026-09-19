// v2 integrity: AAD binding must reject reordering, tampering, truncation, downgrade.
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { MIB, randU8, encryptRun, decryptOk, concat } from './dom-stub.mjs';

describe('v2 tamper / integrity suite', () => {
  const pt = randU8(2 * MIB + 137); // 3 chunks: 1 MiB, 1 MiB, 137 B
  let enc;

  it('fixture encrypts', async () => {
    const { blob } = await encryptRun(pt, 't.bin', 'pw-tamper');
    enc = new Uint8Array(await blob.arrayBuffer());
  });

  // Parse header once: magic(4) | version(1) | metaLen(4 LE) | meta | blocks
  const metaLen = () => new DataView(enc.buffer, 5, 4).getUint32(0, true);
  const blockBounds = () => {
    const hdrLen = 9 + metaLen();
    const bounds = [];
    let off = hdrLen, idx = 0;
    while (off < enc.length) {
      const chunkSize = Math.min(MIB, pt.length - idx * MIB);
      bounds.push([off, off + 12 + chunkSize + 16]);
      off += 12 + chunkSize + 16; idx++;
    }
    return bounds;
  };

  it('chunk reordering rejected', async () => {
    const [b0, b1] = blockBounds();
    const reordered = concat(enc.slice(0, b0[0]), enc.slice(...b1), enc.slice(...b0), enc.slice(b1[1]));
    assert.equal(await decryptOk(reordered, 'pw-tamper'), false);
  });

  it('ciphertext bit-flip rejected', async () => {
    const flipped = enc.slice();
    flipped[blockBounds()[1][0] + 12 + 5] ^= 0x01;
    assert.equal(await decryptOk(flipped, 'pw-tamper'), false);
  });

  it('truncation rejected', async () => {
    assert.equal(await decryptOk(enc.slice(0, enc.length - 10), 'pw-tamper'), false);
  });

  it('same-length metadata tampering rejected (AAD)', async () => {
    const ml = metaLen();
    const metaStr = new TextDecoder().decode(enc.slice(9, 9 + ml));
    const tamperedMeta = metaStr.replace('600000', '599999');
    assert.equal(tamperedMeta.length, metaStr.length);
    const tampered = concat(enc.slice(0, 9), new TextEncoder().encode(tamperedMeta), enc.slice(9 + ml));
    assert.equal(await decryptOk(tampered, 'pw-tamper'), false);
  });

  it('version downgrade rejected', async () => {
    const downgraded = enc.slice();
    downgraded[4] = 1;
    assert.equal(await decryptOk(downgraded, 'pw-tamper'), false);
  });
});
