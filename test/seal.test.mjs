// The seal's pattern is a pure function of the salt: the same file always
// draws the same seal, and different salts draw different ones.
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { ringPaths, sealNumber } from '../src/js/seal.js';

const salt = (...bytes) => Uint8Array.from(bytes);
const A = salt(0x7c, 0x3a, 0x91, 0xf2, 0x0b, 0x5e, 0x44, 0xd1, 0xa8, 0x6f, 0x0c, 0x2e, 0x9b, 0x17, 0xd3, 0x50);
const B = salt(0xe4, 0x1b, 0x07, 0xc9, 0x5d, 0x33, 0x82, 0xaa, 0x10, 0xf6, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05);

describe('seal number', () => {
  it('is the first six bytes of the salt, in groups of four', () => {
    assert.equal(sealNumber(A), '7C3A 91F2 0B5E');
    assert.equal(sealNumber(salt(0, 1, 2, 3, 4, 5, 6)), '0001 0203 0405');
  });
});

describe('seal pattern', () => {
  it('is the same every time for the same salt', () => {
    assert.deepEqual(ringPaths(A), ringPaths(A.slice()));
  });

  it('differs between salts', () => {
    assert.notDeepEqual(ringPaths(A), ringPaths(B));
  });

  it('has three rings, each with the number of strands its salt byte picks', () => {
    const rings = ringPaths(A);
    assert.equal(rings.length, 3);
    assert.deepEqual(
      rings.map((r) => r.length),
      [5 + (A[1] % 3), 4 + (A[4] % 3), 3 + (A[7] % 2)],
    );
    for (const d of rings.flat()) assert.match(d, /^M[\d.]+ [\d.]+(L[\d.]+ [\d.]+)+Z$/);
  });

  it('stays inside the drawing, whatever the salt', () => {
    for (let v = 0; v < 256; v += 5) {
      for (const d of ringPaths(new Uint8Array(16).fill(v)).flat()) {
        for (const [, x, y] of d.matchAll(/[ML]([\d.]+) ([\d.]+)/g)) {
          const r = Math.hypot(Number(x) - 160, Number(y) - 160);
          assert.ok(r > 24 && r < 136, `radius ${r.toFixed(1)} for salt byte ${v}`);
        }
      }
    }
  });

  it('draws fewer strands for small sizes', () => {
    assert.deepEqual(
      ringPaths(A, true).map((r) => r.length),
      [3, 2, 2],
    );
  });

  it('accepts salts shorter than nine bytes', () => {
    assert.equal(ringPaths(salt(1, 2, 3)).length, 3);
  });
});
