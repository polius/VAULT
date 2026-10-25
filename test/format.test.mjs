// Format v3: round trips, the exact-size promise, and every way a file can be
// wrong (password, tampering, truncation, trailing data, forged headers).
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { CHUNK, E, encrypt, encryptedSize, fileSource, inspect, unlock } from '../src/js/format.js';
import {
  bytesSource,
  collect,
  concat,
  decryptBytes,
  encryptBytes,
  FAST,
  MIB,
  parseV3,
  randU8,
  rejectsWith,
} from './helpers.mjs';

const te = new TextEncoder();

describe('v3 round trips', () => {
  for (const size of [0, 1, 4095, 4096, 4097, 3 * 4096 + 17]) {
    it(`size ${size} with 4 KiB chunks`, async () => {
      const plain = randU8(size);
      const enc = await encryptBytes(plain, { name: `doc-${size}.bin` });
      assert.equal(
        enc.length,
        encryptedSize({ meta: { name: `doc-${size}.bin`, type: 'file' }, size, kdf: FAST, chunk: 4096 }),
      );
      const { session, plain: out } = await decryptBytes(enc);
      assert.deepEqual(session.meta, { name: `doc-${size}.bin`, size, type: 'file', count: undefined });
      assert.ok(Buffer.from(out).equals(Buffer.from(plain)));
    });
  }

  it('default 1 MiB chunks and default Argon2id cost, from a Blob source', async () => {
    const plain = randU8(2 * MIB + 137);
    const meta = { name: 'big.bin', type: 'file' };
    const enc = await collect(
      encrypt({ password: 'default-cost', meta, size: plain.length, source: fileSource(new Blob([plain])) }),
    );
    assert.equal(enc.length, encryptedSize({ meta, size: plain.length }));
    const info = await inspect(new Blob([enc]));
    assert.deepEqual([info.params.m, info.params.t, info.params.p, info.params.chunk], [65536, 3, 1, CHUNK]);
    const { plain: out } = await decryptBytes(enc, 'default-cost');
    assert.ok(Buffer.from(out).equals(Buffer.from(plain)));
  });

  it('unicode names and passwords; NFD and NFC passwords are the same password', async () => {
    const plain = randU8(100);
    const nfd = 'café ü pässwörd'.normalize('NFD');
    const enc = await encryptBytes(plain, { name: 'résumé – 履歴書.pdf', password: nfd });
    const { session } = await decryptBytes(enc, nfd.normalize('NFC'));
    assert.equal(session.meta.name, 'résumé – 履歴書.pdf');
  });

  it('progress reaches the full size, and phases run kdf then encrypt', async () => {
    const plain = randU8(10_000);
    const seen = [];
    const phases = [];
    await collect(
      encrypt({
        password: 'p',
        meta: { name: 'p.bin', type: 'file' },
        size: plain.length,
        source: bytesSource(plain),
        kdf: FAST,
        chunk: 4096,
        onPhase: (p) => phases.push(p),
        onProgress: (d, t) => seen.push([d, t]),
      }),
    );
    assert.deepEqual(phases, ['kdf', 'encrypt']);
    assert.deepEqual(seen.at(-1), [10_000, 10_000]);
  });
});

describe('v3 metadata privacy', () => {
  it('the cleartext header holds no file name or size', async () => {
    const enc = await encryptBytes(randU8(12345), { name: 'passport-scan.jpg' });
    const header = new TextDecoder().decode(enc.subarray(0, parseV3(enc).headerLen));
    assert.ok(!header.includes('passport'));
    assert.ok(!header.includes('12345'));
    assert.deepEqual(Object.keys(JSON.parse(header.slice(9))).sort(), [
      'chunk',
      'commit',
      'kdf',
      'm',
      'meta',
      'p',
      'salt',
      't',
    ]);
  });

  it('metadata is padded, so similar names give the same length', async () => {
    const a = parseV3(await encryptBytes(randU8(1), { name: 'a' })).params.meta;
    const b = parseV3(await encryptBytes(randU8(1), { name: 'a-somewhat-longer-file-name.txt' })).params.meta;
    assert.equal(a, b);
    assert.equal(a % 256, 0);
  });
});

describe('v3 password and integrity', () => {
  it('wrong password fails at unlock, before any output', async () => {
    const enc = await encryptBytes(randU8(5000));
    await rejectsWith(unlock(new Blob([enc]), 'nope'), E.WRONG_PASSWORD);
  });

  it('empty files are authenticated: a wrong password is rejected (audit H1)', async () => {
    const enc = await encryptBytes(new Uint8Array(0));
    await rejectsWith(unlock(new Blob([enc]), 'nope'), E.WRONG_PASSWORD);
    const { plain } = await decryptBytes(enc);
    assert.equal(plain.length, 0);
  });

  it('a header-only file cannot pass as a valid empty file (audit H1)', async () => {
    const enc = await encryptBytes(new Uint8Array(0));
    const { headerLen } = parseV3(enc);
    await rejectsWith(unlock(new Blob([enc.subarray(0, headerLen)]), 'pw'), E.CORRUPTED);
    // Dropping only the final (empty) data frame is caught too.
    await rejectsWith(unlock(new Blob([enc.subarray(0, enc.length - 28)]), 'pw'), E.CORRUPTED);
  });

  it('trailing bytes are rejected (audit M2)', async () => {
    const enc = await encryptBytes(randU8(5000));
    await rejectsWith(unlock(new Blob([concat(enc, randU8(1))]), 'pw'), E.CORRUPTED);
  });

  it('truncation is rejected', async () => {
    const enc = await encryptBytes(randU8(5000));
    await rejectsWith(unlock(new Blob([enc.subarray(0, enc.length - 1)]), 'pw'), E.CORRUPTED);
  });

  it('reordered data frames are rejected', async () => {
    const enc = await encryptBytes(randU8(3 * 4096));
    const { frames } = parseV3(enc);
    const [, f1, f2] = frames;
    const swapped = concat(enc.subarray(0, f1[0]), enc.subarray(...f2), enc.subarray(...f1), enc.subarray(f2[1]));
    const session = await unlock(new Blob([swapped]), 'pw');
    await rejectsWith(collect(session.chunks()), E.CORRUPTED);
  });

  it('a flipped bit in a data frame is rejected', async () => {
    const enc = await encryptBytes(randU8(3 * 4096));
    const { frames } = parseV3(enc);
    enc[frames[2][0] + 20] ^= 1;
    const session = await unlock(new Blob([enc]), 'pw');
    await rejectsWith(collect(session.chunks()), E.CORRUPTED);
  });

  it('a flipped bit in the metadata frame is rejected at unlock', async () => {
    const enc = await encryptBytes(randU8(100));
    enc[parseV3(enc).frames[0][0] + 15] ^= 1;
    await rejectsWith(unlock(new Blob([enc]), 'pw'), E.CORRUPTED);
  });

  it('editing a header field is rejected', async () => {
    const enc = await encryptBytes(randU8(100));
    const { headerLen } = parseV3(enc);
    const at = Buffer.from(enc.subarray(0, headerLen)).indexOf('"t":1') + 4;
    enc[at] = '2'.charCodeAt(0);
    // A different cost gives a different key, so the commitment no longer matches.
    await rejectsWith(unlock(new Blob([enc]), 'pw'), E.WRONG_PASSWORD);
  });

  it('a frame from another file with the same password is rejected', async () => {
    const a = await encryptBytes(randU8(5000));
    const b = await encryptBytes(randU8(5000));
    const pa = parseV3(a);
    const pb = parseV3(b);
    const spliced = concat(a.subarray(0, pa.frames[1][0]), b.subarray(...pb.frames[1]), a.subarray(pa.frames[1][1]));
    const session = await unlock(new Blob([spliced]), 'pw');
    await rejectsWith(collect(session.chunks()), E.CORRUPTED);
  });

  it('a source that changes size while being read is rejected', async () => {
    const plain = randU8(5000);
    await rejectsWith(encryptBytes(plain, { source: bytesSource(plain.subarray(0, 4000)) }), E.SOURCE_CHANGED);
    await rejectsWith(encryptBytes(plain, { source: bytesSource(concat(plain, plain)) }), E.SOURCE_CHANGED);
  });

  it('cancellation stops encryption and decryption', async () => {
    const plain = randU8(10 * 4096);
    const controller = new AbortController();
    const gen = encrypt({
      password: 'pw',
      meta: { name: 'x', type: 'file' },
      size: plain.length,
      source: bytesSource(plain),
      kdf: FAST,
      chunk: 4096,
      signal: controller.signal,
    });
    await gen.next();
    await gen.next();
    await gen.next();
    controller.abort();
    await assert.rejects(gen.next(), { name: 'AbortError' });
  });
});

describe('header validation', () => {
  const header = (version, params) => {
    const json = te.encode(JSON.stringify(params));
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, json.length, true);
    return concat(te.encode('AES1'), new Uint8Array([version]), len, json, new Uint8Array(64));
  };
  const good = {
    kdf: 'argon2id',
    m: 65536,
    t: 3,
    p: 1,
    salt: btoa('s'.repeat(16)),
    chunk: CHUNK,
    meta: 256,
    commit: btoa('c'.repeat(32)),
  };

  it('not a VAULT file', async () => {
    await rejectsWith(inspect(new Blob([te.encode('%PDF-1.7 hello world')])), E.NOT_VAULT);
    await rejectsWith(inspect(new Blob([new Uint8Array(3)])), E.NOT_VAULT);
  });

  it('newer format version', async () => {
    await rejectsWith(inspect(new Blob([header(4, good)])), E.UNSUPPORTED);
  });

  it('accepts a well-formed v3 header', async () => {
    const info = await inspect(new Blob([header(3, good)]));
    assert.equal(info.version, 3);
    assert.equal(info.legacy, null);
  });

  const bad = [
    ['unknown kdf', { kdf: 'scrypt' }],
    ['memory too high (DoS)', { m: 4_194_304 }],
    ['memory too low', { m: 1024 }],
    ['too many passes (DoS)', { t: 1000 }],
    ['lanes', { p: 64 }],
    ['short salt', { salt: btoa('s') }],
    ['salt not base64', { salt: '***' }],
    ['tiny chunk', { chunk: 1 }],
    ['huge chunk', { chunk: 1 << 30 }],
    ['meta too large', { meta: 1 << 20 }],
    ['commit length', { commit: btoa('c') }],
  ];
  for (const [name, override] of bad) {
    it(`rejects ${name}`, async () => {
      await rejectsWith(inspect(new Blob([header(3, { ...good, ...override })])), E.BAD_HEADER);
    });
  }

  it('rejects malformed JSON and absurd lengths', async () => {
    const raw = concat(te.encode('AES1'), new Uint8Array([3]), new Uint8Array([5, 0, 0, 0]), te.encode('{nope'));
    await rejectsWith(inspect(new Blob([raw])), E.BAD_HEADER);
    const huge = concat(
      te.encode('AES1'),
      new Uint8Array([3]),
      new Uint8Array([0xff, 0xff, 0xff, 0x7f]),
      te.encode('{}'),
    );
    await rejectsWith(inspect(new Blob([huge])), E.BAD_HEADER);
  });
});

describe('v3 forward-compatibility vector', () => {
  it('decrypts the committed v3 vector', async () => {
    const { readFile } = await import('node:fs/promises');
    const { createHash } = await import('node:crypto');
    const manifest = JSON.parse(await readFile(new URL('./vectors/v3.json', import.meta.url), 'utf8'));
    for (const v of manifest.vectors) {
      const bytes = new Uint8Array(await readFile(new URL(`./vectors/${v.file}`, import.meta.url)));
      const { session, plain } = await decryptBytes(bytes, v.password);
      assert.equal(session.meta.name, v.name);
      assert.equal(createHash('sha256').update(plain).digest('hex'), v.sha256);
    }
  });
});
