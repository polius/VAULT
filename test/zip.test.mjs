// The streaming ZIP writer: exact planned size, CRC-32, path safety, ZIP64,
// and archives that real tools (Python's zipfile, unzip) accept.
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import zlib from 'node:zlib';
import { crc32, planZip, safeEntryPath, zipStream } from '../src/js/zip.js';
import { collect, randU8 } from './helpers.mjs';

const has = (cmd, flag = '--version') => {
  try {
    execFileSync(cmd, [flag], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
};
const PYTHON = has('python3');

const entries = () => {
  const data = { a: new TextEncoder().encode('hello'), b: randU8(70_000) };
  return [
    { path: 'photos/a.txt', size: 5, lastModified: Date.UTC(2024, 0, 2, 3, 4, 6), data: data.a },
    { path: 'photos/sub/ünïcode 名前.bin', size: data.b.length, lastModified: Date.now(), data: data.b },
    { path: 'photos/empty.txt', size: 0, lastModified: Date.now(), data: new Uint8Array(0) },
    { path: 'photos/empty-folder', dir: true },
  ];
};

async function build(list, opts) {
  const plan = planZip(list, opts);
  const bytes = await collect(
    zipStream(plan, async function* (e) {
      for (let i = 0; i < e.data.length; i += 1000) yield e.data.subarray(i, i + 1000);
    }),
  );
  return { plan, bytes };
}

describe('crc32', () => {
  it('matches zlib for many lengths', () => {
    for (const n of [0, 1, 2, 3, 4, 5, 7, 8, 63, 64, 1000, 65537]) {
      const b = randU8(n);
      assert.equal(crc32(b), zlib.crc32(b), `length ${n}`);
    }
  });
  it('is incremental', () => {
    const b = randU8(10_000);
    assert.equal(crc32(b.subarray(3333), crc32(b.subarray(0, 3333))), zlib.crc32(b));
  });
});

describe('safeEntryPath', () => {
  for (const [input, expected] of [
    ['a/b.txt', 'a/b.txt'],
    ['../../etc/passwd', 'etc/passwd'],
    ['/abs/path', 'abs/path'],
    ['a\\b\\c', 'a/b/c'],
    ['a/./b//c', 'a/b/c'],
    ['bad\u0001name', 'bad_name'],
  ]) {
    it(`${JSON.stringify(input)} -> ${expected}`, () => assert.equal(safeEntryPath(input), expected));
  }
  it('rejects paths that normalize to nothing, and duplicates', () => {
    assert.throws(() => planZip([{ path: '../..', size: 0 }]));
    assert.throws(() =>
      planZip([
        { path: 'a', size: 0 },
        { path: './a', size: 0 },
      ]),
    );
  });
});

describe('zipStream', () => {
  let dir;
  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'vault-zip-'));
  });
  after(() => rm(dir, { recursive: true, force: true }));

  for (const forceZip64 of [false, true]) {
    it(`output length equals the plan (${forceZip64 ? 'ZIP64' : 'ZIP32'})`, async () => {
      const { plan, bytes } = await build(entries(), { forceZip64 });
      assert.equal(bytes.length, plan.size);
    });

    it(`Python zipfile reads it back exactly (${forceZip64 ? 'ZIP64' : 'ZIP32'})`, {
      skip: !PYTHON && 'python3 not found',
    }, async () => {
      const list = entries();
      const { bytes } = await build(list, { forceZip64 });
      const file = path.join(dir, `t${forceZip64 ? 64 : 32}.zip`);
      await writeFile(file, bytes);
      const out = JSON.parse(
        execFileSync('python3', [
          '-I',
          '-c',
          `import zipfile,json,hashlib,sys
z=zipfile.ZipFile(sys.argv[1])
assert z.testzip() is None
print(json.dumps({i.filename:[i.file_size,hashlib.sha256(z.read(i)).hexdigest(),i.is_dir()] for i in z.infolist()}))`,
          file,
        ]).toString(),
      );
      const sha = (b) => createHash('sha256').update(b).digest('hex');
      for (const e of list) {
        const key = e.dir ? `${e.path}/` : e.path;
        assert.ok(out[key], `missing ${key}`);
        if (!e.dir) assert.deepEqual(out[key].slice(0, 2), [e.size, sha(e.data)]);
        else assert.equal(out[key][2], true);
      }
    });
  }

  it('unzip -t accepts it', { skip: !has('unzip', '-v') && 'unzip not found' }, async () => {
    const { bytes } = await build(entries(), { forceZip64: true });
    const file = path.join(dir, 'u.zip');
    await writeFile(file, bytes);
    execFileSync('unzip', ['-tq', file]);
  });

  it('uses ZIP64 only when needed', () => {
    const small = planZip([{ path: 'a', size: 10 }]);
    assert.equal(small.zip64End, false);
    assert.equal(small.entries[0].zip64, false);
    const big = planZip([{ path: 'a', size: 5 * 2 ** 30 }]);
    assert.equal(big.entries[0].zip64, true);
    const many = planZip(Array.from({ length: 70_000 }, (_, i) => ({ path: `f${i}`, size: 0 })));
    assert.equal(many.zip64End, true);
  });

  it('rejects an entry that changes size while being read', async () => {
    const plan = planZip([{ path: 'a', size: 10 }]);
    await assert.rejects(
      collect(
        zipStream(plan, async function* () {
          yield new Uint8Array(5);
        }),
      ),
      /shrank/,
    );
  });
});
