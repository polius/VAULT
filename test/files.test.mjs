// File naming and selection helpers.
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import {
  archiveName,
  dedupePaths,
  formatBytes,
  formatDuration,
  fromDataTransfer,
  fromFileList,
  neutralName,
  safeFileName,
} from '../src/js/files.js';

describe('safeFileName', () => {
  for (const [input, expected] of [
    ['report.pdf', 'report.pdf'],
    ['a/b\\c:d*e?f"g<h>i|j', 'a_b_c_d_e_f_g_h_i_j'],
    ['invoice‮fdp.exe', 'invoicefdp.exe'], // right-to-left override removed
    ['tab\tname', 'tab_name'],
    ['  trailing dots...  ', 'trailing dots'],
    ['.bashrc', '.bashrc'],
    ['..', 'file'],
    ['', 'file'],
    ['café', 'café'],
  ]) {
    it(`${JSON.stringify(input)} -> ${JSON.stringify(expected)}`, () => assert.equal(safeFileName(input), expected));
  }
  it('caps the length', () => assert.equal(safeFileName('x'.repeat(1000)).length, 240));
});

describe('formatBytes / formatDuration', () => {
  for (const [n, s] of [
    [0, '0 bytes'],
    [1, '1 byte'],
    [999, '999 bytes'],
    [1000, '1 KB'],
    [1536, '1.5 KB'],
    [4_200_000, '4.2 MB'],
    [123_456_789, '123 MB'],
    [5e12, '5 TB'],
  ]) {
    it(`${n} -> ${s}`, () => assert.equal(formatBytes(n), s));
  }
  it('durations', () => {
    assert.equal(formatDuration(0.2), 'less than a second');
    assert.equal(formatDuration(42), '42 s');
    assert.equal(formatDuration(125), '2 min 5 s');
    assert.equal(formatDuration(7260), '2 h 1 min');
  });
});

describe('selections', () => {
  const f = (name, rel = '') => ({ name, size: 1, webkitRelativePath: rel });

  it('keeps folder-relative paths', () => {
    const s = fromFileList([f('a.txt', 'photos/a.txt'), f('b.txt', 'photos/x/b.txt')]);
    assert.deepEqual(
      s.files.map((x) => x.path),
      ['photos/a.txt', 'photos/x/b.txt'],
    );
    assert.equal(archiveName(s), 'photos.zip');
  });

  it('names loose files by date', () => {
    const s = fromFileList([f('a.txt'), f('b.txt')]);
    assert.equal(archiveName(s, new Date('2026-10-25T12:00:00Z')), 'files-2026-10-25.zip');
  });

  it('makes duplicate names unique, case-insensitively', () => {
    const s = dedupePaths(fromFileList([f('a.txt'), f('A.txt'), f('a.txt'), f('README')]));
    assert.deepEqual(
      s.files.map((x) => x.path),
      ['a.txt', 'A (2).txt', 'a (3).txt', 'README'],
    );
  });

  it('neutral names reveal nothing about the input', () => {
    assert.match(neutralName(new Date('2026-10-25T00:00:00Z')), /^vault-2026-10-25-[0-9a-f]{6}\.vault$/);
  });
});

describe('fromDataTransfer (drag and drop)', () => {
  // Minimal FileSystemEntry fakes. readEntries returns children in batches, as
  // Chromium does (100 at a time), so the reader must loop until empty.
  const fileEntry = (name) => ({
    name,
    isFile: true,
    isDirectory: false,
    file: (ok) => ok({ name, size: name.length }),
  });
  const dirEntry = (name, children) => ({
    name,
    isFile: false,
    isDirectory: true,
    createReader() {
      const batches = [children.slice(0, 2), children.slice(2), []];
      return { readEntries: (ok) => ok(batches.shift() ?? []) };
    },
  });
  const item = (entry) => ({
    kind: 'file',
    webkitGetAsEntry: () => entry,
    getAsFile: () => (entry.isFile ? { name: entry.name, size: 1 } : null),
  });

  it('walks folders, keeps paths, reads every batch and keeps empty folders', async () => {
    const tree = dirEntry('album', [fileEntry('1.jpg'), fileEntry('2.jpg'), fileEntry('3.jpg'), dirEntry('empty', [])]);
    const sel = await fromDataTransfer({ items: [item(tree), item(fileEntry('loose.txt'))] });
    assert.deepEqual(
      sel.files.map((f) => f.path),
      ['album/1.jpg', 'album/2.jpg', 'album/3.jpg', 'loose.txt'],
    );
    assert.deepEqual(sel.dirs, ['album/empty']);
  });

  it('takes plain files from getAsFile(), without touching the entries API', async () => {
    const broken = { name: 'a.txt', isFile: true, file: (_ok, fail) => fail(new Error('Path does not exist')) };
    const sel = await fromDataTransfer({ items: [item(broken)] });
    assert.deepEqual(
      sel.files.map((f) => f.path),
      ['a.txt'],
    );
  });

  it('falls back to the plain file list without the entries API', async () => {
    const sel = await fromDataTransfer({ items: [], files: [{ name: 'a.txt', size: 1 }] });
    assert.deepEqual(
      sel.files.map((f) => f.path),
      ['a.txt'],
    );
  });
});
