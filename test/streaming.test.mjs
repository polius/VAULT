// Flat-memory assertions: while streaming through the fs sink (writing to real
// disk), peak RSS must stay near 1x the input instead of multiple full copies.
import { describe, it, before, after } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { MIB, randU8, encryptRun, decryptRun, getEl } from './dom-stub.mjs';
import { makeTempDir, cleanupTempDir, installDiskFsSink, resetSinks } from './fake-sinks.mjs';
import { sinkState } from '../src/js/sink.js';

function rssPeakDelta() {
  const base = process.memoryUsage().rss;
  const samples = [base];
  const t = setInterval(() => samples.push(process.memoryUsage().rss), 20);
  return async (fn) => {
    try { await fn(); } finally { clearInterval(t); }
    return Math.max(...samples, process.memoryUsage().rss) - base;
  };
}

describe('flat memory while streaming to disk', () => {
  const SIZE = 128 * MIB;
  let dir;
  before(async () => { dir = await makeTempDir(); });
  after(async () => { await cleanupTempDir(dir); resetSinks(); });

  it('encrypt peak RSS delta stays under ~1.5x input size', async () => {
    const pt = randU8(SIZE);
    installDiskFsSink(dir);
    sinkState.forced = 'fs';
    const delta = await rssPeakDelta()(async () => {
      await encryptRun(pt, 'big.bin', 'memtest');
      assert.equal(getEl('encLog').className, 'status-log success');
    });
    resetSinks();
    // Disk-backed streaming measures ~1.5x locally (node:fs write buffering
    // accounts for the slack over 1x); the pre-streaming code measured ~4x.
    assert.ok(delta < 2 * SIZE, `encrypt peak delta ${(delta / MIB).toFixed(0)} MB >= 2x input`);
  });

  it('decrypt peak RSS delta stays under ~1.5x input size', async () => {
    const pt = randU8(SIZE);
    installDiskFsSink(dir);
    sinkState.forced = 'fs';
    await encryptRun(pt, 'big.bin', 'memtest');
    const enc = await readFile(path.join(dir, 'big.bin.vault'));
    const delta = await rssPeakDelta()(async () => {
      await decryptRun(enc, 'memtest');
      assert.equal(getEl('decLog').className, 'status-log success');
    });
    resetSinks();
    assert.ok(delta < 2 * SIZE, `decrypt peak delta ${(delta / MIB).toFixed(0)} MB >= 2x input`);
  });
});
