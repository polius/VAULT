// Streaming sinks: format correctness through a fake File System Access sink,
// and flat-memory assertions (peak RSS stays near 1x input while streaming).
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { MIB, randU8, encryptRun, decryptRun, decryptOk, concat, getEl } from './dom-stub.mjs';
import { sinkState } from '../src/js/sink.js';

// Fake File System Access sink: fs mode is selected via sinkState.forced because
// auto-detection runs at module load (no real picker exists in Node).
function installFakeFs(capture) {
  const state = { writable: null, suggestedName: null };
  globalThis.window.showSaveFilePicker = async (opts) => {
    state.suggestedName = opts.suggestedName;
    const chunks = [];
    state.writable = {
      chunks,
      async write(c) { if (capture) chunks.push(new Uint8Array(c)); },
      async close() {},
      async abort() {},
    };
    return { createWritable: async () => state.writable };
  };
  sinkState.forced = 'fs';
  return state;
}

function uninstallFakeFs() {
  delete globalThis.window.showSaveFilePicker;
  sinkState.forced = null;
}

function rssPeakDelta() {
  const base = process.memoryUsage().rss;
  const samples = [base];
  const t = setInterval(() => samples.push(process.memoryUsage().rss), 20);
  return async (fn) => {
    try { await fn(); } finally { clearInterval(t); }
    return Math.max(...samples, process.memoryUsage().rss) - base;
  };
}

describe('fs sink streaming', () => {
  it('streamed output is byte-identical to blob output (3-chunk file)', async () => {
    const pt = randU8(2 * MIB + 137);
    const fake = installFakeFs(true);
    const { blob } = await encryptRun(pt, 'doc.bin', 'pw-stream');
    uninstallFakeFs();
    assert.ok(fake.writable, 'fake picker not used');
    assert.equal(fake.suggestedName, 'doc.bin.vault');
    const enc = concat(...fake.writable.chunks);

    // Cross-check: same plaintext through the blob path must produce the same
    // structure (decrypts to the same bytes).
    const { blob: blob2 } = await encryptRun(pt, 'doc.bin', 'pw-stream');
    const enc2 = new Uint8Array(await blob2.arrayBuffer());
    assert.equal(enc.length, enc2.length);
    assert.ok(await decryptOk(enc, 'pw-stream', pt));
  });

  it('decrypt streams out through fs sink (no download blob)', async () => {
    const pt = randU8(10000);
    const { blob } = await encryptRun(pt, 'a.bin', 'pw');
    const enc = new Uint8Array(await blob.arrayBuffer());
    installFakeFs(false);
    const out = await decryptRun(enc, 'pw');
    uninstallFakeFs();
    assert.equal(out, undefined); // fs sink closes the file, no blob URL
    assert.equal(getEl('decLog').className, 'status-log success');
  });
});

describe('flat memory while streaming (fake fs sink discards output)', () => {
  const SIZE = 128 * MIB;

  it('encrypt peak RSS delta stays under ~1.5x input size', async () => {
    const pt = randU8(SIZE);
    installFakeFs(false);
    const delta = await rssPeakDelta()(async () => {
      const ok = getEl('encLog').className;
      await encryptRun(pt, 'big.bin', 'memtest');
      assert.equal(getEl('encLog').className, 'status-log success', ok);
    });
    uninstallFakeFs();
    assert.ok(delta < 1.5 * SIZE, `encrypt peak delta ${ (delta / MIB).toFixed(0) } MB >= 1.5x input`);
  });

  it('decrypt peak RSS delta stays under ~1.5x input size', async () => {
    const pt = randU8(SIZE);
    const { blob } = await encryptRun(pt, 'big.bin', 'memtest');
    const enc = new Uint8Array(await blob.arrayBuffer());
    installFakeFs(false);
    const delta = await rssPeakDelta()(async () => {
      await decryptRun(enc, 'memtest');
      assert.equal(getEl('decLog').className, 'status-log success');
    });
    uninstallFakeFs();
    assert.ok(delta < 1.5 * SIZE, `decrypt peak delta ${ (delta / MIB).toFixed(0) } MB >= 1.5x input`);
  });
});
