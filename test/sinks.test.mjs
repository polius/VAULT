// End-to-end round-trips through every sink mode: blob (in-memory), fs (real
// disk writes), and sw (the real src/sw.js streaming over an OPFS emulator).
import { describe, it, before, after } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { makeTempDir, cleanupTempDir, installDiskFsSink, installSwSink, makeSwBridge, resetSinks } from './fake-sinks.mjs';
import { MIB, randU8, encryptRun, decryptRun, decryptOk, getEl } from './dom-stub.mjs';
import { sinkState } from '../src/js/sink.js';

const SIZE = 2 * MIB + 137; // 3 chunks: 1 MiB, 1 MiB, 137 B

describe('sink round-trips (encrypt -> decrypt per mode)', () => {
  let dir;
  before(async () => { dir = await makeTempDir(); });
  after(async () => { await cleanupTempDir(dir); resetSinks(); });

  it('blob -> blob round-trips', async () => {
    const pt = randU8(SIZE);
    const { blob, outName } = await encryptRun(pt, 'doc.bin', 'pw');
    assert.equal(outName, 'doc.bin.vault');
    const enc = new Uint8Array(await blob.arrayBuffer());
    assert.equal(new TextDecoder().decode(enc.slice(0, 4)), 'AES1');
    assert.ok(await decryptOk(enc, 'pw', pt));
  });

  it('fs -> fs round-trips through real files on disk', async () => {
    const pt = randU8(SIZE);
    const fsState = installDiskFsSink(dir);
    sinkState.forced = 'fs';

    const { blob, outName } = await encryptRun(pt, 'doc.bin', 'pw');
    assert.equal(blob, undefined); // streamed to disk, no blob URL
    assert.equal(outName, null); // no anchor in fs mode
    assert.equal(fsState.suggestedName, 'doc.bin.vault');
    const encOnDisk = await readFile(fsState.path);
    assert.equal(new TextDecoder().decode(encOnDisk.subarray(0, 4)), 'AES1');

    const dec = await decryptRun(encOnDisk, 'pw');
    assert.equal(dec, undefined); // plaintext streamed to disk
    assert.equal(getEl('decLog').className, 'status-log success');
    const ptOnDisk = await readFile(fsState.path);
    assert.ok(ptOnDisk.equals(Buffer.from(pt)));
    resetSinks();
  });

  it('sw -> sw round-trips through real src/sw.js streaming', async () => {
    const pt = randU8(SIZE);
    const opfsDir = path.join(dir, 'opfs');
    const bridge = makeSwBridge();
    installSwSink(opfsDir, bridge);
    sinkState.forced = 'sw';

    const { blob } = await encryptRun(pt, 'doc.bin', 'pw');
    assert.equal(blob, undefined); // delivered via SW response, no blob URL
    const enc = new Uint8Array(await (await bridge.downloads[0].promise).arrayBuffer());
    assert.equal(new TextDecoder().decode(enc.slice(0, 4)), 'AES1');

    const dec = await decryptRun(enc, 'pw');
    assert.equal(dec, undefined);
    const ptOut = new Uint8Array(await (await bridge.downloads[1].promise).arrayBuffer());
    assert.ok(Buffer.from(ptOut).equals(Buffer.from(pt)));
    assert.equal(getEl('decLog').className, 'status-log success');
    resetSinks();
  });

  it('sw serves the full download even when the fetch arrives after end (Firefox race)', async () => {
    // Firefox dispatches the iframe navigation after the page finished streaming
    // small files; deleting the transfer on 'end' used to 404 the download here.
    const pt = randU8(SIZE);
    const bridge = makeSwBridge({ fetchAfterEnd: true });
    installSwSink(path.join(dir, 'opfs-3'), bridge);
    sinkState.forced = 'sw';

    const { blob } = await encryptRun(pt, 'doc.bin', 'pw');
    assert.equal(blob, undefined);
    const enc = new Uint8Array(await (await bridge.downloads[0].promise).arrayBuffer());
    assert.equal(new TextDecoder().decode(enc.slice(0, 4)), 'AES1');

    const dec = await decryptRun(enc, 'pw');
    assert.equal(dec, undefined);
    const ptOut = new Uint8Array(await (await bridge.downloads[1].promise).arrayBuffer());
    assert.ok(Buffer.from(ptOut).equals(Buffer.from(pt)));
    resetSinks();
  });

  it('format is sink-independent: sw-produced .vault decrypts via blob', async () => {
    const pt = randU8(SIZE);
    const bridge = makeSwBridge();
    installSwSink(path.join(dir, 'opfs-2'), bridge);
    sinkState.forced = 'sw';
    await encryptRun(pt, 'doc.bin', 'pw');
    const enc = new Uint8Array(await (await bridge.downloads[0].promise).arrayBuffer());

    resetSinks();
    assert.ok(await decryptOk(enc, 'pw', pt));
  });
});
