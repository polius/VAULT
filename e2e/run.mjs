// VAULT end-to-end: drives real Chromium against the real container and
// round-trips a randomly generated file through encrypt -> decrypt, verifying
// SHA-256 equality of the final output. Cells (one per sink mode):
//
//   sw    Service Worker download — capture via the download event.
//   blob  in-memory fallback — capture via the download event.
//   fs    File System Access API — the OS save dialog has no automation surface,
//         so showSaveFilePicker is shimmed in the page (mirroring FileSync's
//         e2e shim): chunks stream to Node through an exposed binding while the
//         REAL sink.js fs branch runs, then the captured ciphertext is fed back
//         through a blob-mode decrypt and verified.
//
//   node run.mjs --base-url=http://127.0.0.1:8080 --size=16M [--sink=sw|fs|blob]
//
// Exit code 0 = all requested cells verified.

import { chromium } from 'playwright';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const argv = Object.fromEntries(process.argv.slice(2).map((a) => {
  const m = a.match(/^--([a-z-]+)=(.+)$/i);
  return m ? [m[1], m[2]] : [];
}));
const BASE_URL = argv['base-url'] || 'http://127.0.0.1:8080';
const SIZE = Number((argv.size || '16M').replace(/(\d+)[Mm]/, '$1') * 1024 * 1024);
const CELLS = argv.sink ? [argv.sink] : ['sw', 'fs', 'blob'];
const PASSWORD = 'e2e-p@ss-' + randomBytes(4).toString('hex');

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const consoleErrors = [];

// Streams writable.write() chunks to Node and resolves when the page closes the
// writable. Also emulates the real FileSystemWritableFileStream contract: a
// pending write() must block overlapping writes, and closed streams reject.
async function installFsSinkShim(context, cap) {
  await context.exposeBinding('__vaultFsChunk', (_src, chunk) => {
    cap.hash.update(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    cap.bytes += chunk.byteLength;
    cap.chunks.push(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength));
  });
  await context.exposeBinding('__vaultFsDone', () => cap.resolveDone());
  await context.addInitScript(() => {
    window.showSaveFilePicker = async (opts) => ({
      kind: 'file',
      name: opts?.suggestedName || 'shim.bin',
      async createWritable() {
        let busy = false, closed = false;
        return {
          async write(input) {
            if (closed) throw new DOMException('Stream is closed', 'InvalidStateError');
            if (busy) throw new DOMException('write() called during a pending write()', 'InvalidStateError');
            busy = true;
            try {
              let data = input;
              if (data && typeof data === 'object' && data.type === 'write') data = data.data;
              let bytes;
              if (data instanceof Blob) bytes = new Uint8Array(await data.arrayBuffer());
              else if (ArrayBuffer.isView(data)) {
                bytes = new Uint8Array(data.byteLength);
                bytes.set(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
              } else if (data instanceof ArrayBuffer) bytes = new Uint8Array(data.slice(0));
              else throw new Error('FS shim: unsupported write input');
              await window.__vaultFsChunk(bytes);
            } finally {
              busy = false;
            }
          },
          async close() { closed = true; await window.__vaultFsDone(); },
          async abort() { closed = true; try { await window.__vaultFsDone(); } catch {} },
        };
      },
    });
  });
}

async function openCell(browser, sink) {
  const context = await browser.newContext({ acceptDownloads: true });
  const cap = sink === 'fs'
    ? { hash: createHash('sha256'), bytes: 0, chunks: [], done: null, resolveDone: null }
    : null;
  if (cap) {
    cap.done = new Promise((r) => { cap.resolveDone = r; });
    await installFsSinkShim(context, cap);
  }
  const page = await context.newPage();
  page.on('pageerror', (err) => consoleErrors.push(`[${sink} pageerror] ${err.message}`));
  page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(`[${sink} console] ${msg.text()}`); });
  await page.goto(`${BASE_URL}/?sink=${sink}`, { waitUntil: 'load' });
  if (sink === 'sw') {
    await page.waitForFunction(() => navigator.serviceWorker.controller !== null, null, { timeout: 20_000 });
  }
  await page.waitForSelector('#encBtn:not([disabled])', { timeout: 10_000 });
  return { context, page, cap };
}

async function encryptDownload(page, inputPath, outputPath) {
  await page.setInputFiles('#encFile', inputPath);
  await page.fill('#encPwd', PASSWORD);
  const download = page.waitForEvent('download', { timeout: 120_000 });
  await page.click('#encBtn');
  const dl = await download;
  await dl.saveAs(outputPath);
  return dl.suggestedFilename();
}

async function decryptDownload(page, inputPath, outputPath) {
  await page.setInputFiles('#decFile', inputPath);
  await page.fill('#decPwd', PASSWORD);
  const download = page.waitForEvent('download', { timeout: 120_000 });
  await page.click('#decBtn');
  const dl = await download;
  await dl.saveAs(outputPath);
  return dl.suggestedFilename();
}

async function runCell(browser, sink, src) {
  const { context, page, cap } = await openCell(browser, sink);
  try {
    let vaultPath;
    if (sink === 'fs') {
      await page.setInputFiles('#encFile', src.path);
      await page.fill('#encPwd', PASSWORD);
      await page.click('#encBtn');
      await Promise.race([cap.done, new Promise((_, rej) => setTimeout(() => rej(new Error('fs sink never closed')), 120_000))]);
      vaultPath = path.join(src.workDir, 'captured.vault');
      await writeFile(vaultPath, Buffer.concat(cap.chunks));
      if (cap.bytes !== (await readFile(vaultPath)).length) throw new Error('fs shim byte accounting mismatch');
    } else {
      vaultPath = path.join(src.workDir, 'captured.vault');
      const name = await encryptDownload(page, src.path, vaultPath);
      if (!name.endsWith('.vault')) throw new Error(`unexpected download name: ${name}`);
    }

    // Decrypt the captured ciphertext through a shim-free blob page.
    const ctx2 = await browser.newContext({ acceptDownloads: true });
    const page2 = await ctx2.newPage();
    page2.on('pageerror', (err) => consoleErrors.push(`[${sink} pageerror] ${err.message}`));
    await page2.goto(`${BASE_URL}/?sink=blob`, { waitUntil: 'load' });
    await page2.waitForSelector('#decBtn:not([disabled])', { timeout: 10_000 });

    const plainPath = path.join(src.workDir, 'roundtrip.out');
    const decName = await decryptDownload(page2, vaultPath, plainPath);
    if (decName !== path.basename(src.path)) throw new Error(`unexpected decrypted name: ${decName}`);

    const outHash = sha256(await readFile(plainPath));
    if (outHash !== src.hash) {
      throw new Error(`SHA-256 mismatch:\n  in : ${src.hash}\n  out: ${outHash}`);
    }
    await ctx2.close();
    console.log(`[e2e] PASS sink=${sink} — sha256 verified (${(SIZE / 1024 / 1024).toFixed(0)}M)`);
  } finally {
    await context.close().catch(() => {});
  }
}

const workDir = await mkdtemp(path.join(tmpdir(), 'vault-e2e-'));
let exitCode = 0;
try {
  const buf = randomBytes(SIZE);
  const src = {
    workDir,
    path: path.join(workDir, `e2e-${SIZE}.bin`),
    hash: sha256(buf),
  };
  await writeFile(src.path, buf);
  console.log(`[e2e] url=${BASE_URL} size=${(SIZE / 1024 / 1024).toFixed(0)}M cells=${CELLS.join(',')}`);

  const browser = await chromium.launch({ headless: true });
  try {
    for (const sink of CELLS) {
      await runCell(browser, sink, src);
    }
  } finally {
    await browser.close().catch(() => {});
  }
  if (consoleErrors.length) throw new Error('console/page errors during run:\n' + consoleErrors.join('\n'));
} catch (err) {
  exitCode = 1;
  console.error('[e2e] FAIL');
  if (consoleErrors.length) console.error('console/page errors:\n' + consoleErrors.join('\n'));
  console.error(err);
} finally {
  await rm(workDir, { recursive: true, force: true }).catch(() => {});
  process.exit(exitCode);
}
