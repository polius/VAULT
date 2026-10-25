import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test as base, expect } from '@playwright/test';

export { expect };

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
export const VECTORS = new URL('../../test/vectors/', import.meta.url);

// Every test gets a temp dir, and fails if the page logged an error, hit a CSP
// or Trusted Types violation, or requested anything from another origin.
export const test = base.extend({
  // biome-ignore lint/correctness/noEmptyPattern: Playwright fixtures declare their dependencies by destructuring
  work: async ({}, use) => {
    const dir = await mkdtemp(path.join(tmpdir(), 'vault-e2e-'));
    await use(dir);
    await rm(dir, { recursive: true, force: true });
  },
  problems: async ({ page, baseURL }, use) => {
    const problems = [];
    const origin = new URL(baseURL).origin;
    page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
    page.on('console', (m) => {
      if (m.type() === 'error') problems.push(`console.error: ${m.text()}`);
    });
    page.on('request', (r) => {
      const u = new URL(r.url());
      if (!['blob:', 'data:'].includes(u.protocol) && u.origin !== origin)
        problems.push(`third-party request: ${r.url()}`);
    });
    await use(problems);
    expect(problems, problems.join('\n')).toEqual([]);
  },
});

export async function makeFile(dir, name, size, fill) {
  const file = path.join(dir, name);
  const data = fill === undefined ? randomBytes(size) : Buffer.alloc(size, fill);
  await writeFile(file, data);
  return { path: file, data, hash: sha256(data) };
}

// showSaveFilePicker has no automation surface, so the fs sink gets a shim that
// streams written chunks to Node. It enforces the real writable contract
// (no overlapping writes, closed streams reject) and records aborts.
export async function installFsShim(page) {
  const cap = { chunks: [], picks: 0, aborted: false, closed: false, names: [] };
  await page.exposeBinding('__vaultFs', (_src, op, data) => {
    if (op === 'pick') {
      cap.picks++;
      cap.names.push(data);
    } else if (op === 'chunk') cap.chunks.push(Buffer.from(data, 'base64'));
    else if (op === 'close') cap.closed = true;
    else if (op === 'abort') cap.aborted = true;
  });
  await page.addInitScript(() => {
    const b64 = (u8) => {
      let s = '';
      for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
      return btoa(s);
    };
    window.showSaveFilePicker = async (opts) => {
      await window.__vaultFs('pick', opts.suggestedName);
      return {
        name: opts.suggestedName,
        async createWritable() {
          let busy = false;
          let closed = false;
          return {
            async write(data) {
              if (closed) throw new DOMException('closed', 'InvalidStateError');
              if (busy) throw new DOMException('overlapping write', 'InvalidStateError');
              busy = true;
              try {
                await window.__vaultFs('chunk', b64(new Uint8Array(data.buffer, data.byteOffset, data.byteLength)));
              } finally {
                busy = false;
              }
            },
            async close() {
              closed = true;
              await window.__vaultFs('close');
            },
            async abort() {
              closed = true;
              await window.__vaultFs('abort');
            },
          };
        },
      };
    };
  });
  cap.bytes = () => Buffer.concat(cap.chunks);
  return cap;
}

export async function openApp(page, sink) {
  await page.goto(sink ? `/?sink=${sink}` : '/', { waitUntil: 'commit' });
  await page.locator('html[data-ready]').waitFor({ state: 'attached' });
  if (sink === 'sw')
    await page.waitForFunction(() => navigator.serviceWorker.controller !== null, null, { timeout: 20_000 });
}

export async function pick(page, files) {
  await page.setInputFiles('#pickFiles', files);
}

export async function encrypt(page, password, { confirm = password } = {}) {
  await expect(page.locator('#encForm')).toBeVisible();
  await page.fill('#encPwd', password);
  if (confirm !== null) await page.fill('#encPwd2', confirm);
  await page.click('#encGo');
}

export async function decrypt(page, password) {
  await expect(page.locator('#decForm')).toBeVisible();
  await page.fill('#decPwd', password);
  await page.click('#decGo');
}

// Runs `action`, returns the bytes the sink produced.
export async function capture(page, sink, fsCap, action, dir, name = 'out.bin') {
  if (sink === 'fs') {
    const before = fsCap.chunks.length;
    fsCap.closed = false;
    await action();
    await expect.poll(() => fsCap.closed, { timeout: 60_000 }).toBe(true);
    return { bytes: Buffer.concat(fsCap.chunks.slice(before)), name: fsCap.names.at(-1) };
  }
  const download = page.waitForEvent('download', { timeout: 60_000 });
  await action();
  const dl = await download;
  const file = path.join(dir, name);
  await dl.saveAs(file);
  return { bytes: await readFile(file), name: dl.suggestedFilename() };
}

export const STRONG = 'orbit-velvet-quarry-lantern-mosaic-tundra';

// Names in the origin-private file system, or null where the browser (such as
// Playwright's WebKit) doesn't provide one.
export async function opfsEntries(page) {
  return page.evaluate(async () => {
    let root;
    try {
      root = await navigator.storage.getDirectory();
    } catch {
      return null;
    }
    const out = [];
    for await (const name of root.keys()) out.push(name);
    return out;
  });
}

export async function expectNoOpfsLeftovers(page) {
  const entries = await opfsEntries(page);
  if (entries !== null) expect(entries).toEqual([]);
}
