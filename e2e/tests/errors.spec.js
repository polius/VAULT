// Failures: wrong password, damaged files, wrong file type, cancel. Each must
// produce a specific message and never leave output behind.
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  capture,
  decrypt,
  encrypt,
  expect,
  expectNoOpfsLeftovers,
  installFsShim,
  makeFile,
  openApp,
  pick,
  STRONG,
  test,
  VECTORS,
} from './helpers.js';

async function encrypted(page, work, size = 50_000) {
  const src = await makeFile(work, 'secret.txt', size);
  await pick(page, src.path);
  const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'x.vault');
  const file = path.join(work, 'secret.txt.vault');
  await writeFile(file, enc.bytes);
  await page.click('#againBtn');
  return { file, bytes: enc.bytes };
}

test('wrong password: checked before the save dialog opens (audit M9)', async ({ page, work, problems }) => {
  const fsCap = await installFsShim(page);
  await openApp(page, 'blob');
  const { file } = await encrypted(page, work);
  await page.goto('/?sink=fs');
  await page.locator('html[data-ready]').waitFor({ state: 'attached' });
  await pick(page, file);
  await decrypt(page, 'wrong password');
  await expect(page.locator('#messageText')).toHaveText('Wrong password. Check it and try again.');
  await expect(page.locator('#decPwd')).toHaveValue('');
  await expect(page.locator('#decPwd')).toBeFocused();
  expect(fsCap.picks).toBe(0);
  const dec = await capture(page, 'fs', fsCap, () => decrypt(page, STRONG), work);
  expect(dec.bytes.length).toBe(50_000);
  expect(fsCap.picks).toBe(1);
  expect(problems).toEqual([]);
});

test('a damaged file says so, keeps the password, and discards partial output', async ({ page, work, problems }) => {
  const fsCap = await installFsShim(page);
  await openApp(page, 'fs');
  const src = await makeFile(work, 'big.bin', 3 * 1048576);
  await pick(page, src.path);
  const enc = await capture(page, 'fs', fsCap, () => encrypt(page, STRONG), work);
  const bytes = Buffer.from(enc.bytes);
  bytes[bytes.length - 100] ^= 1; // last frame
  const file = path.join(work, 'damaged.vault');
  await writeFile(file, bytes);
  await page.click('#againBtn');
  await pick(page, file);
  await decrypt(page, STRONG);
  await expect(page.locator('#messageText')).toHaveText(
    'The file is damaged or was changed after it was encrypted. The partial output was discarded.',
  );
  expect(fsCap.aborted).toBe(true);
  expect(problems).toEqual([]);
});

test('a truncated file is refused before anything is written', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const { bytes } = await encrypted(page, work);
  const file = path.join(work, 'cut.vault');
  await writeFile(file, bytes.subarray(0, bytes.length - 10));
  await pick(page, file);
  await decrypt(page, STRONG);
  await expect(page.locator('#messageText')).toHaveText(
    'The file is damaged or was changed after it was encrypted, so it can’t be opened.',
  );
  await expect(page.locator('#decPwd')).not.toHaveValue('');
  expect(problems).toEqual([]);
});

test('a file that is not a VAULT file goes to Encrypt; forcing Decrypt explains why not', async ({
  page,
  work,
  problems,
}) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'photo.jpg', 2000);
  await pick(page, src.path);
  await expect(page.locator('#modeEnc')).toBeChecked();
  await page.click('label.mode-dec');
  await expect(page.locator('#vaultInfo')).toHaveText(
    "This isn't a VAULT file. Choose Encrypt to protect it, or pick a .vault file.",
  );
  await expect(page.locator('#decGo')).toBeDisabled();
  expect(problems).toEqual([]);
});

test('an empty VAULT 1.x file is refused with an explanation (audit H1)', async ({ page, problems }) => {
  await openApp(page, 'blob');
  await pick(page, new URL('v2-0.vault', VECTORS).pathname);
  await decrypt(page, 'anything');
  await expect(page.locator('#messageText')).toContainText('empty file from VAULT 1.x');
  expect(problems).toEqual([]);
});

test('a file from a newer VAULT is recognised', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const file = path.join(work, 'future.vault');
  await writeFile(file, Buffer.concat([Buffer.from('AES1'), Buffer.from([9]), Buffer.alloc(40)]));
  await pick(page, file);
  await expect(page.locator('#modeDec')).toBeChecked();
  await expect(page.locator('#vaultInfo')).toContainText('newer version of VAULT');
  expect(problems).toEqual([]);
});

// Big inputs, so these run one after another in a single worker rather than
// all at once. The fs shim is slow (every chunk crosses into Node), so it needs
// far less data to still be mid-stream when Cancel is clicked.
test.describe('cancel', () => {
  test.describe.configure({ mode: 'default' });
  for (const sink of ['sw', 'fs']) {
    test(`Cancel works with a mouse click and leaves nothing behind (${sink}, audit H5)`, async ({
      page,
      work,
      problems,
      browserName,
    }) => {
      const fsCap = sink === 'fs' ? await installFsShim(page) : null;
      await openApp(page, sink);
      const src = await makeFile(work, 'large.bin', (sink === 'fs' ? 48 : 256) * 1048576, 7);
      await pick(page, src.path);
      const download = sink === 'sw' ? page.waitForEvent('download') : null;
      await encrypt(page, STRONG);
      await expect(page.locator('#work')).toBeVisible();
      await expect
        .poll(async () => Number(await page.locator('#progress').getAttribute('aria-valuenow')), { timeout: 30_000 })
        .toBeGreaterThan(0);
      await page.locator('#cancelBtn').click(); // real pointer click: fails if anything covers the button
      await expect(page.locator('#messageText')).toHaveText('Cancelled. Nothing was saved.');
      if (sink === 'fs') expect(fsCap.aborted).toBe(true);
      // The aborted stream fails the download. Playwright can observe that in
      // Chromium and WebKit; its Firefox never settles failure() for this case.
      else if (browserName !== 'firefox') expect(await (await download).failure()).not.toBeNull();
      await expectNoOpfsLeftovers(page);
      // Firefox logs the deliberately failed download response; that is the point.
      const expected = /A ServiceWorker intercepted the request and encountered an unexpected error/;
      expect(problems.filter((p) => !expected.test(p))).toEqual([]);
      problems.length = 0;
    });
  }
});

test('a download the browser sends past the Service Worker falls back instead of hanging', async ({
  page,
  work,
  problems,
  browserName,
}) => {
  test.skip(browserName !== 'chromium', 'uses the DevTools protocol to bypass the worker');
  await page.addInitScript(() => {
    delete window.showSaveFilePicker;
  });
  await openApp(page);
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null, null, { timeout: 20_000 });
  // What Firefox does after a forced reload or with DevTools' cache disabled.
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Network.enable');
  await cdp.send('Network.setBypassServiceWorker', { bypass: true });

  const src = await makeFile(work, 'notes.txt', 50_000);
  await pick(page, src.path);
  const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'n.vault');
  expect(enc.name).toBe('notes.txt.vault');
  await expect(page.locator('#doneTitle')).toHaveText('Encrypted');

  const file = path.join(work, 'notes.txt.vault');
  await writeFile(file, enc.bytes);
  await page.click('#againBtn');
  await pick(page, file);
  const dec = await capture(page, 'blob', null, () => decrypt(page, STRONG), work, 'n.txt');
  expect(dec.bytes.equals(src.data)).toBe(true);
  // The server answers the skipped request with a 404, once.
  expect(problems).toEqual([expect.stringMatching(/404/)]);
  problems.length = 0;
});

test('dismissing the save dialog cancels cleanly', async ({ page, work, problems }) => {
  await page.addInitScript(() => {
    window.showSaveFilePicker = async () => {
      throw new DOMException('The user aborted a request.', 'AbortError');
    };
  });
  await openApp(page, 'fs');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await encrypt(page, STRONG);
  await expect(page.locator('#messageText')).toHaveText('Cancelled. Nothing was saved.');
  await expect(page.locator('#encPwd')).toHaveValue(STRONG);
  expect(problems).toEqual([]);
});

test('an expired click asks for one more before showing the save dialog', async ({ page, work, problems }) => {
  await page.addInitScript(() => {
    let calls = 0;
    const real = async (opts) => ({
      name: opts.suggestedName,
      createWritable: async () => ({
        write: async () => {},
        close: async () => {},
        abort: async () => {},
      }),
    });
    window.showSaveFilePicker = async (opts) => {
      if (calls++ === 0) throw new DOMException('Must be handling a user gesture.', 'SecurityError');
      return real(opts);
    };
  });
  await openApp(page, 'blob');
  const { file } = await encrypted(page, work);
  await page.goto('/?sink=fs');
  await page.locator('html[data-ready]').waitFor({ state: 'attached' });
  await pick(page, file);
  await decrypt(page, STRONG);
  await expect(page.locator('#messageText')).toContainText('Password correct');
  await page.click('#messageAction');
  await expect(page.locator('#doneTitle')).toHaveText('Decrypted');
  expect(problems).toEqual([]);
});
