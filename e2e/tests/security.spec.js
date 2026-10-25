// Security properties of the running app: CSP and Trusted Types enforced, no
// third-party requests, OPFS leftovers from 1.x swept, plain HTTP refused
// clearly, the KDF off the main thread.
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { chromium } from '@playwright/test';
import { expect, makeFile, openApp, opfsEntries, pick, STRONG, test } from './helpers.js';

const require = createRequire(import.meta.url);

test('security headers are sent', async ({ request }) => {
  const res = await request.get('/');
  const h = res.headers();
  expect(h['content-security-policy']).toContain("require-trusted-types-for 'script'");
  expect(h['content-security-policy']).toContain("frame-ancestors 'self'");
  expect(h['x-content-type-options']).toBe('nosniff');
  expect(h['referrer-policy']).toBe('no-referrer');
  expect(h['cache-control']).toBe('no-cache');
  expect(h['cross-origin-opener-policy']).toBe('same-origin');
});

test('Trusted Types block HTML injection', async ({ page, browserName, problems }) => {
  await openApp(page, 'blob');
  const supported = await page.evaluate(() => 'trustedTypes' in window);
  test.skip(!supported, `${browserName} has no Trusted Types`);
  const blocked = await page.evaluate(() => {
    try {
      document.body.innerHTML = '<img src=x onerror=alert(1)>';
      return false;
    } catch (e) {
      return e instanceof TypeError;
    }
  });
  expect(blocked).toBe(true);
  problems.length = 0; // the console logs the (expected) violation
});

test('VAULT 1.x staging leftovers are removed from browser storage on load (audit H2)', async ({ page, problems }) => {
  await openApp(page, 'blob');
  test.skip((await opfsEntries(page)) === null, 'no origin-private file system in this browser');
  await page.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const h = await root.getFileHandle('vault-part-0000-leftover', { create: true });
    const w = await h.createWritable();
    await w.write('decrypted plaintext from 1.x');
    await w.close();
    await root.getFileHandle('unrelated-file', { create: true });
  });
  expect(await opfsEntries(page)).toContain('vault-part-0000-leftover');
  await page.reload();
  await page.locator('html[data-ready]').waitFor({ state: 'attached' });
  await expect.poll(() => opfsEntries(page)).toEqual(['unrelated-file']);
  expect(problems).toEqual([]);
});

// Argon2id must run in kdf-worker.js, never on the main thread (which would
// freeze the page, including the progress animation, for the whole derivation).
test('key derivation runs in a worker', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  const workers = [];
  page.on('worker', (w) => workers.push(w.url()));
  await page.fill('#encPwd', STRONG);
  await page.fill('#encPwd2', STRONG);
  const download = page.waitForEvent('download');
  await page.click('#encGo');
  await download;
  expect(workers.filter((u) => u.endsWith('/js/kdf-worker.js'))).toHaveLength(1);
  expect(problems).toEqual([]);
});

test('plain HTTP on a non-local host shows a clear explanation (audit H4)', async ({ browserName, baseURL }) => {
  test.skip(browserName !== 'chromium', 'host mapping uses a Chromium flag');
  const port = new URL(baseURL).port;
  const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP vault.test 127.0.0.1'] });
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.goto(`http://vault.test:${port}/`);
    await expect(page.locator('#insecure')).toBeVisible();
    await expect(page.locator('#insecureTitle')).toHaveText('VAULT needs a secure connection');
    await expect(page.locator('#app')).toBeHidden();
    expect(errors).toEqual([]);
  } finally {
    await browser.close();
  }
});

test.describe('accessibility (axe, WCAG 2.1 AA)', () => {
  test.use({ bypassCSP: true }); // axe is injected as an inline script
  const axeSource = readFile(require.resolve('axe-core/axe.min.js'), 'utf8');

  async function audit(page) {
    // Mid-animation opacity would read as low contrast.
    await page.evaluate(() =>
      Promise.all(
        document
          .getAnimations()
          .filter((a) => a.effect.getTiming().iterations !== Infinity)
          .map((a) => a.finished),
      ),
    );
    await page.addScriptTag({ content: await axeSource });
    return page.evaluate(async () => {
      const r = await window.axe.run(document, {
        runOnly: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'],
      });
      return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
    });
  }

  for (const scheme of ['light', 'dark']) {
    test(`every view passes in ${scheme} mode (audit M13)`, async ({ page, work, browserName }) => {
      test.skip(browserName !== 'chromium', 'one engine is enough for axe');
      await page.emulateMedia({ colorScheme: scheme });
      await openApp(page, 'blob');
      expect(await audit(page), 'pick').toEqual([]);
      const src = await makeFile(work, 'a.txt', 10);
      await pick(page, src.path);
      await page.fill('#encPwd', 'Password1!');
      await page.fill('#encPwd2', 'Password1');
      await page.click('#encGo');
      expect(await audit(page), 'encrypt form with errors').toEqual([]);
      await page.fill('#encPwd2', 'Password1!');
      await page.click('#encGo');
      expect(await audit(page), 'weak warning').toEqual([]);
      await page.click('#genBtn');
      expect(await audit(page), 'generated').toEqual([]);
      const download = page.waitForEvent('download');
      await page.click('#encGo');
      await download;
      await expect(page.locator('#done')).toBeVisible();
      expect(await audit(page), 'done').toEqual([]);
      await page.click('#againBtn');
      await pick(page, new URL('../../test/vectors/v3-10000.vault', import.meta.url).pathname);
      await page.fill('#decPwd', 'wrong');
      await page.click('#decGo');
      await expect(page.locator('#message')).toBeVisible();
      expect(await audit(page), 'decrypt with error').toEqual([]);
    });
  }

  test('keyboard focus is always visible, including on the file pickers', async ({ page, browserName }) => {
    test.skip(browserName === 'webkit', 'WebKit skips buttons when tabbing by default');
    await openApp(page, 'blob');
    const seen = [];
    for (let i = 0; i < 6; i++) {
      await page.keyboard.press('Tab');
      seen.push(
        await page.evaluate(() => {
          const el = document.activeElement;
          const s = getComputedStyle(el);
          return {
            id: el.id || el.textContent.trim().slice(0, 20),
            outline: s.outlineStyle !== 'none' && s.outlineWidth !== '0px',
          };
        }),
      );
    }
    expect(seen.map((s) => s.id)).toContain('pickFilesBtn');
    for (const s of seen) expect(s.outline, JSON.stringify(s)).toBe(true);
  });
});
