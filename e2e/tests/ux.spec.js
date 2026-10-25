// Interaction details: password confirmation, weak-password gate, generated
// passphrases, drag and drop anywhere, mode switching, theme, mobile layout.

import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { capture, decrypt, encrypt, expect, makeFile, openApp, pick, STRONG, test } from './helpers.js';

test('Encrypt needs a matching confirmation (audit H6)', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await expect(page.locator('#encPwd')).toBeFocused();
  await encrypt(page, STRONG, { confirm: `${STRONG}x` });
  await expect(page.locator('#confirmHelp')).toHaveText('The passwords don’t match.');
  await expect(page.locator('#encPwd2')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#encPwd2')).toBeFocused();
  await expect(page.locator('#work')).toBeHidden();
  await page.fill('#encPwd2', STRONG);
  await expect(page.locator('#confirmHelp')).toHaveText('The passwords match.');
  expect(problems).toEqual([]);
});

test('a weak password needs a second, explicit click (audit M4)', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await page.fill('#encPwd', 'Password1!');
  await expect(page.locator('#strengthText')).toContainText('Very weak');
  await page.fill('#encPwd2', 'Password1!');
  await page.click('#encGo');
  await expect(page.locator('#messageText')).toContainText('This password is very weak');
  await expect(page.locator('#encGo')).toHaveText('Encrypt anyway');
  // Changing the password resets the gate.
  await page.fill('#encPwd', 'Password1!!');
  await expect(page.locator('#encGo')).toHaveText('Encrypt');
  await page.fill('#encPwd', 'Password1!');
  await page.click('#encGo');
  const download = page.waitForEvent('download');
  await page.click('#encGo');
  await download;
  await expect(page.locator('#doneTitle')).toHaveText('Encrypted');
  expect(problems).toEqual([]);
});

test('a generated passphrase is shown, needs no confirmation, can be copied and decrypts (audit M5)', async ({
  page,
  context,
  work,
  problems,
  browserName,
}) => {
  if (browserName === 'chromium') await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 1000);
  await pick(page, src.path);
  await page.click('#genBtn');
  const phrase = await page.inputValue('#encPwd');
  expect(phrase).toMatch(/^[a-z]+(-[a-z]+){5}$/);
  await expect(page.locator('#encPwd')).toHaveAttribute('type', 'text');
  await expect(page.locator('#generated')).toBeVisible();
  await expect(page.locator('#confirmField')).toBeHidden();
  await expect(page.locator('#strengthText')).toContainText('Very strong');
  if (browserName === 'chromium') {
    await page.click('#copyBtn');
    await expect(page.locator('#copyBtn')).toHaveText('Copied');
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(phrase);
  }
  const enc = await capture(page, 'blob', null, () => page.click('#encGo'), work, 'g.vault');
  const file = path.join(work, 'g.vault');
  await writeFile(file, enc.bytes);
  await page.click('#againBtn');
  await pick(page, file);
  await capture(page, 'blob', null, () => decrypt(page, phrase), work, 'g.out');
  await expect(page.locator('#doneTitle')).toHaveText('Decrypted');
  expect(problems).toEqual([]);
});

test('files dropped anywhere on the page are taken, never opened by the browser (audit M8)', async ({
  page,
  problems,
}) => {
  await openApp(page, 'blob');
  const prevented = await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(['hello'], 'dropped.txt', { type: 'text/plain' }));
    const target = document.querySelector('footer');
    const fire = (type) => {
      const e = new DragEvent(type, { bubbles: true, cancelable: true, dataTransfer: dt });
      target.dispatchEvent(e);
      return e.defaultPrevented;
    };
    return { enter: fire('dragenter'), over: fire('dragover'), drop: fire('drop') };
  });
  expect(prevented).toEqual({ enter: true, over: true, drop: true });
  await expect(page.locator('#selName')).toHaveText('dropped.txt');
  await expect(page.locator('#dropOverlay')).toBeHidden();
  expect(problems).toEqual([]);
});

test('the drag overlay appears while dragging files over the page', async ({ page, problems }) => {
  await openApp(page, 'blob');
  await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(['x'], 'x.txt'));
    document.body.dispatchEvent(new DragEvent('dragenter', { bubbles: true, cancelable: true, dataTransfer: dt }));
  });
  await expect(page.locator('#dropOverlay')).toBeVisible();
  expect(problems).toEqual([]);
});

test('switching modes and clearing the selection', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await page.click('label.mode-dec');
  await expect(page.locator('#decForm')).toBeVisible();
  await page.click('label.mode-enc');
  await expect(page.locator('#encForm')).toBeVisible();
  await page.click('#clearBtn');
  await expect(page.locator('#pick')).toBeVisible();
  await expect(page.locator('#pickFilesBtn')).toBeFocused();
  expect(problems).toEqual([]);
});

test('passwords are cleared after a successful run', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'c.vault');
  for (const id of ['#encPwd', '#encPwd2', '#decPwd']) await expect(page.locator(id)).toHaveValue('');
  expect(problems).toEqual([]);
});

test('theme follows the system and the toggle persists (audit L8)', async ({ page, problems }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await openApp(page, 'blob');
  const bg = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(await bg()).toBe('rgb(245, 246, 248)');
  await page.emulateMedia({ colorScheme: 'dark' });
  expect(await bg()).toBe('rgb(13, 17, 23)');
  await page.click('[data-theme-set="light"]');
  expect(await bg()).toBe('rgb(245, 246, 248)');
  await page.reload();
  expect(await bg()).toBe('rgb(245, 246, 248)');
  await expect(page.locator('[data-theme-set="light"]')).toHaveAttribute('aria-pressed', 'true');
  expect(problems).toEqual([]);
});

test.describe('phone layout', () => {
  test.use({ viewport: { width: 360, height: 740 }, hasTouch: true, isMobile: false });

  test('no horizontal scroll in any view (audit L7)', async ({ page, work, problems }) => {
    await openApp(page, 'blob');
    const overflow = () => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(await overflow()).toBeLessThanOrEqual(0);
    const src = await makeFile(work, 'a-really-long-file-name-that-keeps-going-and-going-forever.pdf', 10);
    await pick(page, src.path);
    await page.fill('#encPwd', 'Password1!');
    await page.fill('#encPwd2', 'Password1!');
    await page.click('#encGo');
    await expect(page.locator('#message')).toBeVisible();
    expect(await overflow()).toBeLessThanOrEqual(0);
    expect(problems).toEqual([]);
  });
});
