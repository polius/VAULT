// Interaction details: password confirmation, weak-password gate, generated
// passphrases, drag and drop anywhere, mode switching, theme, mobile layout.

import { readFile, writeFile } from 'node:fs/promises';
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

test('Tab goes from Password straight to Confirm', async ({ page, work, problems, browserName }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await expect(page.locator('#encPwd')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('#encPwd2')).toBeFocused();
  // The buttons beside Password stay reachable, backwards.
  if (browserName !== 'webkit') {
    await page.keyboard.press('Shift+Tab');
    await expect(page.locator('#encShow')).toBeFocused();
  }
  expect(problems).toEqual([]);
});

test('a weak password needs a second, explicit click (audit M4)', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await page.fill('#encPwd', 'Password1!');
  await expect(page.locator('#strengthText')).toHaveText('Very weak · guessed instantly');
  await page.fill('#encPwd2', 'Password1!');
  await page.click('#encGo');
  await expect(page.locator('#messageText')).toHaveText(
    'This password is very weak. A well-equipped attacker could guess it instantly. Use a longer one or generate a passphrase, or encrypt anyway.',
  );
  await expect(page.locator('#encGo')).toHaveText('Encrypt anyway');
  // Changing the password resets the gate.
  await page.fill('#encPwd', 'Password1!!');
  await expect(page.locator('#encGo')).toHaveText('Encrypt');
  await page.fill('#encPwd', 'Password1!');
  await page.click('#encGo');
  const download = page.waitForEvent('download');
  await page.click('#encGo');
  await download;
  await expect(page.locator('#stateTitle')).toHaveText('Encrypted');
  expect(problems).toEqual([]);
});

test('the weak-password warning sits under the meter and makes the safe choice the big button (audit F5)', async ({
  page,
  work,
  problems,
}) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await page.fill('#encPwd', 'Password1!');
  await page.fill('#encPwd2', 'Password1!');
  await page.click('#encGo');
  await expect(page.locator('#message')).toBeVisible();
  // Directly under the meter, inside the password field.
  expect(await page.evaluate(() => document.querySelector('#meter').nextElementSibling.id)).toBe('message');
  await expect(page.locator('#messageAction')).toHaveText('Use a generated passphrase');
  await expect(page.locator('#messageAction')).toHaveClass(/btn-ink/);
  await expect(page.locator('#encGo')).toHaveClass(/btn-ghost/);
  await page.click('#messageAction');
  await expect(page.locator('#generated')).toBeVisible();
  await expect(page.locator('#message')).toBeHidden();
  await expect(page.locator('#encGo')).toHaveClass(/btn-lock/);
  expect(problems).toEqual([]);
});

test('a pasted file is selected, pasted text stays text, and Escape leaves an untouched job (audit F12)', async ({
  page,
  problems,
}) => {
  await openApp(page, 'blob');
  const paste = (withFile) =>
    page.evaluate((withFile) => {
      const dt = new DataTransfer();
      if (withFile) dt.items.add(new File(['hello'], 'pasted.txt', { type: 'text/plain' }));
      else dt.setData('text/plain', 'just text');
      const e = new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true });
      document.body.dispatchEvent(e);
      return e.defaultPrevented;
    }, withFile);
  expect(await paste(false)).toBe(false);
  await expect(page.locator('#pick')).toBeVisible();
  expect(await paste(true)).toBe(true);
  await expect(page.locator('#selName')).toHaveText('pasted.txt');
  await page.keyboard.press('Escape');
  await expect(page.locator('#pick')).toBeVisible();
  // With a password typed, Escape does nothing.
  await paste(true);
  await page.fill('#encPwd', 'x');
  await page.keyboard.press('Escape');
  await expect(page.locator('#job')).toBeVisible();
  expect(problems).toEqual([]);
});

test('password managers see each file under its own name (audit F13)', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'report-q3.pdf', 10);
  await pick(page, src.path);
  const user = (form) => page.locator(`${form} input[name="username"]`).inputValue();
  expect(await user('#encForm')).toBe('report-q3.pdf.vault');
  await page.click('.options summary');
  await page.check('#hideName');
  expect(await user('#encForm')).toMatch(/^vault-\d{4}-\d{2}-\d{2}-[0-9a-f]{6}\.vault$/);
  await expect(page.locator('#saveAs')).toHaveText(`saves ${await user('#encForm')}`);
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
  // Generating loads the wordlist first.
  await expect(page.locator('#encPwd')).toHaveValue(/^[a-z]+(-[a-z]+){5}$/);
  const phrase = await page.inputValue('#encPwd');
  // Shown once, whole, in the block; the field stays masked.
  await expect(page.locator('#encPwd')).toHaveAttribute('type', 'password');
  await expect(page.locator('#generated')).toBeVisible();
  await expect(page.locator('#confirmField')).toBeHidden();
  await expect(page.locator('#strengthText')).toHaveText('Very strong · beyond any realistic guessing');
  await expect(page.locator('#genPhrase')).toHaveText(phrase);
  // Never copied: the first click asks whether it was saved and starts nothing (audit F1).
  await page.click('#encGo');
  await expect(page.locator('#messageText')).toContainText('Have you saved this passphrase?');
  await expect(page.locator('#encGo')).toHaveText('I saved it. Encrypt');
  await expect(page.locator('#work')).toBeHidden();
  if (browserName === 'chromium') {
    await page.bringToFront(); // clipboard writes need a focused document
    await page.click('#messageAction');
    await expect(page.locator('#copyBtn')).toHaveText('Copied');
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(phrase);
  }
  const enc = await capture(page, 'blob', null, () => page.click('#encGo'), work, 'g.vault');
  const file = path.join(work, 'g.vault');
  await writeFile(file, enc.bytes);
  await page.click('#againBtn');
  await pick(page, file);
  await capture(page, 'blob', null, () => decrypt(page, phrase), work, 'g.out');
  await expect(page.locator('#stateTitle')).toHaveText('Decrypted');
  expect(problems).toEqual([]);
});

test('a copied passphrase encrypts on the first click; generating again asks again (audit F1)', async ({
  page,
  context,
  work,
  problems,
  browserName,
}) => {
  test.skip(browserName !== 'chromium', 'clipboard permissions are Chromium-only in Playwright');
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await page.click('#genLink');
  await expect(page.locator('#generated')).toBeVisible();
  await page.bringToFront(); // clipboard writes need a focused document
  await page.click('#copyBtn');
  await expect(page.locator('#copyBtn')).toHaveText('Copied');
  await page.click('#genBtn');
  await page.click('#encGo');
  await expect(page.locator('#messageText')).toContainText('Have you saved this passphrase?');
  // Editing the field drops the generated state and the question with it.
  await page.fill('#encPwd', STRONG);
  await expect(page.locator('#generated')).toBeHidden();
  await expect(page.locator('#encGo')).toHaveText('Encrypt');
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

test('the mode follows the file; a .vault file can still be encrypted again (audit F4)', async ({
  page,
  work,
  problems,
}) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await expect(page.locator('#stateTitle')).toHaveText('Encrypt');
  await expect(page.locator('#encForm')).toBeVisible();
  await expect(page.locator('#switchMode')).toBeHidden();
  const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'a.vault');
  const file = path.join(work, 'a.txt.vault');
  await writeFile(file, enc.bytes);
  await page.click('#againBtn');
  await pick(page, file);
  await expect(page.locator('#stateTitle')).toHaveText('Decrypt');
  await expect(page.locator('#bar')).toHaveAttribute('data-state', 'sealed');
  await page.click('#switchMode');
  await expect(page.locator('#encForm')).toBeVisible();
  await expect(page.locator('#stateTitle')).toHaveText('Encrypt');
  await expect(page.locator('#saveAs')).toHaveText('saves a.txt.vault.vault');
  await page.click('#switchMode');
  await expect(page.locator('#decForm')).toBeVisible();
  await page.click('#clearBtn');
  await expect(page.locator('#pick')).toBeVisible();
  await expect(page.locator('#pickFilesBtn')).toBeFocused();
  expect(problems).toEqual([]);
});

test('several .vault files decrypt one after another with one password (audit F7)', async ({
  page,
  work,
  problems,
}) => {
  await openApp(page, 'blob');
  const files = [];
  for (const name of ['one.txt', 'two.txt']) {
    const src = await makeFile(work, name, 3000);
    await pick(page, src.path);
    const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, `${name}.vault`);
    const file = path.join(work, `${name}.vault`);
    await writeFile(file, enc.bytes);
    files.push({ file, src });
    await page.click('#againBtn');
  }
  await pick(
    page,
    files.map((f) => f.file),
  );
  await expect(page.locator('#stateTitle')).toHaveText('Decrypt 2 files');
  await expect(page.locator('#decGo')).toHaveText('Decrypt 2 files');
  const downloads = [];
  page.on('download', (d) => downloads.push(d));
  await decrypt(page, STRONG);
  await expect(page.locator('#stateTitle')).toHaveText('Decrypted');
  await expect(page.locator('#selName')).toHaveText('2 files');
  expect(downloads.map((d) => d.suggestedFilename()).sort()).toEqual(['one.txt', 'two.txt']);
  for (const d of downloads) {
    const out = path.join(work, `out-${d.suggestedFilename()}`);
    await d.saveAs(out);
    const src = files.find((f) => f.src.path.endsWith(d.suggestedFilename())).src;
    expect((await readFile(out)).equals(src.data)).toBe(true);
  }
  expect(problems).toEqual([]);
});

test('a second password is asked for when one .vault file of several needs it (audit F7)', async ({
  page,
  work,
  problems,
}) => {
  await openApp(page, 'blob');
  const made = [];
  for (const [name, pw] of [
    ['one.txt', STRONG],
    ['two.txt', `${STRONG}-other`],
  ]) {
    const src = await makeFile(work, name, 100);
    await pick(page, src.path);
    const enc = await capture(page, 'blob', null, () => encrypt(page, pw), work, `${name}.vault`);
    const file = path.join(work, `${name}.vault`);
    await writeFile(file, enc.bytes);
    made.push(file);
    await page.click('#againBtn');
  }
  await pick(page, made);
  await decrypt(page, STRONG);
  await expect(page.locator('#messageText')).toHaveText(
    '1 of 2 files decrypted and saved. “two.txt.vault” needs a different password.',
  );
  await expect(page.locator('#selName')).toHaveText('two.txt.vault');
  await capture(page, 'blob', null, () => decrypt(page, `${STRONG}-other`), work, 'two.out');
  await expect(page.locator('#stateTitle')).toHaveText('Decrypted');
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

test('the done screen says the original is unchanged, and offers the download again (audit F9)', async ({
  page,
  work,
  problems,
}) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 1000);
  await pick(page, src.path);
  const first = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'first.vault');
  await expect(page.locator('#doneDetail')).toContainText('Your original file is unchanged.');
  await expect(page.locator('#doneMeta')).toContainText('Sent to your browser’s downloads');
  const again = await capture(page, 'blob', null, () => page.click('#downloadAgain'), work, 'again.vault');
  expect(again.name).toBe('a.txt.vault');
  expect(again.bytes.equals(first.bytes)).toBe(true);
  expect(problems).toEqual([]);
});

test('Caps Lock is pointed out while typing a password (audit F10)', async ({ page, work, problems, browserName }) => {
  test.skip(browserName !== 'chromium', 'synthetic Caps Lock state is Chromium-only');
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  const key = (caps) =>
    page.locator('#encPwd').evaluate((el, caps) => {
      el.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', modifierCapsLock: caps, bubbles: true }));
    }, caps);
  await key(true);
  await expect(page.locator('#encCaps')).toBeVisible();
  await key(false);
  await expect(page.locator('#encCaps')).toBeHidden();
  expect(problems).toEqual([]);
});

test('theme follows the system and the toggle persists (audit L8)', async ({ page, problems }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await openApp(page, 'blob');
  const bg = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const LIGHT = 'rgb(244, 244, 240)';
  const DARK = 'rgb(16, 18, 20)';
  expect(await bg()).toBe(LIGHT);
  await page.emulateMedia({ colorScheme: 'dark' });
  expect(await bg()).toBe(DARK);
  // One button cycles Auto -> Light -> Dark and names the current one.
  await expect(page.locator('#themeBtn')).toHaveText('Theme: Auto');
  await page.click('#themeBtn');
  await expect(page.locator('#themeBtn')).toHaveText('Theme: Light');
  expect(await bg()).toBe(LIGHT);
  await page.reload();
  expect(await bg()).toBe(LIGHT);
  await expect(page.locator('#themeBtn')).toHaveText('Theme: Light');
  await page.click('#themeBtn');
  expect(await bg()).toBe(DARK);
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

  test('a generated passphrase is fully visible (audit F3)', async ({ page, work, problems }) => {
    await openApp(page, 'blob');
    const src = await makeFile(work, 'a.txt', 10);
    await pick(page, src.path);
    await page.click('#genBtn');
    const phrase = page.locator('#genPhrase');
    await expect(phrase).toHaveText(/^[a-z]+(-[a-z]+){5}$/);
    expect(await phrase.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
    expect(await phrase.evaluate((el) => el.getBoundingClientRect().right <= window.innerWidth)).toBe(true);
    expect(problems).toEqual([]);
  });
});
