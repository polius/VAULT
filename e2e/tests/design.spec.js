// The layout, and the seal. The landing sentence leaves with the first file
// (audit F2), the file's name keeps its place through every state and typing
// moves nothing (V1), the tab title carries progress (F8), the page fits
// 320 px (V3) and a phone shows the main button (F2, E3). Every .vault file
// has a seal drawn from its salt: blank, drawn, sealed, broken.
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { capture, decrypt, encrypt, expect, makeFile, openApp, pick, STRONG, test } from './helpers.js';

// Where the file's name sits, while there is one.
const nameBox = (page) =>
  page.locator('#selName').evaluate((el) => {
    const r = el.getBoundingClientRect();
    return r.height ? { top: Math.round(r.top), height: Math.round(r.height) } : null;
  });
const sealMode = (page) => page.locator('#seal').getAttribute('data-mode');
// The salt in a .vault file's header, as the seal number shows it.
function sealNumberOf(bytes) {
  const params = JSON.parse(bytes.subarray(9, 9 + bytes.readUInt32LE(5)).toString('utf8'));
  const hex = Buffer.from(params.salt, 'base64').subarray(0, 6).toString('hex').toUpperCase();
  return hex.replace(/(.{4})(?=.)/g, '$1 ');
}
const appHeight = (page) => page.locator('#app').evaluate((el) => el.getBoundingClientRect().height);

test('the file keeps its place through every state, and a word names each state', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const states = [];
  const record = async () =>
    states.push({
      state: await page.locator('#bar').getAttribute('data-state'),
      title: (await page.locator('#stateTitle').isVisible()) ? await page.locator('#stateTitle').textContent() : '',
      box: await nameBox(page),
    });
  await record();
  const src = await makeFile(work, 'report-q3.pdf', 20_000);
  await pick(page, src.path);
  await record();
  const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'r.vault');
  await record();
  const file = path.join(work, 'report-q3.pdf.vault');
  await writeFile(file, enc.bytes);
  await page.click('#againBtn');
  await pick(page, file);
  await record();
  await capture(page, 'blob', null, () => decrypt(page, STRONG), work, 'r.out');
  await record();
  expect(states.map((s) => [s.state, s.title])).toEqual([
    ['empty', ''],
    ['open', 'Encrypt'],
    ['sealed', 'Encrypted'],
    ['sealed', 'Decrypt'],
    ['opened', 'Decrypted'],
  ]);
  // No file on landing; after that the name never moves or changes height.
  expect(states[0].box).toBeNull();
  expect(new Set(states.slice(1).map((s) => JSON.stringify(s.box))).size).toBe(1);
  await expect(page.locator('#selName')).toHaveText('report-q3.pdf');
  expect(problems).toEqual([]);
});

test('the landing sentence is only on the landing view (audit F2)', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  await expect(page.locator('.intro')).toBeVisible();
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  await expect(page.locator('.intro')).toBeHidden();
  await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'a.vault');
  await expect(page.locator('.intro')).toBeHidden();
  await page.click('#againBtn');
  await expect(page.locator('.intro')).toBeVisible();
  expect(problems).toEqual([]);
});

test('typing a password moves nothing (audit V1)', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'a.txt', 10);
  await pick(page, src.path);
  const before = await appHeight(page);
  await page.fill('#encPwd', 'o');
  expect(await appHeight(page)).toBe(before);
  await page.fill('#encPwd', STRONG);
  await page.fill('#encPwd2', STRONG);
  await expect(page.locator('#confirmHelp')).toHaveText('The passwords match.');
  expect(await appHeight(page)).toBe(before);
  expect(problems).toEqual([]);
});

test('the tab title shows progress, and is restored afterwards (audit F8)', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const base = await page.title();
  const src = await makeFile(work, 'big.bin', 24 * 1048576, 3);
  await pick(page, src.path);
  await page.evaluate(() => {
    window.__titles = [];
    new MutationObserver(() => window.__titles.push(document.title)).observe(document.querySelector('title'), {
      childList: true,
      characterData: true,
      subtree: true,
    });
  });
  await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'b.vault');
  const titles = await page.evaluate(() => window.__titles);
  expect(
    titles.some((t) => /^\d+% · Encrypting big\.bin$/.test(t)),
    titles.join('\n'),
  ).toBe(true);
  expect(await page.title()).toBe(base);
  expect(problems).toEqual([]);
});

test('a long name loses its middle and keeps its extension', async ({ page, work, problems }) => {
  await page.setViewportSize({ width: 360, height: 740 });
  await openApp(page, 'blob');
  const name = `${'quarterly-financial-statement-'.repeat(4)}final.pdf`;
  const src = await makeFile(work, name, 10);
  await pick(page, src.path);
  await expect(page.locator('#selName')).toHaveText(name);
  const shown = await page.evaluate(() => {
    const head = document.querySelector('#selName .head');
    const tail = document.querySelector('#selName .tail');
    return {
      cut: head.scrollWidth > head.clientWidth,
      tail: tail.textContent,
      fits: document.querySelector('#selName').getBoundingClientRect().right <= window.innerWidth,
    };
  });
  expect(shown.cut).toBe(true);
  expect(shown.tail.endsWith('final.pdf')).toBe(true);
  expect(shown.fits).toBe(true);
  expect(problems).toEqual([]);
});

test('the seal is blank, then drawn from the file\u2019s salt, and the same file shows it again', async ({
  page,
  work,
  problems,
}) => {
  await openApp(page, 'blob');
  expect(await sealMode(page)).toBe('blank');
  await expect(page.locator('#sealNo')).toHaveText('Drawn when the file is encrypted');
  const src = await makeFile(work, 'a.txt', 3000);
  await pick(page, src.path);
  expect(await sealMode(page)).toBe('blank');
  const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'a.vault');
  const number = sealNumberOf(enc.bytes);
  await expect(page.locator('#seal')).toHaveAttribute('data-mode', 'sealed');
  await expect(page.locator('#sealNo')).toHaveText(number);
  // Both drawings (large and small) hold the three rings.
  await expect(page.locator('#seal svg')).toHaveCount(2);
  await expect(page.locator('#seal .seal-full .seal-ink .seal-ring')).toHaveCount(3);
  const drawn = () =>
    page.locator('#seal .seal-full defs path').evaluateAll((paths) => paths.map((p) => p.getAttribute('d')).join(''));
  const first = await drawn();

  // Back on landing the seal is blank again.
  await page.click('#againBtn');
  expect(await sealMode(page)).toBe('blank');
  await expect(page.locator('#sealNo')).toHaveText('Drawn when the file is encrypted');
  expect(await drawn()).not.toBe(first);

  // The encrypted file brings its seal with it.
  const file = path.join(work, 'a.txt.vault');
  await writeFile(file, enc.bytes);
  await pick(page, file);
  await expect(page.locator('#seal')).toHaveAttribute('data-mode', 'sealed');
  await expect(page.locator('#sealNo')).toHaveText(number);
  expect(await drawn()).toBe(first);

  // A wrong password leaves it shut; the right one breaks it.
  await decrypt(page, 'not-the-password');
  await expect(page.locator('#message')).toBeVisible();
  await expect(page.locator('#seal')).toHaveClass(/seal-deny/);
  await expect(page.locator('#seal')).toHaveAttribute('data-mode', 'sealed');
  await capture(page, 'blob', null, () => decrypt(page, STRONG), work, 'a.out');
  await expect(page.locator('#seal')).toHaveAttribute('data-mode', 'broken');
  await expect(page.locator('#seal')).toHaveClass(/seal-split/);
  await expect(page.locator('#sealNo')).toHaveText(number);
  expect(problems).toEqual([]);
});

test('two files encrypted with the same password get different seals', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const numbers = [];
  for (const name of ['one.txt', 'two.txt']) {
    const src = await makeFile(work, name, 10);
    await pick(page, src.path);
    const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, `${name}.vault`);
    await expect(page.locator('#sealNo')).toHaveText(sealNumberOf(enc.bytes));
    numbers.push(await page.locator('#sealNo').textContent());
    await page.click('#againBtn');
  }
  expect(numbers[0]).not.toBe(numbers[1]);
  expect(problems).toEqual([]);
});

test.describe('reduced motion', () => {
  test.use({ reducedMotion: 'reduce' });

  test('the seal still ends sealed, then broken, with nothing turning', async ({ page, work, problems }) => {
    await openApp(page, 'blob');
    const src = await makeFile(work, 'calm.txt', 2 * 1048576, 5);
    await pick(page, src.path);
    const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'calm.vault');
    await expect(page.locator('#seal')).toHaveAttribute('data-mode', 'sealed');
    await expect(page.locator('#seal')).not.toHaveClass(/seal-stamp/);
    const turned = await page.locator('#seal').evaluate((el) => el.style.getPropertyValue('--seal-a1'));
    expect(turned).toBe('0.00deg');
    const file = path.join(work, 'calm.txt.vault');
    await writeFile(file, enc.bytes);
    await page.click('#againBtn');
    await pick(page, file);
    await capture(page, 'blob', null, () => decrypt(page, STRONG), work, 'calm.out');
    await expect(page.locator('#seal')).toHaveAttribute('data-mode', 'broken');
    expect(problems).toEqual([]);
  });
});

test('the first Tab stop skips the header to the page (audit V4)', async ({ page, problems, browserName }) => {
  test.skip(browserName === 'webkit', 'WebKit skips links when tabbing by default');
  await openApp(page, 'blob');
  await page.keyboard.press('Tab');
  await expect(page.locator('.skip-link')).toBeFocused();
  await expect(page.locator('.skip-link')).toBeInViewport();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('#pickFilesBtn')).toBeFocused();
  expect(problems).toEqual([]);
});

test.describe('phone', () => {
  test.use({ viewport: { width: 360, height: 640 }, hasTouch: true, isMobile: false });

  test('the Encrypt button is on screen with both passwords typed (audit F2, E3)', async ({ page, work, problems }) => {
    await openApp(page, 'blob');
    const src = await makeFile(work, 'report-q3.pdf', 10);
    await pick(page, src.path);
    await page.fill('#encPwd', STRONG);
    await page.fill('#encPwd2', STRONG);
    await page.evaluate(() => window.scrollTo(0, 0));
    const bottom = await page.locator('#encGo').evaluate((el) => el.getBoundingClientRect().bottom);
    expect(bottom).toBeLessThanOrEqual(640);
    expect(problems).toEqual([]);
  });
});

test.describe('320 px', () => {
  test.use({ viewport: { width: 320, height: 640 }, hasTouch: true, isMobile: false });

  test('no horizontal scroll at the WCAG reflow width (audit V3, E3)', async ({ page, work, problems }) => {
    await openApp(page, 'blob');
    const overflow = () => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(await overflow()).toBeLessThanOrEqual(0);
    const src = await makeFile(work, 'a-really-long-file-name-that-keeps-going-and-going-forever.pdf', 10);
    await pick(page, src.path);
    expect(await overflow()).toBeLessThanOrEqual(0);
    await page.click('#genBtn');
    await expect(page.locator('#generated')).toBeVisible();
    expect(await overflow()).toBeLessThanOrEqual(0);
    expect(await page.locator('#genPhrase').evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
    expect(problems).toEqual([]);
  });
});
