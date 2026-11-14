// The file bar (audit D1) and the layout problems it settles: the landing
// sentence leaves with the first file (F2), the bar keeps one height through
// every state and typing moves nothing (V1), the tab title carries progress
// (F8), the page fits 320 px (V3) and a phone shows the main button (F2, E3).
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { capture, decrypt, encrypt, expect, makeFile, openApp, pick, STRONG, test } from './helpers.js';

const barHeight = (page) => page.locator('#bar').evaluate((el) => Math.round(el.getBoundingClientRect().height));
const appHeight = (page) => page.locator('#app').evaluate((el) => el.getBoundingClientRect().height);

test('the bar keeps one height through every state, and states it in words', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const states = [];
  const record = async () =>
    states.push({
      state: await page.locator('#bar').getAttribute('data-state'),
      title: (await page.locator('#stateTitle').isVisible()) ? await page.locator('#stateTitle').textContent() : '',
      height: await barHeight(page),
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
  expect(new Set(states.map((s) => s.height)).size).toBe(1);
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

test('a long name loses its middle, keeps its extension, and shortens the same in both layers', async ({
  page,
  work,
  problems,
}) => {
  await page.setViewportSize({ width: 360, height: 740 });
  await openApp(page, 'blob');
  const name = `${'quarterly-financial-statement-'.repeat(4)}final.pdf`;
  const src = await makeFile(work, name, 10);
  await pick(page, src.path);
  await expect(page.locator('#selName')).toHaveText(name);
  const layers = await page.evaluate(() =>
    ['#selName', '#fillName'].map((id) => {
      const head = document.querySelector(`${id} .head`);
      const tail = document.querySelector(`${id} .tail`);
      return {
        cut: head.scrollWidth > head.clientWidth,
        headWidth: Math.round(head.getBoundingClientRect().width),
        tail: tail.textContent,
      };
    }),
  );
  expect(layers[0].cut).toBe(true);
  expect(layers[0].tail.endsWith('final.pdf')).toBe(true);
  expect(layers[1]).toEqual(layers[0]);
  expect(problems).toEqual([]);
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
