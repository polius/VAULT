// Encrypt then decrypt through every sink, single files and folders, and check
// the bytes are identical. Also: nothing is left in browser storage (audit H2).
import { execFileSync } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
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
  sha256,
  test,
} from './helpers.js';

// Download names as the browser reports them: macOS may hand back NFD, and
// WebKit (Playwright 1.64+) turns spaces into underscores. The test names have no underscores.
const savedName = ({ name }) => name.normalize('NFC').replaceAll('_', ' ');

for (const sink of ['sw', 'fs', 'blob']) {
  test.describe(`${sink} sink`, () => {
    test('single file round trip', async ({ page, work, problems }) => {
      const fsCap = sink === 'fs' ? await installFsShim(page) : null;
      await openApp(page, sink);
      const src = await makeFile(work, 'Quarterly report ü.pdf', 5 * 1048576 + 333);
      await pick(page, src.path);

      const enc = await capture(page, sink, fsCap, () => encrypt(page, STRONG), work, 'a.vault');
      expect(savedName(enc)).toBe('Quarterly report ü.pdf.vault');
      await expect(page.locator('#doneTitle')).toHaveText('Encrypted');
      await expect(page.locator('#doneName')).toHaveText('Quarterly report ü.pdf.vault');
      await expect(page.locator('#doneMeta')).toContainText(
        sink === 'fs' ? 'Saved where you chose' : 'Saved to your downloads',
      );
      // The cleartext header must not leak the name (audit M1).
      expect(enc.bytes.subarray(0, 400).includes('Quarterly')).toBe(false);

      const vaultPath = path.join(work, 'roundtrip.vault');
      await writeFile(vaultPath, enc.bytes);
      await page.click('#againBtn');
      await pick(page, vaultPath);
      await expect(page.locator('#vaultInfo')).toContainText('format 3');
      const dec = await capture(page, sink, fsCap, () => decrypt(page, STRONG), work, 'b.out');
      expect(savedName(dec)).toBe('Quarterly report ü.pdf');
      expect(sha256(dec.bytes)).toBe(src.hash);
      await expect(page.locator('#doneTitle')).toHaveText('Decrypted');
      await expect(page.locator('#decPwd')).toHaveValue('');
      await expectNoOpfsLeftovers(page);
      expect(problems).toEqual([]);
    });
  });
}

test('empty file round trip, and a wrong password is rejected for it (audit H1)', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'empty.txt', 0);
  await pick(page, src.path);
  const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'e.vault');
  const vaultPath = path.join(work, 'e.vault');
  await writeFile(vaultPath, enc.bytes);
  await page.click('#againBtn');
  await pick(page, vaultPath);
  await decrypt(page, 'not the password');
  await expect(page.locator('#messageText')).toHaveText('Wrong password. Check it and try again.');
  const dec = await capture(page, 'blob', null, () => decrypt(page, STRONG), work, 'e.out');
  expect(dec.bytes.length).toBe(0);
  expect(problems).toEqual([]);
});

test('a folder becomes one ZIP and comes back intact', async ({ page, work, problems, browserName }) => {
  test.skip(browserName !== 'chromium', 'Playwright uploads directories only in Chromium');
  const root = path.join(work, 'Holiday photos');
  await mkdir(path.join(root, 'day 1'), { recursive: true });
  await mkdir(path.join(root, 'empty'), { recursive: true });
  const a = await makeFile(root, 'notes.txt', 1200);
  const b = await makeFile(path.join(root, 'day 1'), 'beach ü.jpg', 2 * 1048576 + 5);
  await openApp(page, 'sw');
  await page.setInputFiles('#pickFolder', root);
  await expect(page.locator('#selName')).toHaveText('Holiday photos');
  await expect(page.locator('#selMeta')).toContainText('2 files');
  await expect(page.locator('#modeDec')).toBeDisabled();
  await expect(page.locator('#encGo')).toHaveText('Encrypt 2 files');

  const enc = await capture(page, 'sw', null, () => encrypt(page, STRONG), work, 'f.vault');
  expect(enc.name).toBe('Holiday photos.zip.vault');
  const vaultPath = path.join(work, 'f.vault');
  await writeFile(vaultPath, enc.bytes);
  await page.click('#againBtn');
  await pick(page, vaultPath);
  const dec = await capture(page, 'sw', null, () => decrypt(page, STRONG), work, 'f.zip');
  expect(savedName(dec)).toBe('Holiday photos.zip');
  await expect(page.locator('#doneDetail')).toContainText('ZIP archive with 2 files');

  const zipPath = path.join(work, 'f.zip');
  await writeFile(zipPath, dec.bytes);
  const listing = JSON.parse(
    execFileSync('python3', [
      '-I',
      '-c',
      'import zipfile,json,hashlib,sys\nz=zipfile.ZipFile(sys.argv[1])\nassert z.testzip() is None\nprint(json.dumps({i.filename: hashlib.sha256(z.read(i)).hexdigest() for i in z.infolist()}))',
      zipPath,
    ]).toString(),
  );
  // A folder picker never reports empty folders (only drag and drop does, see
  // test/files.test.mjs), so `empty/` is not expected here.
  expect(listing).toEqual({
    'Holiday photos/notes.txt': a.hash,
    'Holiday photos/day 1/beach ü.jpg': b.hash,
  });
  expect(problems).toEqual([]);
});

test('several loose files become one ZIP', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const a = await makeFile(work, 'a.txt', 10);
  const b = await makeFile(work, 'b.bin', 20_000);
  await pick(page, [a.path, b.path]);
  await expect(page.locator('#selMeta')).toContainText('2 files');
  await page.click('#fileList summary');
  await expect(page.locator('#fileListItems li')).toHaveCount(2);
  const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'm.vault');
  expect(enc.name).toMatch(/^files-\d{4}-\d{2}-\d{2}\.zip\.vault$/);
  expect(problems).toEqual([]);
});

test('the neutral-name option hides the original name in the output file name', async ({ page, work, problems }) => {
  await openApp(page, 'blob');
  const src = await makeFile(work, 'tax return 2026.pdf', 100);
  await pick(page, src.path);
  await page.click('.options summary');
  await page.check('#hideName');
  const enc = await capture(page, 'blob', null, () => encrypt(page, STRONG), work, 'n.vault');
  expect(enc.name).toMatch(/^vault-\d{4}-\d{2}-\d{2}-[0-9a-f]{6}\.vault$/);
  expect(problems).toEqual([]);
});

test('VAULT 1.x files still decrypt', async ({ page, work, problems }) => {
  const { VECTORS } = await import('./helpers.js');
  const { readFile } = await import('node:fs/promises');
  const manifest = JSON.parse(await readFile(new URL('legacy.json', VECTORS), 'utf8'));
  await openApp(page, 'blob');
  for (const v of manifest.vectors.filter((x) => x.size > 0 && x.size < 100_000)) {
    await pick(page, new URL(v.file, VECTORS).pathname);
    await expect(page.locator('#vaultInfo')).toContainText(`format ${v.version}`);
    await expect(page.locator('#vaultInfo')).toContainText(v.filename);
    const dec = await capture(page, 'blob', null, () => decrypt(page, v.password), work, `${v.file}.out`);
    expect(sha256(dec.bytes)).toBe(v.sha256);
    await expect(page.locator('#doneDetail')).toContainText('older VAULT format');
    await page.click('#againBtn');
  }
  expect(problems).toEqual([]);
});
