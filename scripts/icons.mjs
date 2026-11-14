// Renders the PNG icons and the link-preview image from src/assets/logo.svg.
//
//   node scripts/icons.mjs     (needs the e2e dependencies: cd e2e && npm ci)
//
// The PNGs are committed, so this only runs when the logo or the page colours
// change. Text in the preview image uses the system font, so the output is not
// byte-for-byte the same on every machine.
import { readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';

const ROOT = new URL('../', import.meta.url);
const ASSETS = new URL('src/assets/', ROOT);
const { chromium } = createRequire(new URL('e2e/package.json', ROOT))('@playwright/test');

const logo = `data:image/svg+xml;base64,${(await readFile(new URL('logo.svg', ASSETS))).toString('base64')}`;
const BG = '#f4f4f0'; // --bg, light theme
const INK = '#14161a'; // --ink
const MUTED = '#555b66'; // --muted
const SANS = "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif";

// A square with the logo centred. `scale` is the logo's share of the side.
const square = (bg, scale) => `
  <body style="margin:0;width:100vw;height:100vh;display:grid;place-items:center;background:${bg}">
    <img src="${logo}" style="width:${scale * 100}vw;height:${scale * 100}vw">
  </body>`;

const preview = `
  <body style="margin:0;width:1200px;height:630px;box-sizing:border-box;padding:0 96px;display:flex;
               align-items:center;gap:72px;background:${BG};font-family:${SANS};color:${INK}">
    <img src="${logo}" style="width:280px;height:280px;flex:none">
    <div>
      <div style="font:600 30px/1 ${SANS};letter-spacing:.14em;color:${MUTED}">VAULT</div>
      <div style="margin-top:28px;font:700 64px/1.1 ${SANS};letter-spacing:-.02em">Lock a file with a password.</div>
      <div style="margin-top:20px;font:400 36px/1.3 ${SANS};color:${MUTED}">It never leaves this device.</div>
    </div>
  </body>`;

const OUTPUTS = [
  // iOS fills transparency with black and rounds the corners itself.
  { file: 'apple-touch-icon.png', size: 180, html: square(BG, 0.72) },
  { file: 'icon-192.png', size: 192, html: square('transparent', 0.9) },
  { file: 'icon-512.png', size: 512, html: square('transparent', 0.9) },
  // Launchers crop maskable icons to a circle 80% of the side wide.
  { file: 'icon-maskable-512.png', size: 512, html: square(BG, 0.56) },
  { file: 'og.png', width: 1200, height: 630, html: preview },
];

const browser = await chromium.launch();
try {
  for (const { file, size, width = size, height = size, html } of OUTPUTS) {
    const page = await browser.newPage({ viewport: { width, height } });
    await page.setContent(`<!doctype html>${html}`);
    await page.waitForFunction(() => [...document.images].every((i) => i.complete));
    await writeFile(new URL(file, ASSETS), await page.screenshot({ omitBackground: true }));
    await page.close();
    console.log(`src/assets/${file}  ${width}x${height}`);
  }
} finally {
  await browser.close();
}
