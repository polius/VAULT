// Renders the PNG icons and the link-preview image from src/assets/logo.svg.
//
//   node scripts/icons.mjs     (needs the e2e dependencies: cd e2e && npm ci)
//
// The PNGs are committed, so this only runs when the logo or the page colours
// change. Text in the preview image uses the page's own typeface.
import { readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';

const ROOT = new URL('../', import.meta.url);
const ASSETS = new URL('src/assets/', ROOT);
const { chromium } = createRequire(new URL('e2e/package.json', ROOT))('@playwright/test');

const svgText = await readFile(new URL('logo.svg', ASSETS), 'utf8');
const dataUrl = (svg) => `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
const BG = '#f1f3ee'; // --bg, light theme
const INK = '#10201a'; // --ink
const SEAL = '#0b7d5f'; // --seal
// The mark in the page's green, and reversed for the app icons: a pale strand on a green tile.
const logo = dataUrl(svgText);
const logoOnSeal = dataUrl(svgText.replace(`color="${SEAL}"`, `color="${BG}"`).replace(/<style>[\s\S]*?<\/style>/, ''));

// The preview image uses the page's own typeface when it is there.
const font = await readFile(new URL('fonts/archivo.woff2', ASSETS)).catch(() => null);
const SANS = "Archivo, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif";
const fontFace = font
  ? `<style>@font-face{font-family:Archivo;font-weight:100 900;font-stretch:62% 125%;
       src:url(data:font/woff2;base64,${font.toString('base64')}) format('woff2')}</style>`
  : '';

// A square with the mark centred. `scale` is the mark's share of the side.
const square = (bg, mark, scale) => `
  <body style="margin:0;width:100vw;height:100vh;display:grid;place-items:center;background:${bg}">
    <img src="${mark}" style="width:${scale * 100}vw;height:${scale * 100}vw">
  </body>`;

const preview = `${fontFace}
  <body style="margin:0;width:1200px;height:630px;box-sizing:border-box;padding:0 96px;display:flex;
               align-items:center;gap:60px;background:${BG};font-family:${SANS};color:${INK}">
    <img src="${logo}" style="width:220px;height:220px;flex:none">
    <div>
      <div style="font:700 26px/1 ${SANS};font-stretch:125%;letter-spacing:.2em">VAULT</div>
      <div style="margin-top:28px;font:640 46px/1.06 ${SANS};font-stretch:108%;letter-spacing:-.028em;white-space:nowrap">
        Lock a file with a password.<br><span style="color:${SEAL}">It never leaves this device.</span>
      </div>
    </div>
  </body>`;

const OUTPUTS = [
  // iOS fills transparency with black and rounds the corners itself.
  { file: 'apple-touch-icon.png', size: 180, html: square(SEAL, logoOnSeal, 0.7) },
  { file: 'icon-192.png', size: 192, html: square('transparent', logo, 0.92) },
  { file: 'icon-512.png', size: 512, html: square('transparent', logo, 0.92) },
  // Launchers crop maskable icons to a circle 80% of the side wide.
  { file: 'icon-maskable-512.png', size: 512, html: square(SEAL, logoOnSeal, 0.56) },
  { file: 'og.png', width: 1200, height: 630, html: preview },
];

const browser = await chromium.launch();
try {
  for (const { file, size, width = size, height = size, html } of OUTPUTS) {
    const page = await browser.newPage({ viewport: { width, height } });
    await page.setContent(`<!doctype html>${html}`);
    await page.waitForFunction(() => [...document.images].every((i) => i.complete));
    await page.evaluate(() => document.fonts.ready);
    await writeFile(new URL(file, ASSETS), await page.screenshot({ omitBackground: true }));
    await page.close();
    console.log(`src/assets/${file}  ${width}x${height}`);
  }
} finally {
  await browser.close();
}
