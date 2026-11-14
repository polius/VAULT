// Things that must agree across files, and rules the source must keep
// (they back the strict CSP and Trusted Types policy).
import { strict as assert } from 'node:assert';
import { readdir, readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';
import { HEADERS } from '../scripts/serve.mjs';

const read = (p) => readFile(new URL(`../${p}`, import.meta.url), 'utf8');
const pkg = JSON.parse(await read('package.json'));
const html = await read('src/index.html');
const nginx = await read('nginx.conf');
const appJs = await read('src/js/app.js');
const ownJs = await Promise.all(
  (await readdir(new URL('../src/js/', import.meta.url)))
    .filter((f) => f.endsWith('.js'))
    .map((f) => read(`src/js/${f}`)),
);

const nginxHeader = (name) => nginx.match(new RegExp(`add_header ${name} "([^"]+)" always;`))?.[1];

describe('version', () => {
  it('the footer shows the package version', () => {
    assert.match(html, new RegExp(`>v${pkg.version.replaceAll('.', '\\.')}</a>`));
  });
});

describe('security headers', () => {
  it('nginx.conf and the dev server send the same headers', () => {
    for (const [name, value] of Object.entries(HEADERS)) assert.equal(nginxHeader(name), value, name);
  });

  it('the <meta> CSP equals the header CSP minus frame-ancestors (not allowed in <meta>)', () => {
    const meta = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
    assert.equal(meta, HEADERS['Content-Security-Policy'].replace(" frame-ancestors 'self';", ''));
  });

  it('the CSP enforces Trusted Types and has no unsafe-inline or unsafe-eval', () => {
    const csp = HEADERS['Content-Security-Policy'];
    assert.match(csp, /require-trusted-types-for 'script'/);
    assert.doesNotMatch(csp, /'unsafe-inline'|'unsafe-eval'/);
  });
});

describe('module preloads (audit V4)', () => {
  // Every module app.js reaches through static imports, so the browser fetches
  // them all at once rather than discovering them one level at a time.
  async function staticGraph(entry, seen = new Set()) {
    for (const [, spec] of (await read(`src/js/${entry}`)).matchAll(/^import\s[^;]*?from\s+'\.\/([^']+)'/gms)) {
      if (seen.has(spec)) continue;
      seen.add(spec);
      await staticGraph(spec, seen);
    }
    return seen;
  }

  it('index.html preloads exactly the modules app.js imports statically', async () => {
    const preloaded = [...html.matchAll(/<link rel="modulepreload" href="js\/([^"]+)">/g)].map((m) => m[1]);
    assert.deepEqual(preloaded.toSorted(), [...(await staticGraph('app.js'))].toSorted());
  });
});

describe('icons and link previews (audit V4)', () => {
  const pngSize = async (p) => {
    const b = await readFile(new URL(`../src/${p}`, import.meta.url));
    assert.equal(b.toString('latin1', 1, 4), 'PNG', `${p} is a PNG`);
    return `${b.readUInt32BE(16)}x${b.readUInt32BE(20)}`;
  };

  it('every file the <head> points to exists', async () => {
    const refs = [...html.matchAll(/<(?:link|meta)\s[^>]*?(?:href|content)="((?:assets\/|manifest)[^"]+)"/g)].map(
      (m) => m[1],
    );
    assert.ok(refs.length >= 4, refs.join(', '));
    for (const ref of refs) await readFile(new URL(`../src/${ref}`, import.meta.url));
  });

  it('the preview image is the size the page declares', async () => {
    const meta = (p) => html.match(new RegExp(`property="og:image:${p}" content="(\\d+)"`))[1];
    assert.equal(await pngSize('assets/og.png'), `${meta('width')}x${meta('height')}`);
  });

  it('the manifest icons exist at the sizes it declares, including a maskable one', async () => {
    const manifest = JSON.parse(await read('src/manifest.json'));
    assert.equal(manifest.start_url, './');
    for (const icon of manifest.icons) {
      if (icon.type === 'image/png') assert.equal(await pngSize(icon.src), icon.sizes, icon.src);
      else await readFile(new URL(`../src/${icon.src}`, import.meta.url));
    }
    assert.ok(manifest.icons.some((i) => i.purpose === 'maskable'));
  });
});

describe('source rules', () => {
  it('no inline styles or inline scripts in index.html (style-src and script-src are self only)', () => {
    assert.doesNotMatch(html, /\sstyle="/);
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
    assert.doesNotMatch(html, /\son[a-z]+="/);
  });

  it('no HTML-parsing sinks in app code (Trusted Types would block them)', () => {
    for (const src of ownJs) assert.doesNotMatch(src, /\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write/);
  });

  it('every element app.js looks up exists in index.html', () => {
    const block = appJs.match(/Object\.fromEntries\(\s*\[([\s\S]*?)\]\.map/)[1];
    const ids = [...block.matchAll(/'([A-Za-z0-9]+)'/g)].map((m) => m[1]);
    assert.ok(ids.length > 40);
    for (const id of ids) assert.match(html, new RegExp(`id="${id}"`), `#${id} missing`);
  });

  it('every icon used has a symbol', () => {
    const used = new Set(
      [...html.matchAll(/href="#(i-[a-z-]+)"/g), ...appJs.matchAll(/'(i-[a-z-]+)'/g)].map((m) => m[1]),
    );
    for (const id of used) assert.match(html, new RegExp(`<symbol id="${id}"`), id);
  });
});
