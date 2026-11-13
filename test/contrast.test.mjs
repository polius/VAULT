// Contrast of the colour tokens, computed from app.css itself (audit V2, D1).
// Text needs 4.5:1 (WCAG 1.4.3); field outlines, the bar's outline and its fill
// need 3:1 against the paper (WCAG 1.4.11).
import { strict as assert } from 'node:assert';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';

const css = await readFile(new URL('../src/css/app.css', import.meta.url), 'utf8');

function tokens(selector) {
  const start = css.indexOf(`${selector} {`);
  assert.ok(start >= 0, `${selector} not found`);
  const body = css.slice(start, css.indexOf('}', start));
  return Object.fromEntries([...body.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})\s*;/g)].map((m) => [m[1], m[2]]));
}

const light = tokens(':root');
const dark = tokens(':root[data-theme="dark"]');
const darkAuto = tokens('  :root:not([data-theme="light"])');

function luminance(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = Number.parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const TEXT = 4.5;
const UI = 3;
const pairs = [
  ['ink', 'bg', TEXT],
  ['ink', 'surface', TEXT],
  ['ink', 'soft', TEXT],
  ['muted', 'bg', TEXT],
  ['muted', 'surface', TEXT],
  ['muted', 'soft', TEXT],
  ['danger', 'bg', TEXT],
  ['danger', 'soft', TEXT],
  ['warn', 'bg', TEXT],
  ['warn', 'soft', TEXT],
  ['on-accent', 'lock', TEXT],
  ['on-accent', 'lock-hover', TEXT],
  ['on-accent', 'unlock', TEXT],
  ['on-accent', 'unlock-hover', TEXT],
  ['field-line', 'bg', UI],
  ['field-line', 'surface', UI],
  ['lock', 'bg', UI],
  ['unlock', 'bg', UI],
  ['unlock', 'surface', UI],
];

for (const [name, theme] of [
  ['light', light],
  ['dark', dark],
]) {
  describe(`${name} theme contrast`, () => {
    for (const [fg, bg, min] of pairs) {
      it(`--${fg} on --${bg} is at least ${min}:1`, () => {
        assert.ok(theme[fg] && theme[bg], `missing --${fg} or --${bg}`);
        const c = contrast(theme[fg], theme[bg]);
        assert.ok(c >= min, `${theme[fg]} on ${theme[bg]}: ${c.toFixed(2)}`);
      });
    }
  });
}

describe('dark tokens', () => {
  it('the system dark theme and the chosen dark theme are the same', () => {
    assert.deepEqual(darkAuto, dark);
  });
});
