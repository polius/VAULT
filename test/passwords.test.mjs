// Strength estimate (audit M4) and passphrase generator (audit M5).
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { generatePassphrase, passphraseBits } from '../src/js/passphrase.js';
import { describeCrackTime, estimate, loadDictionaries, WEAK_BELOW_BITS } from '../src/js/strength.js';
import { WORDS } from '../src/js/vendor/eff-wordlist.js';

const dicts = await loadDictionaries();

describe('estimate', () => {
  const weak = [
    'password',
    'Password1!',
    'P@ssw0rd',
    'qwerty123',
    'aaaaaaaaaaaaaaaa',
    'abcdefghijkl',
    'dragon2024',
    'Summer2024!',
  ];
  for (const pw of weak) {
    it(`${JSON.stringify(pw)} is weak`, () => {
      const e = estimate(pw, dicts);
      assert.ok(e.weak, `${pw}: ${e.bits.toFixed(1)} bits`);
    });
  }

  const strong = ['visitor-ravishing-thickness-eskimo-blip-sterile', 'kX9#mQ2$vL7!pR4&', 'x7Gq-29fL-pW3z-8Kd2'];
  for (const pw of strong) {
    it(`${JSON.stringify(pw)} is strong`, () => {
      const e = estimate(pw, dicts);
      assert.ok(!e.weak && e.score >= 3, `${pw}: ${e.bits.toFixed(1)} bits`);
    });
  }

  it('a 4-word passphrase rates far above Password1! (the 1.x meter rated both Medium)', () => {
    assert.ok(estimate('correct horse battery staple', dicts).bits > estimate('Password1!', dicts).bits + 30);
  });

  it('works without dictionaries (before they load)', () => {
    const e = estimate('abc', null);
    assert.equal(e.score, 0);
  });

  it('empty password has no estimate', () => {
    assert.equal(estimate('', dicts), null);
  });

  it('the weak threshold is 50 bits', () => {
    assert.equal(WEAK_BELOW_BITS, 50);
  });
});

describe('describeCrackTime', () => {
  for (const [s, text] of [
    [0.1, 'instantly'],
    [30, 'about 30 seconds'],
    [90, 'about 2 minutes'],
    [3 * 3600, 'about 3 hours'],
    [3 * 86400, 'about 3 days'],
    [5 * 365.25 * 86400, 'about 5 years'],
    [2e6 * 365.25 * 86400, 'about 2 million years'],
    [1e30, 'longer than the age of the universe'],
  ]) {
    it(`${s} s -> ${text}`, () => assert.equal(describeCrackTime(s), text));
  }
});

describe('generatePassphrase', () => {
  it('six EFF words joined by hyphens, about 77 bits', async () => {
    const words = new Set(WORDS.filter((w) => !w.includes('-')));
    assert.equal(words.size, 7772);
    const phrase = await generatePassphrase();
    const parts = phrase.split('-');
    assert.equal(parts.length, 6);
    for (const w of parts) assert.ok(words.has(w), w);
    assert.ok(Math.abs(passphraseBits() - 77.5) < 0.1);
    assert.ok(estimate(phrase, dicts).bits >= 75);
  });

  it('does not repeat itself', async () => {
    const seen = new Set();
    for (let i = 0; i < 200; i++) seen.add(await generatePassphrase());
    assert.equal(seen.size, 200);
  });

  it('uses the whole list without bias (chi-squared on the first letter)', async () => {
    const list = WORDS.filter((w) => !w.includes('-'));
    const expected = {};
    for (const w of list) expected[w[0]] = (expected[w[0]] ?? 0) + 1 / list.length;
    const counts = {};
    const N = 6000;
    for (let i = 0; i < N / 6; i++) {
      for (const w of (await generatePassphrase()).split('-')) counts[w[0]] = (counts[w[0]] ?? 0) + 1;
    }
    let chi = 0;
    for (const [k, p] of Object.entries(expected)) chi += ((counts[k] ?? 0) - N * p) ** 2 / (N * p);
    // 25 degrees of freedom: p < 1e-6 above ~75, so a false failure is negligible.
    assert.ok(chi < 75, `chi-squared ${chi.toFixed(1)}`);
  });
});
