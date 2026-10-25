// Password strength as estimated guessing entropy, in bits. Each password is
// scored as the cheapest of several attacker models (common-password list,
// dictionary word plus a suffix, diceware passphrase, raw characters with
// repeats and sequences discounted), so popular tricks are not over-rated.

const LOG2_EFF = Math.log2(7776);
// Guessing rate against Argon2id (64 MiB, t=3) for a large GPU cluster. A
// deliberately pessimistic assumption about the attacker.
export const GUESSES_PER_SECOND = 1e5;
export const WEAK_BELOW_BITS = 50;

const LEET = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', '@': 'a', $: 's', '!': 'i' };
const KEYBOARD = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'qwertzuiop', 'azertyuiop'];

let dicts = null;
export async function loadDictionaries() {
  if (!dicts) {
    const [{ WORDS }, { COMMON }] = await Promise.all([
      import('./vendor/eff-wordlist.js'),
      import('./vendor/common-passwords.js'),
    ]);
    dicts = { words: new Set(WORDS), common: new Map(COMMON.map((p, i) => [p, i])) };
  }
  return dicts;
}

const deleet = (s) => s.replace(/[013457@$!]/g, (c) => LEET[c]);

function poolSize(s) {
  let pool = 0;
  if (/[a-z]/.test(s)) pool += 26;
  if (/[A-Z]/.test(s)) pool += 26;
  if (/[0-9]/.test(s)) pool += 10;
  if (/[\x20-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]/.test(s)) pool += 33;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: matches anything outside printable ASCII
  if (/[^\x00-\x7e]/.test(s)) pool += 100;
  return Math.max(pool, 10);
}

const isSeqStep = (a, b) => Math.abs(a.codePointAt(0) - b.codePointAt(0)) === 1;
const onKeyboardRow = (a, b) =>
  KEYBOARD.some((row) => {
    const i = row.indexOf(a.toLowerCase());
    return i >= 0 && (row[i + 1] === b.toLowerCase() || row[i - 1] === b.toLowerCase());
  });

// Characters cost log2(pool) bits, except repeats and sequence steps (abc,
// 321, qwe), which cost about one bit each.
function bruteBits(s) {
  if (!s) return 0;
  const chars = [...s];
  const per = Math.log2(poolSize(s));
  let bits = per;
  for (let i = 1; i < chars.length; i++) {
    const prev = chars[i - 1];
    const cur = chars[i];
    if (cur === prev) bits += 1;
    else if (isSeqStep(prev, cur) || onKeyboardRow(prev, cur)) bits += 1.5;
    else bits += per;
  }
  return bits;
}

// Rank-based cost of a known word: log2 of its position in a frequency list.
function wordBits(word, { words, common }) {
  const rank = common.get(word);
  if (rank !== undefined) return Math.log2(rank + 2);
  if (words.has(word)) return LOG2_EFF;
  return null;
}

// Capitalizing the first letter or the whole word adds a single bit.
function caseBits(original) {
  if (original === original.toLowerCase()) return 0;
  if (original === original.toUpperCase()) return 1;
  if (original[0] === original[0].toUpperCase() && original.slice(1) === original.slice(1).toLowerCase()) return 1;
  return [...original].filter((c) => c !== c.toLowerCase()).length + 1;
}

function dictionaryBits(pw, d) {
  const lower = pw.toLowerCase();
  const candidates = [];
  for (const variant of new Set([lower, deleet(lower)])) {
    const whole = wordBits(variant, d);
    if (whole !== null) candidates.push(whole + caseBits(pw) + (variant !== lower ? 2 : 0));
    // word + suffix ("password123!") and prefix + word ("2024summer")
    const m = variant.match(/^([a-z]{3,})([^a-z]*)$/) || variant.match(/^([^a-z]*)([a-z]{3,})$/);
    if (m) {
      const [word, extra] = /^[a-z]/.test(m[1]) ? [m[1], m[2]] : [m[2], m[1]];
      const wb = wordBits(word, d);
      if (wb !== null) candidates.push(wb + caseBits(pw) + bruteBits(extra) + 1 + (variant !== lower ? 2 : 0));
    }
  }
  return candidates.length ? Math.min(...candidates) : Infinity;
}

// Diceware-style: every separator-delimited token is a dictionary word.
function passphraseBits(pw, d) {
  const tokens = pw
    .replace(/([a-z])([A-Z])/g, '$1 $2') // camelCase counts as separate words
    .split(/[\s\-_.,+:;/|]+/)
    .filter(Boolean);
  if (tokens.length < 2) return Infinity;
  let bits = 0;
  for (const t of tokens) {
    const wb = wordBits(t.toLowerCase(), d);
    bits += wb ?? bruteBits(t);
    bits += caseBits(t) ? 1 : 0;
  }
  return bits + Math.log2(tokens.length); // word count is guessable too
}

export function estimate(password, d = dicts) {
  if (!password) return null;
  const options = [bruteBits(password)];
  if (d) options.push(dictionaryBits(password, d), passphraseBits(password, d));
  const bits = Math.max(0, Math.min(...options));
  const score = bits < 28 ? 0 : bits < 36 ? 1 : bits < WEAK_BELOW_BITS ? 2 : bits < 64 ? 3 : 4;
  return {
    bits,
    score,
    label: ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'][score],
    weak: bits < WEAK_BELOW_BITS,
    crackSeconds: 2 ** (bits - 1) / GUESSES_PER_SECOND,
  };
}

export function describeCrackTime(seconds) {
  if (seconds < 1) return 'instantly';
  const steps = [
    [60, 'second'],
    [60 * 60, 'minute'],
    [24 * 3600, 'hour'],
    [365.25 * 86400, 'day'],
  ];
  let unit = 1;
  for (const [limit, name] of steps) {
    if (seconds < limit) {
      const n = Math.round(seconds / unit);
      return `about ${n} ${name}${n === 1 ? '' : 's'}`;
    }
    unit = limit;
  }
  const years = seconds / (365.25 * 86400);
  if (years < 1000) return `about ${Math.round(years)} year${Math.round(years) === 1 ? '' : 's'}`;
  if (years < 1e6) return `about ${Math.round(years / 1000)} thousand years`;
  if (years < 1e9) return `about ${Math.round(years / 1e6)} million years`;
  if (years < 1.38e10) return `about ${Math.round(years / 1e9)} billion years`;
  return 'longer than the age of the universe';
}
