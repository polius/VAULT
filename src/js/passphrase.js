// Diceware passphrases from the EFF large wordlist, words joined by hyphens.
// The 4 words that contain a hyphen themselves (t-shirt, yo-yo, ...) are left
// out so a passphrase always splits back into its words. That leaves 7,772
// words, about 12.92 bits each, so the default 6 words give about 77 bits.

export const DEFAULT_WORDS = 6;

let pool = null;
async function words() {
  if (!pool) {
    const { WORDS } = await import('./vendor/eff-wordlist.js');
    pool = WORDS.filter((w) => !w.includes('-'));
  }
  return pool;
}

// Uniform index in [0, n) without modulo bias.
function uniform(n) {
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf);
  while (buf[0] >= limit);
  return buf[0] % n;
}

export async function generatePassphrase(count = DEFAULT_WORDS) {
  const list = await words();
  return Array.from({ length: count }, () => list[uniform(list.length)]).join('-');
}

export const passphraseBits = (count = DEFAULT_WORDS) => count * Math.log2(7772);
