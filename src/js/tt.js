// Trusted Types. The CSP enforces `require-trusted-types-for 'script'` and only
// allows the policy named "vault", which accepts exactly the two scripts this
// app loads at runtime. Browsers without Trusted Types get plain strings.

const ALLOWED = new Set([new URL('../sw.js', import.meta.url).href, new URL('./kdf-worker.js', import.meta.url).href]);

const policy = globalThis.trustedTypes?.createPolicy('vault', {
  createScriptURL(url) {
    if (!ALLOWED.has(new URL(url, import.meta.url).href)) throw new TypeError(`Blocked script URL: ${url}`);
    return url;
  },
});

export function scriptURL(url) {
  const href = new URL(url, import.meta.url).href;
  return policy ? policy.createScriptURL(href) : href;
}
