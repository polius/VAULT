// Key derivation. Argon2id (format v3) runs in a worker so the page stays
// responsive; Node and browsers without module workers run it inline.

export const ARGON2_DEFAULTS = Object.freeze({ m: 65536, t: 3, p: 1 }); // 64 MiB, 3 passes

async function inline(password, salt, { m, t, p }) {
  const { argon2id } = await import('./vendor/argon2.js');
  return argon2id({
    password,
    salt,
    parallelism: p,
    iterations: t,
    memorySize: m,
    hashLength: 32,
    outputType: 'binary',
  });
}

async function inWorker(password, salt, params) {
  const { scriptURL } = await import('./tt.js');
  const worker = new Worker(scriptURL('./kdf-worker.js'), { type: 'module', name: 'vault-kdf' });
  try {
    return await new Promise((resolve, reject) => {
      worker.onmessage = ({ data }) => (data.ok ? resolve(data.out) : reject(new Error(data.message)));
      worker.onerror = (e) => {
        e.preventDefault();
        reject(new Error(e.message || 'Key derivation worker failed to start'));
      };
      worker.postMessage({ password, salt, ...params });
    });
  } finally {
    worker.terminate();
  }
}

// Returns 32 raw bytes. `password` is a Uint8Array the caller zeroes afterwards.
export async function argon2id(password, salt, params) {
  if (typeof Worker === 'function' && typeof document !== 'undefined') {
    try {
      return await inWorker(password.slice(), salt, params);
    } catch (err) {
      console.warn('Argon2id worker unavailable, deriving on the main thread:', err);
    }
  }
  return inline(password, salt, params);
}

// Legacy formats v1/v2: PBKDF2-SHA-512 straight to an AES-GCM key.
export async function pbkdf2Key(password, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-512' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
}
