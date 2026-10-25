// Runs Argon2id off the main thread. Receives { password, salt, m, t, p },
// replies { ok, out } with 32 raw bytes, and zeroes its copy of the password.
import { argon2id } from './vendor/argon2.js';

self.onmessage = async ({ data }) => {
  try {
    const out = await argon2id({
      password: data.password,
      salt: data.salt,
      parallelism: data.p,
      iterations: data.t,
      memorySize: data.m,
      hashLength: 32,
      outputType: 'binary',
    });
    self.postMessage({ ok: true, out }, [out.buffer]);
  } catch (err) {
    self.postMessage({ ok: false, message: String(err?.message || err) });
  } finally {
    data.password.fill(0);
  }
};
