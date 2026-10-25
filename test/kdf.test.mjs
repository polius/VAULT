// The vendored Argon2id must match an independent implementation. Expected
// values come from OpenSSL 3.2+:
//   openssl kdf -keylen 32 -kdfopt pass:password -kdfopt salt:somesaltsomesalt \
//     -kdfopt iter:3 -kdfopt memcost:19456 -kdfopt lanes:1 ARGON2ID
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { ARGON2_DEFAULTS, argon2id } from '../src/js/kdf.js';

const hex = (b) => Buffer.from(b).toString('hex');
const te = new TextEncoder();

describe('Argon2id known answers (OpenSSL)', () => {
  it('m=19456, t=3, p=1', async () => {
    const out = await argon2id(te.encode('password'), te.encode('somesaltsomesalt'), { m: 19456, t: 3, p: 1 });
    assert.equal(hex(out), 'ad076cfc1bba7680e5017d6afb1e614f8c4dfeb060d4fc7cd59d270be0084755');
  });

  it('VAULT defaults (m=64 MiB, t=3, p=1)', async () => {
    assert.deepEqual({ ...ARGON2_DEFAULTS }, { m: 65536, t: 3, p: 1 });
    const salt = Uint8Array.from({ length: 16 }, (_, i) => i);
    const out = await argon2id(te.encode('correct horse'), salt, ARGON2_DEFAULTS);
    assert.equal(hex(out), 'e3c889ca40ed01e6b6771fc8a5bf16e35ad60b41c9bd5d7e6d63adf51e50b0fd');
  });
});
