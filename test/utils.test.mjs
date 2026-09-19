// Pure helper tests — no KDF, run instantly.
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { formatFileSize, calculatePasswordStrength } from '../src/js/utils.js';

describe('formatFileSize', () => {
  const cases = [
    [0, '0 Bytes'],
    [1, '1 Bytes'],
    [1023, '1023 Bytes'],
    [1024, '1 KB'],
    [1536, '1.5 KB'],
    [1024 ** 3, '1 GB'],
    [2 ** 40, '1 TB'],
    [2 ** 50, '1 PB'],
    [2 ** 60, '1024 PB'], // clamped, never "undefined"
  ];
  for (const [input, expected] of cases) {
    it(`${input} -> "${expected}"`, () => {
      assert.equal(formatFileSize(input), expected);
    });
  }
});

describe('calculatePasswordStrength', () => {
  it('empty password', () => {
    assert.equal(calculatePasswordStrength(''), null);
  });
  it('weak', () => {
    assert.equal(calculatePasswordStrength('abc').level, 'weak');
  });
  it('medium', () => {
    assert.equal(calculatePasswordStrength('abcdefgh1234').level, 'medium');
  });
  it('strong', () => {
    assert.equal(calculatePasswordStrength('Abcdefgh-1234-!xyz').level, 'strong');
  });
});
