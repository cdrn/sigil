import { test } from 'node:test';
import { deepEqual, equal, notDeepEqual, throws } from 'node:assert/strict';
import { DEFAULT_KDF_PARAMS, deriveKey, DERIVED_KEY_LEN, SALT_LEN } from '../../src/crypto/kdf.js';

// Fast params for tests — real defaults are too slow for a unit test suite.
const TEST_PARAMS = { m: 256, t: 1, p: 1 };

test('deriveKey produces a 32-byte key', () => {
  const salt = Buffer.alloc(SALT_LEN, 0x01);
  const key = deriveKey(Buffer.from('passphrase'), salt, TEST_PARAMS);
  equal(key.length, DERIVED_KEY_LEN);
});

test('deriveKey is deterministic — same inputs produce same output', () => {
  const salt = Buffer.alloc(SALT_LEN, 0x01);
  const a = deriveKey(Buffer.from('hunter2'), salt, TEST_PARAMS);
  const b = deriveKey(Buffer.from('hunter2'), salt, TEST_PARAMS);
  deepEqual(Array.from(a), Array.from(b));
});

test('deriveKey with different salts produces different keys', () => {
  const a = deriveKey(Buffer.from('p'), Buffer.alloc(SALT_LEN, 0x01), TEST_PARAMS);
  const b = deriveKey(Buffer.from('p'), Buffer.alloc(SALT_LEN, 0x02), TEST_PARAMS);
  notDeepEqual(Array.from(a), Array.from(b));
});

test('deriveKey with different passphrases produces different keys', () => {
  const salt = Buffer.alloc(SALT_LEN, 0x01);
  const a = deriveKey(Buffer.from('one'), salt, TEST_PARAMS);
  const b = deriveKey(Buffer.from('two'), salt, TEST_PARAMS);
  notDeepEqual(Array.from(a), Array.from(b));
});

test('deriveKey rejects wrong-length salt', () => {
  throws(() => deriveKey(Buffer.from('p'), Buffer.alloc(8), TEST_PARAMS), /salt must be 16 bytes/);
});

test('deriveKey rejects invalid params', () => {
  const salt = Buffer.alloc(SALT_LEN);
  throws(() => deriveKey(Buffer.from('p'), salt, { m: 4, t: 1, p: 1 }), /m must be >= 8/);
  throws(() => deriveKey(Buffer.from('p'), salt, { m: 256, t: 0, p: 1 }), /t must be >= 1/);
  throws(() => deriveKey(Buffer.from('p'), salt, { m: 256, t: 1, p: 0 }), /p must be >= 1/);
});

test('DEFAULT_KDF_PARAMS reflects expected hardening level', () => {
  // Documented choice: 64 MiB memory, 3 iterations, 4 parallelism.
  equal(DEFAULT_KDF_PARAMS.m, 64 * 1024);
  equal(DEFAULT_KDF_PARAMS.t, 3);
  equal(DEFAULT_KDF_PARAMS.p, 4);
});
