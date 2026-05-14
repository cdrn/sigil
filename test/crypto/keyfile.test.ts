import { test } from 'node:test';
import { deepEqual, equal, notDeepEqual, throws } from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  HEADER_LEN,
  KeyfileFormatError,
  WrongPassphraseError,
  sealKey,
  unsealKey,
} from '../../src/crypto/keyfile.js';

// Fast KDF params for tests.
const TEST_KDF = { m: 256, t: 1, p: 1 };

test('seal/unseal round trip recovers the original key', () => {
  const plain = randomBytes(32);
  const pass = Buffer.from('correct horse battery staple');
  const sealed = sealKey(plain, pass, TEST_KDF);
  const opened = unsealKey(sealed, pass);
  try {
    deepEqual(Array.from(opened.bytes()), Array.from(plain));
  } finally {
    opened.dispose();
  }
});

test('wrong passphrase fails with WrongPassphraseError', () => {
  const plain = randomBytes(32);
  const sealed = sealKey(plain, Buffer.from('right'), TEST_KDF);
  throws(() => unsealKey(sealed, Buffer.from('wrong')), WrongPassphraseError);
});

test('tampered ciphertext byte fails verify', () => {
  const sealed = sealKey(randomBytes(32), Buffer.from('p'), TEST_KDF);
  // Flip a bit in the ciphertext region.
  sealed[HEADER_LEN] = (sealed[HEADER_LEN] ?? 0) ^ 0x01;
  throws(() => unsealKey(sealed, Buffer.from('p')), WrongPassphraseError);
});

test('tampered salt fails verify (AAD binding)', () => {
  const sealed = sealKey(randomBytes(32), Buffer.from('p'), TEST_KDF);
  // Salt starts at offset 16: 5 magic + 1 ver + 1 kdf + 4 m + 1 t + 1 p + 1 aead + 2 reserved.
  sealed[16] = (sealed[16] ?? 0) ^ 0xff;
  throws(() => unsealKey(sealed, Buffer.from('p')), WrongPassphraseError);
});

test('tampered nonce fails verify (AAD binding)', () => {
  const sealed = sealKey(randomBytes(32), Buffer.from('p'), TEST_KDF);
  // Nonce starts at offset 32 (16 header + 16 salt).
  sealed[32] = (sealed[32] ?? 0) ^ 0xff;
  throws(() => unsealKey(sealed, Buffer.from('p')), WrongPassphraseError);
});

test('bad magic is rejected at decode', () => {
  const sealed = sealKey(randomBytes(32), Buffer.from('p'), TEST_KDF);
  sealed[0] = 0x00;
  throws(() => unsealKey(sealed, Buffer.from('p')), KeyfileFormatError);
});

test('unsupported format version is rejected at decode', () => {
  const sealed = sealKey(randomBytes(32), Buffer.from('p'), TEST_KDF);
  sealed[5] = 0xff;
  throws(() => unsealKey(sealed, Buffer.from('p')), KeyfileFormatError);
});

test('unsupported kdf type is rejected at decode', () => {
  const sealed = sealKey(randomBytes(32), Buffer.from('p'), TEST_KDF);
  sealed[6] = 0xff;
  throws(() => unsealKey(sealed, Buffer.from('p')), KeyfileFormatError);
});

test('unsupported aead type is rejected at decode', () => {
  const sealed = sealKey(randomBytes(32), Buffer.from('p'), TEST_KDF);
  // aead type byte is at offset 13 (after 5 magic + 1 ver + 1 kdf type + 4 m + 1 t + 1 p).
  sealed[13] = 0xff;
  throws(() => unsealKey(sealed, Buffer.from('p')), KeyfileFormatError);
});

test('truncated keyfile is rejected at decode', () => {
  const sealed = sealKey(randomBytes(32), Buffer.from('p'), TEST_KDF);
  const truncated = sealed.subarray(0, HEADER_LEN - 1);
  throws(() => unsealKey(truncated, Buffer.from('p')), KeyfileFormatError);
});

test('different invocations produce different ciphertext (fresh salt + nonce)', () => {
  const plain = randomBytes(32);
  const pass = Buffer.from('p');
  const a = sealKey(plain, pass, TEST_KDF);
  const b = sealKey(plain, pass, TEST_KDF);
  notDeepEqual(Array.from(a), Array.from(b));
});

test('header is exactly HEADER_LEN bytes and ciphertext is plaintext.length + 16 (poly1305 tag)', () => {
  const plain = randomBytes(32);
  const sealed = sealKey(plain, Buffer.from('p'), TEST_KDF);
  equal(sealed.length, HEADER_LEN + plain.length + 16);
});

test('preserves KDF params in header (decoded keyfile uses stored params, not defaults)', () => {
  const plain = randomBytes(32);
  const pass = Buffer.from('p');
  const sealed = sealKey(plain, pass, { m: 256, t: 2, p: 1 });
  // If params weren't preserved, unseal would derive a different key and AEAD would fail.
  const opened = unsealKey(sealed, pass);
  try {
    deepEqual(Array.from(opened.bytes()), Array.from(plain));
  } finally {
    opened.dispose();
  }
});
