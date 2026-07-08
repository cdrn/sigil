import { test } from 'node:test';
import { deepEqual, equal, throws } from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  AeadVerifyError,
  aeadDecrypt,
  aeadEncrypt,
} from '../../src/crypto/aead.js';

function freshKey() {
  return randomBytes(AEAD_KEY_LEN);
}
function freshNonce() {
  return randomBytes(AEAD_NONCE_LEN);
}

test('xchacha20poly1305 output is pinned across dependency upgrades (keyfile compatibility)', () => {
  // Known-answer vector computed with @noble/ciphers 1.3.0. If this fails
  // after a dependency bump, DO NOT update the expected value — a changed
  // cipher output means every keyfile already on disk becomes undecryptable.
  // The round-trip tests below can't catch that: they seal and open with the
  // same library version.
  const key = Buffer.from(Uint8Array.from({ length: 32 }, (_, i) => i));
  const nonce = Buffer.from(Uint8Array.from({ length: 24 }, (_, i) => 100 + i));
  const plaintext = Buffer.from('sigil keyfile compatibility vector', 'utf8');
  const V1_CT =
    '0f1a9ed9930ee2e7fe56f453c34fdea636cb33058d4ea3dce5211d875d3b1b64c4743363cbb68ce825fc150bb5cdef1ffdb3';
  const ct = aeadEncrypt(key, nonce, plaintext);
  equal(Buffer.from(ct).toString('hex'), V1_CT);
  const pt = aeadDecrypt(key, nonce, Buffer.from(V1_CT, 'hex'));
  deepEqual(Buffer.from(pt), plaintext);
});

test('round trip', () => {
  const key = freshKey();
  const nonce = freshNonce();
  const pt = Buffer.from('the quick brown fox');
  const ct = aeadEncrypt(key, nonce, pt);
  const out = aeadDecrypt(key, nonce, ct);
  deepEqual(Array.from(out), Array.from(pt));
});

test('round trip with AAD', () => {
  const key = freshKey();
  const nonce = freshNonce();
  const pt = Buffer.from([1, 2, 3, 4, 5]);
  const aad = Buffer.from('header-bound-data');
  const ct = aeadEncrypt(key, nonce, pt, aad);
  const out = aeadDecrypt(key, nonce, ct, aad);
  deepEqual(Array.from(out), Array.from(pt));
});

test('wrong key fails verify', () => {
  const key = freshKey();
  const nonce = freshNonce();
  const ct = aeadEncrypt(key, nonce, Buffer.from('hi'));
  throws(() => aeadDecrypt(freshKey(), nonce, ct), AeadVerifyError);
});

test('wrong nonce fails verify', () => {
  const key = freshKey();
  const nonce = freshNonce();
  const ct = aeadEncrypt(key, nonce, Buffer.from('hi'));
  throws(() => aeadDecrypt(key, freshNonce(), ct), AeadVerifyError);
});

test('tampered ciphertext fails verify', () => {
  const key = freshKey();
  const nonce = freshNonce();
  const ct = aeadEncrypt(key, nonce, Buffer.from('hello world'));
  ct[0] = (ct[0] ?? 0) ^ 0x01;
  throws(() => aeadDecrypt(key, nonce, ct), AeadVerifyError);
});

test('mismatched AAD fails verify', () => {
  const key = freshKey();
  const nonce = freshNonce();
  const ct = aeadEncrypt(key, nonce, Buffer.from('hi'), Buffer.from('aad-A'));
  throws(() => aeadDecrypt(key, nonce, ct, Buffer.from('aad-B')), AeadVerifyError);
});

test('omitted AAD on decrypt fails if encrypt provided one', () => {
  const key = freshKey();
  const nonce = freshNonce();
  const ct = aeadEncrypt(key, nonce, Buffer.from('hi'), Buffer.from('aad'));
  throws(() => aeadDecrypt(key, nonce, ct), AeadVerifyError);
});

test('rejects wrong-length key', () => {
  throws(
    () => aeadEncrypt(Buffer.alloc(16), freshNonce(), Buffer.alloc(0)),
    /key must be 32 bytes/,
  );
});

test('rejects wrong-length nonce', () => {
  throws(
    () => aeadEncrypt(freshKey(), Buffer.alloc(12), Buffer.alloc(0)),
    /nonce must be 24 bytes/,
  );
});
