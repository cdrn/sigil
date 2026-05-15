import { test } from 'node:test';
import { deepEqual, equal, ok, throws } from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  getPublicKeyUncompressed,
  recoverPublicKey,
  signDigest,
} from '../../src/eth/secp.js';

test('signDigest produces deterministic output (RFC 6979)', () => {
  const priv = Buffer.alloc(32); priv[31] = 1;
  const digest = Buffer.alloc(32, 7);
  const a = signDigest(digest, priv);
  const b = signDigest(digest, priv);
  deepEqual(Array.from(a.r), Array.from(b.r));
  deepEqual(Array.from(a.s), Array.from(b.s));
  equal(a.recovery, b.recovery);
});

test('signDigest rejects wrong-length digest', () => {
  const priv = Buffer.alloc(32); priv[31] = 1;
  throws(() => signDigest(Buffer.alloc(16), priv), /digest must be 32 bytes/);
});

test('signDigest returns recovery in {0,1}', () => {
  const priv = Buffer.alloc(32); priv[31] = 1;
  for (let i = 0; i < 8; i++) {
    const digest = randomBytes(32);
    const sig = signDigest(digest, priv);
    ok(sig.recovery === 0 || sig.recovery === 1, `recovery was ${sig.recovery}`);
    equal(sig.r.length, 32);
    equal(sig.s.length, 32);
  }
});

test('recoverPublicKey returns the original 65-byte uncompressed pubkey', () => {
  const priv = Buffer.alloc(32); priv[31] = 1;
  const pub = getPublicKeyUncompressed(priv);
  const digest = Buffer.alloc(32, 42);
  const sig = signDigest(digest, priv);
  const recovered = recoverPublicKey(digest, sig);
  equal(recovered.length, 65);
  equal(recovered[0], 0x04);
  deepEqual(Array.from(recovered), Array.from(pub));
});

test('getPublicKeyUncompressed has the 0x04 prefix', () => {
  const priv = Buffer.alloc(32); priv[31] = 1;
  const pub = getPublicKeyUncompressed(priv);
  equal(pub.length, 65);
  equal(pub[0], 0x04);
});
