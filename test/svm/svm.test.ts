import { test } from 'node:test';
import { equal, ok, throws, deepEqual } from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { base58Encode, base58Decode } from '../../src/svm/base58.js';
import { getPublicKey, sign, verify } from '../../src/svm/ed25519.js';
import { svmAddressFromSecret } from '../../src/svm/address.js';

// --- base58 -----------------------------------------------------------------

test('base58: 32 zero bytes encode to the System Program id (32 ones)', () => {
  // The Solana System Program address is base58(32 zero bytes) — a canonical,
  // citable vector.
  equal(base58Encode(new Uint8Array(32)), '1'.repeat(32));
});

test('base58: leading zero bytes become leading ones', () => {
  equal(base58Encode(Uint8Array.from([0, 0, 1])), '112');
  deepEqual([...base58Decode('112')], [0, 0, 1]);
});

test('base58: known small vectors', () => {
  // bytes [0] -> "1"; [255] -> "5Q"; "Hello World!" ascii -> known bitcoin vec
  equal(base58Encode(Uint8Array.from([0])), '1');
  equal(base58Encode(Uint8Array.from([255])), '5Q');
  equal(base58Encode(Buffer.from('Hello World!', 'ascii')), '2NEpo7TZRRrLZSi2U');
});

test('base58: round-trips arbitrary byte strings', () => {
  // Deterministic pseudo-random vectors (no Math.random in this env).
  for (let len = 0; len <= 64; len++) {
    const b = new Uint8Array(len);
    for (let i = 0; i < len; i++) b[i] = (i * 37 + len * 11 + 7) & 0xff;
    deepEqual([...base58Decode(base58Encode(b))], [...b], `len=${len}`);
  }
});

test('base58Decode: rejects non-alphabet characters', () => {
  throws(() => base58Decode('0OIl'), /invalid base58 character/);
});

// --- ed25519 ----------------------------------------------------------------

function seed(n: number): Buffer { const s = Buffer.alloc(32); s.fill(n); return s; }

/** Independent reference: derive the ed25519 public key via Node's native
 *  crypto (OpenSSL) by wrapping the seed in PKCS8, to cross-check noble. */
function nativePub(seed32: Buffer): Buffer {
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed32]);
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(key).export({ format: 'der', type: 'spki' });
  return Buffer.from(spki.subarray(-32));
}

test('ed25519: public key matches Node-native OpenSSL derivation', () => {
  for (const n of [0, 1, 7, 42, 255]) {
    ok(getPublicKey(seed(n)).equals(nativePub(seed(n))), `seed=${n}`);
  }
});

test('ed25519: sign/verify round-trips; tamper fails', () => {
  const s = seed(9);
  const pub = getPublicKey(s);
  const msg = Buffer.from('solana message');
  const sig = sign(msg, s);
  equal(sig.length, 64);
  ok(verify(sig, msg, pub));
  // Wrong message fails.
  ok(!verify(sig, Buffer.from('different'), pub));
  // Flipped signature byte fails.
  const bad = Buffer.from(sig); bad[0] = bad[0]! ^ 0x01;
  ok(!verify(bad, msg, pub));
});

test('ed25519: rejects a non-32-byte seed', () => {
  throws(() => getPublicKey(Buffer.alloc(31)), /seed must be 32 bytes/);
  throws(() => sign(Buffer.from('x'), Buffer.alloc(33)), /seed must be 32 bytes/);
});

// --- address ----------------------------------------------------------------

test('svmAddressFromSecret: is base58 of the ed25519 pubkey, decodes to 32 bytes', () => {
  const s = seed(123);
  const addr = svmAddressFromSecret(s);
  // Reverses to the public key.
  deepEqual([...base58Decode(addr)], [...getPublicKey(s)]);
  // Solana addresses are 32-byte keys; base58 length is 32–44 chars.
  ok(addr.length >= 32 && addr.length <= 44, `addr len ${addr.length}`);
});

test('svmAddressFromSecret: deterministic + distinct from EVM address space', () => {
  const s = seed(5);
  equal(svmAddressFromSecret(s), svmAddressFromSecret(s));
  // Not 0x-prefixed — it's a different address format entirely.
  ok(!svmAddressFromSecret(s).startsWith('0x'));
});
