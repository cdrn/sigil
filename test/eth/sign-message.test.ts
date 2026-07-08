import { test } from 'node:test';
import { deepEqual, equal, throws } from 'node:assert/strict';
import {
  deserializeEthSignature,
  personalSign,
  personalSignDigest,
  serializeEthSignature,
} from '../../src/eth/sign-message.js';
import { addressFromPublicKey } from '../../src/eth/address.js';
import { recoverPublicKey, signDigest } from '../../src/eth/secp.js';

const PRIV = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
const ADDR = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf';

test('personalSignDigest matches the EIP-191 prefix construction for known msg', () => {
  // For empty message, digest = keccak256("\x19Ethereum Signed Message:\n0").
  const digest = personalSignDigest(Buffer.alloc(0));
  equal(digest.toString('hex'), '5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad');
});

test('personalSign produces a 65-byte signature (r||s||v)', () => {
  const sig = personalSign(Buffer.from('hello'), PRIV);
  equal(sig.length, 65);
  const v = sig[64]!;
  equal(v === 27 || v === 28, true);
});

test('signed message recovers to the signer address', () => {
  const msg = Buffer.from('the quick brown fox');
  const sig = personalSign(msg, PRIV);
  const parsed = deserializeEthSignature(sig);
  const digest = personalSignDigest(msg);
  const pub = recoverPublicKey(digest, parsed);
  equal(addressFromPublicKey(pub), ADDR);
});

test('serialize/deserialize round trip preserves r, s, recovery', () => {
  const digest = personalSignDigest(Buffer.from('roundtrip'));
  const sig = signDigest(digest, PRIV);
  const bytes = serializeEthSignature(sig);
  const back = deserializeEthSignature(bytes);
  deepEqual(Array.from(back.r), Array.from(sig.r));
  deepEqual(Array.from(back.s), Array.from(sig.s));
  equal(back.recovery, sig.recovery);
});

test('deserializeEthSignature rejects wrong-length input', () => {
  throws(() => deserializeEthSignature(Buffer.alloc(64)), /expected 65-byte/);
});

test('deserializeEthSignature rejects invalid v', () => {
  const bad = Buffer.alloc(65);
  bad[64] = 30;
  throws(() => deserializeEthSignature(bad), /expected v in/);
});
