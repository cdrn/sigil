import { keccak256 } from './keccak.js';
import { signDigest, type EthSignature } from './secp.js';

/**
 * EIP-191 personal_sign: keccak256("\x19Ethereum Signed Message:\n" + len + message).
 *
 * `message` is treated as opaque bytes. If you have a string, encode it to UTF-8 first.
 */
export function personalSignDigest(message: Buffer | Uint8Array): Buffer {
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${message.length}`, 'utf8');
  return keccak256(
    Buffer.concat([prefix, Buffer.isBuffer(message) ? message : Buffer.from(message)]),
  );
}

/**
 * EIP-191 personal_sign returning a 65-byte serialized sig (r || s || v) where v = recovery + 27.
 */
export function personalSign(
  message: Buffer | Uint8Array,
  privateKey: Buffer | Uint8Array,
): Buffer {
  const digest = personalSignDigest(message);
  return serializeEthSignature(signDigest(digest, privateKey));
}

/**
 * Serialize an EthSignature to the 65-byte form used by personal_sign / eth_sign_typed_data:
 * r (32) || s (32) || v (1, where v = recovery + 27).
 */
export function serializeEthSignature(sig: EthSignature): Buffer {
  const out = Buffer.alloc(65);
  sig.r.copy(out, 0);
  sig.s.copy(out, 32);
  out[64] = sig.recovery + 27;
  return out;
}

export function deserializeEthSignature(bytes: Buffer | Uint8Array): EthSignature {
  if (bytes.length !== 65) throw new Error(`expected 65-byte signature, got ${bytes.length}`);
  const v = bytes[64]!;
  if (v !== 27 && v !== 28) throw new Error(`expected v in {27, 28}, got ${v}`);
  return {
    r: Buffer.from(bytes.subarray(0, 32)),
    s: Buffer.from(bytes.subarray(32, 64)),
    recovery: (v - 27) as 0 | 1,
  };
}
