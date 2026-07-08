import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';

// One-time wiring: noble/secp256k1 v3 keeps itself dep-free and expects the
// caller to plug in sha256/hmac-sha256 implementations. The cast through
// `unknown` papers over noble's stricter `Uint8Array<ArrayBuffer>` vs
// `Uint8Array<ArrayBufferLike>` typing — semantically the functions match.

type Hashes = typeof secp.hashes;
(secp.hashes as Hashes).sha256 = sha256 as unknown as Hashes['sha256'];
(secp.hashes as Hashes).hmacSha256 = ((key: Uint8Array, msg: Uint8Array) =>
  hmac(sha256, key, msg)) as unknown as Hashes['hmacSha256'];

export interface EthSignature {
  r: Buffer;
  s: Buffer;
  recovery: 0 | 1;
}

export function getPublicKeyUncompressed(privateKey: Buffer | Uint8Array): Buffer {
  return Buffer.from(secp.getPublicKey(privateKey, false));
}

/**
 * Generate a fresh secp256k1 secret key. Uses the platform CSPRNG via
 * noble's utility, which is uniform over the valid scalar range (handles
 * the vanishingly small bias of raw 256-bit random against N).
 */
export function randomSecretKey(): Buffer {
  return Buffer.from(secp.utils.randomSecretKey());
}

/**
 * Signs a 32-byte digest and returns the Ethereum-shaped components.
 * The noble v3 recovered format is `recovery || r || s` (recovery is byte 0).
 */
export function signDigest(
  digest: Buffer | Uint8Array,
  privateKey: Buffer | Uint8Array,
): EthSignature {
  if (digest.length !== 32) throw new Error(`digest must be 32 bytes, got ${digest.length}`);
  // prehash: false — the caller already passed a 32-byte keccak digest; noble's default is
  // sha256(message) which would double-hash. Without this, sigs verify only against sigil's own
  // recoverPublicKey (which has the same default) and fail Ethereum consensus recovery.
  const sigR = secp.sign(digest, privateKey, { format: 'recovered', prehash: false });
  const recovery = sigR[0];
  if (recovery !== 0 && recovery !== 1) {
    throw new Error(`unexpected recovery byte: ${recovery}`);
  }
  return {
    recovery,
    r: Buffer.from(sigR.slice(1, 33)),
    s: Buffer.from(sigR.slice(33, 65)),
  };
}

/**
 * Recover the 65-byte uncompressed public key (with 0x04 prefix) from a digest and signature.
 * Used in tests and address derivation from signature.
 */
export function recoverPublicKey(digest: Buffer | Uint8Array, sig: EthSignature): Buffer {
  if (digest.length !== 32) throw new Error(`digest must be 32 bytes, got ${digest.length}`);
  const sigR = new Uint8Array(65);
  sigR[0] = sig.recovery;
  sigR.set(sig.r, 1);
  sigR.set(sig.s, 33);
  // prehash: false — see signDigest comment. Recovery must use the raw 32-byte digest.
  const compressed = secp.recoverPublicKey(sigR, digest, { prehash: false });
  // recoverPublicKey returns compressed (33 bytes) — convert to uncompressed.
  const point = secp.Point.fromBytes(compressed);
  return Buffer.from(point.toBytes(false));
}
