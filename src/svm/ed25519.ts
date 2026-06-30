import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

// One-time wiring: noble/ed25519 v3 keeps itself dep-free and expects the
// caller to plug in a synchronous SHA-512 (it needs it for the seed -> scalar
// expansion and the deterministic nonce). We reuse @noble/hashes, exactly as
// src/eth/secp.ts wires sha256/hmac for noble/secp256k1. The cast papers over
// noble's stricter `Uint8Array<ArrayBuffer>` vs `Uint8Array<ArrayBufferLike>`
// typing — semantically the function matches.
type Hashes = typeof ed.hashes;
(ed.hashes as Hashes).sha512 = sha512 as unknown as Hashes['sha512'];

/**
 * Derive the 32-byte ed25519 public key from a 32-byte seed.
 *
 * The "seed" is the portal's raw secret — the SAME 32 bytes that serve as the
 * secp256k1 private key for EVM. ed25519 hashes the seed (clamped SHA-512) to
 * get its actual signing scalar, so the ed25519 key is independent of the
 * secp256k1 scalar even though both come from one secret. This is exactly the
 * derivation Phantom/Solflare perform on "import private key", so the address
 * this produces is recoverable there.
 */
export function getPublicKey(seed: Buffer | Uint8Array): Buffer {
  if (seed.length !== 32) throw new Error(`ed25519 seed must be 32 bytes, got ${seed.length}`);
  return Buffer.from(ed.getPublicKey(seed));
}

/**
 * Sign a message with the ed25519 key derived from `seed`. Returns the 64-byte
 * detached signature (R ‖ S).
 */
export function sign(message: Buffer | Uint8Array, seed: Buffer | Uint8Array): Buffer {
  if (seed.length !== 32) throw new Error(`ed25519 seed must be 32 bytes, got ${seed.length}`);
  return Buffer.from(ed.sign(message, seed));
}

/** Verify — used in tests and by callers that want to self-check a signature. */
export function verify(
  signature: Buffer | Uint8Array,
  message: Buffer | Uint8Array,
  publicKey: Buffer | Uint8Array,
): boolean {
  return ed.verify(signature, message, publicKey);
}
