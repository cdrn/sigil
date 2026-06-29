import { base58Encode } from './base58.js';
import { getPublicKey } from './ed25519.js';

/**
 * The Solana address controlled by a portal's secret.
 *
 * A Solana address IS the base58 of the 32-byte ed25519 public key. We derive
 * that key from the portal's raw 32-byte secret (the same bytes used as the
 * secp256k1 key for EVM), so one portal controls both an `0x…` EVM address and
 * a base58 Solana address — different strings, same secret.
 *
 * Note: this address will NOT match a Solana account derived from a seed
 * phrase via BIP44 (m/44'/501'/0'/0'); it matches the "import private key"
 * path in Phantom/Solflare, which uses the raw bytes as the ed25519 seed.
 */
export function svmAddressFromSecret(secret: Buffer | Uint8Array): string {
  return base58Encode(getPublicKey(secret));
}
