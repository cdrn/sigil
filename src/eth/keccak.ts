import { keccak_256 } from '@noble/hashes/sha3.js';

export function keccak256(data: Buffer | Uint8Array): Buffer {
  return Buffer.from(keccak_256(data));
}
