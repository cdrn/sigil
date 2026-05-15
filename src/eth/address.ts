import { keccak256 } from './keccak.js';
import { getPublicKeyUncompressed } from './secp.js';

const HEX = '0123456789abcdef';

function bytesToHex(buf: Buffer | Uint8Array): string {
  let out = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]!;
    out += HEX[(b >>> 4) & 0xf]! + HEX[b & 0xf]!;
  }
  return out;
}

/**
 * Lowercase 0x-prefixed 20-byte address derived from a private key.
 */
export function addressFromPrivateKey(privateKey: Buffer | Uint8Array): string {
  const pub = getPublicKeyUncompressed(privateKey);
  // strip 0x04 prefix; address = last 20 bytes of keccak256(pub[1..])
  const hash = keccak256(pub.subarray(1));
  return '0x' + bytesToHex(hash.subarray(12));
}

/**
 * Lowercase 0x-prefixed 20-byte address derived from a 65-byte uncompressed public key.
 */
export function addressFromPublicKey(uncompressedPub: Buffer | Uint8Array): string {
  if (uncompressedPub.length !== 65) {
    throw new Error(`expected 65-byte uncompressed pubkey, got ${uncompressedPub.length}`);
  }
  if (uncompressedPub[0] !== 0x04) {
    throw new Error(`expected 0x04 prefix on uncompressed pubkey, got ${uncompressedPub[0]?.toString(16)}`);
  }
  const hash = keccak256(uncompressedPub.subarray(1));
  return '0x' + bytesToHex(hash.subarray(12));
}

/**
 * EIP-55 checksummed address (mixed-case 0x-prefixed).
 */
export function toChecksumAddress(address: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`not a 20-byte hex address: ${address}`);
  }
  const lower = address.slice(2).toLowerCase();
  const hash = keccak256(Buffer.from(lower, 'ascii'));
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    const c = lower[i]!;
    const nibble = hash[i >>> 1]! >>> (i % 2 === 0 ? 4 : 0) & 0xf;
    out += nibble >= 8 ? c.toUpperCase() : c;
  }
  return out;
}
