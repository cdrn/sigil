/**
 * Base58 (Bitcoin / Solana alphabet) encode + decode.
 *
 * Hand-rolled to keep sigil's dependency surface small (same posture as the
 * hand-rolled keccak / RLP in src/eth). Inputs here are tiny — 32-byte
 * addresses and 64-byte signatures — so the simple BigInt long-division
 * implementation is more than fast enough; we don't need the byte-array
 * division trick.
 *
 * Leading zero bytes map to leading '1' characters (and vice versa), which is
 * what makes the all-zero 32-byte System Program key encode to 32 '1's.
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = 58n;

// Reverse lookup: char code -> digit value, -1 for non-alphabet chars.
const LOOKUP: Int8Array = (() => {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) t[ALPHABET.charCodeAt(i)] = i;
  return t;
})();

export function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  let num = 0n;
  for (const b of bytes) num = (num << 8n) + BigInt(b);

  let out = '';
  while (num > 0n) {
    const rem = Number(num % BASE);
    num /= BASE;
    out = ALPHABET[rem]! + out;
  }
  return '1'.repeat(zeros) + out;
}

export function base58Decode(str: string): Uint8Array {
  let num = 0n;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    const v = code < 128 ? LOOKUP[code]! : -1;
    if (v < 0) throw new Error(`invalid base58 character ${JSON.stringify(str[i])} at index ${i}`);
    num = num * BASE + BigInt(v);
  }

  const rev: number[] = [];
  while (num > 0n) {
    rev.push(Number(num & 0xffn));
    num >>= 8n;
  }

  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;

  const out = new Uint8Array(zeros + rev.length);
  // rev holds the big-endian body in reverse; copy it back after the zeros.
  for (let i = 0; i < rev.length; i++) out[zeros + i] = rev[rev.length - 1 - i]!;
  return out;
}
