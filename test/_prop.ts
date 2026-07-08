/**
 * Tiny seeded-PRNG harness for property/fuzz tests. Deterministic so failures
 * reproduce — each fuzz test pins a known seed.
 *
 * splitmix64 → 53-bit float in [0, 1). Quality is fine for fuzzing test
 * inputs; do NOT use this for anything cryptographic.
 */

export type Rng = () => number;

const MASK64 = 0xffffffffffffffffn;
const STEP = 0x9e3779b97f4a7c15n;
const MIX1 = 0xbf58476d1ce4e5b9n;
const MIX2 = 0x94d049bb133111ebn;

export function makeRng(seed: number | bigint): Rng {
  let state = (typeof seed === 'bigint' ? seed : BigInt(seed)) & MASK64;
  return () => {
    state = (state + STEP) & MASK64;
    let z = state;
    z = ((z ^ (z >> 30n)) * MIX1) & MASK64;
    z = ((z ^ (z >> 27n)) * MIX2) & MASK64;
    z = z ^ (z >> 31n);
    // Take the upper 53 bits to fill a JS double's significand.
    const top53 = Number(z >> 11n);
    return top53 / 2 ** 53;
  };
}

export function rngInt(rng: Rng, minInclusive: number, maxExclusive: number): number {
  return minInclusive + Math.floor(rng() * (maxExclusive - minInclusive));
}

export function rngBytes(rng: Rng, len: number): Buffer {
  const buf = Buffer.alloc(len);
  for (let i = 0; i < len; i++) buf[i] = rngInt(rng, 0, 256);
  return buf;
}

export function rngHex(rng: Rng, byteLen: number): string {
  return rngBytes(rng, byteLen).toString('hex');
}

export function rngString(rng: Rng, maxLen: number): string {
  const len = rngInt(rng, 0, maxLen + 1);
  let out = '';
  for (let i = 0; i < len; i++) {
    // Mix printable ASCII with a sprinkling of non-ASCII to stress UTF-8 handling.
    const r = rng();
    if (r < 0.85) out += String.fromCharCode(rngInt(rng, 0x20, 0x7f));
    else out += String.fromCharCode(rngInt(rng, 0x80, 0x500));
  }
  return out;
}

export function rngPick<T>(rng: Rng, items: readonly T[]): T {
  if (items.length === 0) throw new Error('rngPick: empty array');
  return items[rngInt(rng, 0, items.length)]!;
}

export function rngBool(rng: Rng): boolean {
  return rng() < 0.5;
}
