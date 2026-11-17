import { keccak256 } from './keccak.js';

/**
 * Minimal Solidity ABI decoder (no encoder): enough to turn calldata, event
 * data and revert payloads into values for the transaction preview. Hand-
 * rolled on top of the existing keccak so the runtime dependency set stays
 * at the pinned @noble/* + @iarna/toml.
 *
 * Every byte this module reads is attacker-supplied (the agent hands sigil
 * calldata; a contract under simulation picks its own logs and revert data),
 * so decoding is strict and bounded:
 *   - every offset and length is checked against the buffer before use, and
 *     any violation is an AbiDecodeError — never a raw RangeError or a
 *     silently short read;
 *   - static values must be canonically padded (a uint8 with high bits set,
 *     an address with a dirty upper word, a bool of 2) — non-canonical
 *     encodings are how two decoders get made to disagree about one payload;
 *   - total decoded output is budgeted against the input size, so offsets
 *     that alias one large element many times can't amplify a small payload
 *     into a huge allocation.
 */

export type AbiType =
  | { kind: 'uint'; bits: number }
  | { kind: 'int'; bits: number }
  | { kind: 'address' }
  | { kind: 'bool' }
  | { kind: 'fixedBytes'; size: number }
  | { kind: 'bytes' }
  | { kind: 'string' }
  | { kind: 'array'; inner: AbiType; length: number | null }
  | { kind: 'tuple'; components: AbiType[] };

export class AbiDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AbiDecodeError';
  }
}

/** Fixed-array lengths above this are refused at parse time: no real ABI
 *  uses them, and the head size would overflow any calldata anyway. */
const MAX_FIXED_ARRAY = 1 << 16;
/** Nesting depth cap for type strings (tuples within arrays within …). */
const MAX_TYPE_DEPTH = 32;

/**
 * Parse a canonical Solidity type string: `uint256`, `int8`, `address`,
 * `bool`, `bytes32`, `bytes`, `string`, `T[k]`, `T[]`, `(T1,T2,…)` and any
 * nesting of those. `uint`/`int` are accepted as aliases for the 256-bit
 * forms. Whitespace is not allowed (canonical signatures have none).
 */
export function parseAbiType(t: string): AbiType {
  const p = { s: t, i: 0 };
  const type = parseTypeAt(p, 0);
  if (p.i !== t.length) {
    throw new AbiDecodeError(`invalid ABI type "${t}": unexpected "${t.slice(p.i)}"`);
  }
  return type;
}

/**
 * Parse a function or event signature `name(T1,T2,…)` into its name and
 * parameter types. The name must be a Solidity identifier.
 */
export function parseSignature(signature: string): { name: string; inputs: AbiType[] } {
  const open = signature.indexOf('(');
  const name = open === -1 ? '' : signature.slice(0, open);
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) {
    throw new AbiDecodeError(`invalid signature "${signature}"`);
  }
  const params = parseAbiType(signature.slice(open));
  if (params.kind !== 'tuple') {
    throw new AbiDecodeError(`invalid signature "${signature}": parameters must be a list`);
  }
  return { name, inputs: params.components };
}

/** The canonical string for a parsed type (round-trips through parseAbiType). */
export function canonicalType(t: AbiType): string {
  switch (t.kind) {
    case 'uint':
    case 'int':
      return `${t.kind}${t.bits}`;
    case 'fixedBytes':
      return `bytes${t.size}`;
    case 'array':
      return `${canonicalType(t.inner)}[${t.length ?? ''}]`;
    case 'tuple':
      return `(${t.components.map(canonicalType).join(',')})`;
    default:
      return t.kind;
  }
}

function parseTypeAt(p: { s: string; i: number }, depth: number): AbiType {
  if (depth > MAX_TYPE_DEPTH) throw new AbiDecodeError(`ABI type nested too deeply: "${p.s}"`);
  let base: AbiType;
  if (p.s[p.i] === '(') {
    p.i++;
    const components: AbiType[] = [];
    if (p.s[p.i] === ')') {
      p.i++;
    } else {
      for (;;) {
        components.push(parseTypeAt(p, depth + 1));
        const c = p.s[p.i];
        p.i++;
        if (c === ')') break;
        if (c !== ',') throw new AbiDecodeError(`invalid ABI type "${p.s}": expected , or )`);
      }
    }
    base = { kind: 'tuple', components };
  } else {
    const m = /^[a-z]+[0-9]*/.exec(p.s.slice(p.i));
    if (!m) throw new AbiDecodeError(`invalid ABI type "${p.s}"`);
    p.i += m[0].length;
    base = parseElementary(m[0], p.s);
  }
  // Array suffixes, applied left to right: uint256[2][] is a dynamic array
  // of uint256[2].
  while (p.s[p.i] === '[') {
    const close = p.s.indexOf(']', p.i);
    if (close === -1) throw new AbiDecodeError(`invalid ABI type "${p.s}": unclosed [`);
    const inner = p.s.slice(p.i + 1, close);
    let length: number | null = null;
    if (inner !== '') {
      if (!/^[1-9][0-9]*$/.test(inner) || Number(inner) > MAX_FIXED_ARRAY) {
        throw new AbiDecodeError(`invalid ABI type "${p.s}": bad array length "${inner}"`);
      }
      length = Number(inner);
    }
    base = { kind: 'array', inner: base, length };
    p.i = close + 1;
  }
  return base;
}

function parseElementary(name: string, whole: string): AbiType {
  if (name === 'address') return { kind: 'address' };
  if (name === 'bool') return { kind: 'bool' };
  if (name === 'string') return { kind: 'string' };
  if (name === 'bytes') return { kind: 'bytes' };
  if (name === 'uint' || name === 'int') return { kind: name, bits: 256 };
  let m = /^(u?int)([0-9]+)$/.exec(name);
  if (m) {
    const bits = Number(m[2]);
    if (bits < 8 || bits > 256 || bits % 8 !== 0 || String(bits) !== m[2]) {
      throw new AbiDecodeError(`invalid ABI type "${whole}": bad integer width ${m[2]}`);
    }
    return { kind: m[1] as 'uint' | 'int', bits };
  }
  m = /^bytes([0-9]+)$/.exec(name);
  if (m) {
    const size = Number(m[1]);
    if (size < 1 || size > 32 || String(size) !== m[1]) {
      throw new AbiDecodeError(`invalid ABI type "${whole}": bad bytes width ${m[1]}`);
    }
    return { kind: 'fixedBytes', size };
  }
  throw new AbiDecodeError(`unsupported ABI type "${name}" in "${whole}"`);
}

/** True when the type's encoding lives in the tail (has an offset in the head). */
export function isDynamic(t: AbiType): boolean {
  switch (t.kind) {
    case 'bytes':
    case 'string':
      return true;
    case 'array':
      return t.length === null || isDynamic(t.inner);
    case 'tuple':
      return t.components.some(isDynamic);
    default:
      return false;
  }
}

/** Bytes the type occupies in its enclosing head. */
function headSize(t: AbiType): number {
  if (isDynamic(t)) return 32;
  if (t.kind === 'array') return t.length! * headSize(t.inner);
  if (t.kind === 'tuple') return t.components.reduce((n, c) => n + headSize(c), 0);
  return 32;
}

/**
 * Decode `data` as the ABI encoding of a parameter list. Values:
 *   uint/int → bigint (two's complement for int), address → lowercase 0x
 *   hex, bool → boolean, bytesN/bytes → lowercase 0x hex, string → string
 *   (UTF-8, invalid sequences replaced), arrays and tuples → unknown[].
 * Trailing bytes after the encoding are tolerated (calldata commonly carries
 * them); everything the types reference must be in bounds.
 */
export function decodeAbiParameters(types: readonly string[], data: Uint8Array): unknown[] {
  return decodeAbiTypes(types.map(parseAbiType), data);
}

/** Same as decodeAbiParameters, for pre-parsed types. */
export function decodeAbiTypes(types: readonly AbiType[], data: Uint8Array): unknown[] {
  const budget = { left: data.length * 4 + 4096 };
  return decodeTuple(types, data, 0, budget, 0);
}

interface Budget {
  left: number;
}

function spend(budget: Budget, n: number): void {
  budget.left -= n;
  if (budget.left < 0) {
    throw new AbiDecodeError('decoded output exceeds budget (aliased offsets?)');
  }
}

function word(data: Uint8Array, pos: number): Uint8Array {
  if (pos < 0 || pos + 32 > data.length) {
    throw new AbiDecodeError(`read of 32 bytes at ${pos} past end of ${data.length}-byte data`);
  }
  return data.subarray(pos, pos + 32);
}

function wordToBigint(w: Uint8Array): bigint {
  let hex = '';
  for (let i = 0; i < w.length; i++) hex += w[i]!.toString(16).padStart(2, '0');
  return hex === '' ? 0n : BigInt('0x' + hex);
}

/** Read a word as an offset/length; must fit comfortably within the data. */
function readSize(data: Uint8Array, pos: number, what: string): number {
  const v = wordToBigint(word(data, pos));
  if (v > BigInt(data.length)) {
    throw new AbiDecodeError(`${what} ${v} at ${pos} exceeds ${data.length}-byte data`);
  }
  return Number(v);
}

function toHex(b: Uint8Array): string {
  return '0x' + Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('hex');
}

function decodeTuple(
  types: readonly AbiType[],
  data: Uint8Array,
  base: number,
  budget: Budget,
  depth: number,
): unknown[] {
  if (depth > MAX_TYPE_DEPTH) throw new AbiDecodeError('ABI value nested too deeply');
  const out: unknown[] = [];
  let head = base;
  for (const t of types) {
    if (isDynamic(t)) {
      const off = readSize(data, head, 'offset');
      const at = base + off;
      if (at >= data.length) {
        throw new AbiDecodeError(`offset ${off} (from ${base}) points past end of data`);
      }
      out.push(decodeAt(t, data, at, budget, depth));
    } else {
      out.push(decodeAt(t, data, head, budget, depth));
    }
    head += headSize(t);
  }
  return out;
}

function decodeAt(
  t: AbiType,
  data: Uint8Array,
  pos: number,
  budget: Budget,
  depth: number,
): unknown {
  spend(budget, 32);
  switch (t.kind) {
    case 'uint': {
      const v = wordToBigint(word(data, pos));
      if (t.bits < 256 && v >> BigInt(t.bits) !== 0n) {
        throw new AbiDecodeError(`uint${t.bits} at ${pos} has non-zero high bits`);
      }
      return v;
    }
    case 'int': {
      const raw = wordToBigint(word(data, pos));
      const v = raw >= 1n << 255n ? raw - (1n << 256n) : raw;
      const lim = 1n << BigInt(t.bits - 1);
      if (v < -lim || v >= lim) {
        throw new AbiDecodeError(`int${t.bits} at ${pos} is not canonically sign-extended`);
      }
      return v;
    }
    case 'address': {
      const w = word(data, pos);
      for (let i = 0; i < 12; i++) {
        if (w[i] !== 0) throw new AbiDecodeError(`address at ${pos} has a dirty upper word`);
      }
      return toHex(w.subarray(12));
    }
    case 'bool': {
      const v = wordToBigint(word(data, pos));
      if (v > 1n) throw new AbiDecodeError(`bool at ${pos} is ${v}, not 0 or 1`);
      return v === 1n;
    }
    case 'fixedBytes': {
      const w = word(data, pos);
      for (let i = t.size; i < 32; i++) {
        if (w[i] !== 0) throw new AbiDecodeError(`bytes${t.size} at ${pos} has non-zero padding`);
      }
      return toHex(w.subarray(0, t.size));
    }
    case 'bytes':
    case 'string': {
      const len = readSize(data, pos, 'length');
      const start = pos + 32;
      if (start + len > data.length) {
        throw new AbiDecodeError(`${t.kind} of ${len} bytes at ${pos} runs past end of data`);
      }
      spend(budget, len);
      const raw = data.subarray(start, start + len);
      return t.kind === 'bytes' ? toHex(raw) : new TextDecoder('utf-8').decode(raw);
    }
    case 'array': {
      let length: number;
      let base: number;
      if (t.length === null) {
        length = readSize(data, pos, 'array length');
        base = pos + 32;
      } else {
        length = t.length;
        base = pos;
      }
      // Each element occupies at least one head word; refuse lengths the
      // remaining data cannot possibly hold before allocating anything.
      const elemHead = headSize(t.inner);
      if (base + length * elemHead > data.length) {
        throw new AbiDecodeError(`array of ${length} at ${pos} runs past end of data`);
      }
      return decodeTuple(new Array<AbiType>(length).fill(t.inner), data, base, budget, depth + 1);
    }
    case 'tuple':
      return decodeTuple(t.components, data, pos, budget, depth + 1);
  }
}

/** Lowercase 0x + 8 hex: the first four bytes of keccak256(signature). */
export function functionSelector(signature: string): string {
  return '0x' + keccak256(Buffer.from(signature, 'utf8')).subarray(0, 4).toString('hex');
}

/** Lowercase 0x + 64 hex: keccak256(signature), the log's topic0. */
export function eventTopic(signature: string): string {
  return '0x' + keccak256(Buffer.from(signature, 'utf8')).toString('hex');
}
