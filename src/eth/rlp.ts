/**
 * Minimal RLP encoder/decoder for transaction signing. Supports byte strings
 * and (nested) lists. No support for other types — we never need them.
 *
 * Ref: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
 */

export type RlpInput = Buffer | Uint8Array | RlpInput[];

function encodeLength(len: number, offset: number): Buffer {
  if (len < 56) {
    return Buffer.from([offset + len]);
  }
  const hex = len.toString(16);
  const lenBytes = Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
  return Buffer.concat([Buffer.from([offset + 55 + lenBytes.length]), lenBytes]);
}

function encodeItem(item: RlpInput): Buffer {
  if (Array.isArray(item)) {
    const inner = Buffer.concat(item.map(encodeItem));
    return Buffer.concat([encodeLength(inner.length, 0xc0), inner]);
  }
  const buf = item instanceof Buffer ? item : Buffer.from(item);
  if (buf.length === 1 && buf[0]! < 0x80) {
    return Buffer.from([buf[0]!]);
  }
  return Buffer.concat([encodeLength(buf.length, 0x80), buf]);
}

export function rlpEncode(input: RlpInput): Buffer {
  return encodeItem(input);
}

/**
 * Encode a non-negative integer as a minimal big-endian byte string,
 * dropping leading zeros. 0 encodes to empty buffer (RLP convention).
 */
export function encodeInt(n: number | bigint): Buffer {
  let v = typeof n === 'bigint' ? n : BigInt(n);
  if (v < 0n) throw new Error('cannot encode negative integer');
  if (v === 0n) return Buffer.alloc(0);
  let hex = v.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex');
}

interface DecodeResult {
  value: Buffer | DecodeResult[];
  consumed: number;
}

function decodeItem(buf: Buffer, offset: number): DecodeResult {
  if (offset >= buf.length) throw new Error('rlp: unexpected end of input');
  const first = buf[offset]!;
  if (first < 0x80) {
    return { value: Buffer.from([first]), consumed: 1 };
  }
  if (first < 0xb8) {
    const len = first - 0x80;
    return { value: Buffer.from(buf.subarray(offset + 1, offset + 1 + len)), consumed: 1 + len };
  }
  if (first < 0xc0) {
    const lenOfLen = first - 0xb7;
    const len = parseInt(buf.subarray(offset + 1, offset + 1 + lenOfLen).toString('hex'), 16);
    const start = offset + 1 + lenOfLen;
    return { value: Buffer.from(buf.subarray(start, start + len)), consumed: 1 + lenOfLen + len };
  }
  if (first < 0xf8) {
    const len = first - 0xc0;
    const items: DecodeResult[] = [];
    let p = offset + 1;
    const end = p + len;
    while (p < end) {
      const item = decodeItem(buf, p);
      items.push(item);
      p += item.consumed;
    }
    return { value: items, consumed: 1 + len };
  }
  const lenOfLen = first - 0xf7;
  const len = parseInt(buf.subarray(offset + 1, offset + 1 + lenOfLen).toString('hex'), 16);
  const start = offset + 1 + lenOfLen;
  const items: DecodeResult[] = [];
  let p = start;
  const end = start + len;
  while (p < end) {
    const item = decodeItem(buf, p);
    items.push(item);
    p += item.consumed;
  }
  return { value: items, consumed: 1 + lenOfLen + len };
}

export type Decoded = Buffer | Decoded[];

function strip(d: DecodeResult): Decoded {
  if (Array.isArray(d.value)) return d.value.map(strip);
  return d.value;
}

export function rlpDecode(buf: Buffer): Decoded {
  const { value, consumed } = decodeItem(buf, 0);
  if (consumed !== buf.length) throw new Error('rlp: extra bytes after item');
  if (Array.isArray(value)) return value.map(strip);
  return value;
}
