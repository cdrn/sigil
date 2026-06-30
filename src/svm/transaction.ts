import { base58Encode } from './base58.js';

/**
 * Minimal Solana transaction-message parser + native-transfer decoder.
 *
 * sigil signs the serialized *message* a caller hands it (ed25519 over the
 * bytes), but to apply policy it first decodes what it can offline. Solana
 * hides most semantics behind account indices and on-chain state, so the only
 * thing reliably decodable without RPC is the **System Program transfer**
 * (native SOL). Everything else — SPL token transfers, arbitrary programs,
 * accounts pulled in via address-lookup-tables — is left as "undecoded", and
 * the policy layer routes those to an out-of-band human confirm.
 *
 * Supports both legacy and v0 (versioned) messages. For v0 we parse the
 * address-table-lookup section to consume the bytes correctly, but any
 * instruction that references an ALT-loaded account (index >= number of static
 * keys) is treated as undecoded, since we can't resolve it offline.
 */

/** The System Program id is the all-zero 32-byte key. */
export const SYSTEM_PROGRAM_ID: Uint8Array = new Uint8Array(32);
/** System instruction discriminant for `Transfer` (little-endian u32). */
const SYS_IX_TRANSFER = 2;

export interface SolInstruction {
  programIdIndex: number;
  accountIndexes: number[];
  data: Uint8Array;
}

export interface SolMessage {
  version: 'legacy' | 0;
  numRequiredSignatures: number;
  numReadonlySigned: number;
  numReadonlyUnsigned: number;
  /** The static account keys carried in the message (32 bytes each). */
  staticAccountKeys: Uint8Array[];
  recentBlockhash: Uint8Array;
  instructions: SolInstruction[];
  /** Number of address-table lookups (v0 only; 0 for legacy). */
  addressTableLookupCount: number;
}

export interface SolTransfer {
  /** base58 sender (the funding account). */
  from: string;
  /** base58 recipient. */
  to: string;
  lamports: bigint;
}

export interface DecodedTx {
  message: SolMessage;
  /** Recognized System-Program transfers, in instruction order. */
  transfers: SolTransfer[];
  /**
   * True iff EVERY instruction in the message was decoded as a recognized
   * System transfer over static accounts. When false, the message contains
   * something we can't see offline and policy must route it to confirm.
   */
  allDecoded: boolean;
}

// ---------------------------------------------------------------------------
// Byte cursor with bounds checks
// ---------------------------------------------------------------------------

class Cursor {
  #buf: Uint8Array;
  #o = 0;
  constructor(buf: Uint8Array) { this.#buf = buf; }

  get offset(): number { return this.#o; }
  get done(): boolean { return this.#o === this.#buf.length; }

  #need(n: number): void {
    if (this.#o + n > this.#buf.length) {
      throw new Error(`unexpected end of message: need ${n} bytes at offset ${this.#o}, have ${this.#buf.length - this.#o}`);
    }
  }

  u8(): number { this.#need(1); return this.#buf[this.#o++]!; }

  bytes(n: number): Uint8Array {
    this.#need(n);
    const out = this.#buf.subarray(this.#o, this.#o + n);
    this.#o += n;
    return out;
  }

  /** compact-u16 (shortvec): 1–3 bytes, 7 bits each, little-endian groups. */
  shortVec(): number {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = this.u8();
      value |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
      if (shift > 14) throw new Error('shortvec length exceeds u16 range');
    }
    return value;
  }
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

export function parseMessage(bytes: Uint8Array): SolMessage {
  if (bytes.length === 0) throw new Error('empty message');
  const c = new Cursor(bytes);

  let version: 'legacy' | 0;
  const first = bytes[0]!;
  if ((first & 0x80) !== 0) {
    const v = first & 0x7f;
    if (v !== 0) throw new Error(`unsupported message version ${v} (only legacy and v0 supported)`);
    version = 0;
    c.u8(); // consume version byte
  } else {
    version = 'legacy';
  }

  const numRequiredSignatures = c.u8();
  const numReadonlySigned = c.u8();
  const numReadonlyUnsigned = c.u8();

  const numKeys = c.shortVec();
  const staticAccountKeys: Uint8Array[] = [];
  for (let i = 0; i < numKeys; i++) staticAccountKeys.push(Uint8Array.from(c.bytes(32)));

  const recentBlockhash = Uint8Array.from(c.bytes(32));

  const numIx = c.shortVec();
  const instructions: SolInstruction[] = [];
  for (let i = 0; i < numIx; i++) {
    const programIdIndex = c.u8();
    const numAcc = c.shortVec();
    const accountIndexes: number[] = [];
    for (let j = 0; j < numAcc; j++) accountIndexes.push(c.u8());
    const dataLen = c.shortVec();
    const data = Uint8Array.from(c.bytes(dataLen));
    instructions.push({ programIdIndex, accountIndexes, data });
  }

  let addressTableLookupCount = 0;
  if (version === 0) {
    const numLookups = c.shortVec();
    addressTableLookupCount = numLookups;
    for (let i = 0; i < numLookups; i++) {
      c.bytes(32); // table account key
      const nw = c.shortVec();
      c.bytes(nw); // writable indexes
      const nr = c.shortVec();
      c.bytes(nr); // readonly indexes
    }
  }

  if (!c.done) {
    throw new Error(`trailing bytes after message: parsed ${c.offset} of ${bytes.length}`);
  }

  return {
    version,
    numRequiredSignatures,
    numReadonlySigned,
    numReadonlyUnsigned,
    staticAccountKeys,
    recentBlockhash,
    instructions,
    addressTableLookupCount,
  };
}

// ---------------------------------------------------------------------------
// Decode native (System Program) transfers
// ---------------------------------------------------------------------------

export function decodeTx(bytes: Uint8Array): DecodedTx {
  const message = parseMessage(bytes);
  const n = message.staticAccountKeys.length;
  const transfers: SolTransfer[] = [];
  let allDecoded = true;
  for (const ix of message.instructions) {
    const t = decodeSystemTransfer(ix, message, n);
    if (t) transfers.push(t);
    else allDecoded = false;
  }
  return { message, transfers, allDecoded };
}

function decodeSystemTransfer(ix: SolInstruction, message: SolMessage, n: number): SolTransfer | null {
  // Program must be a static account and the System Program.
  if (ix.programIdIndex >= n) return null;
  if (!isSystemProgram(message.staticAccountKeys[ix.programIdIndex]!)) return null;
  // Transfer payload is exactly 12 bytes: u32 LE discriminant (2) + u64 LE lamports.
  if (ix.data.length !== 12) return null;
  if (readU32LE(ix.data, 0) !== SYS_IX_TRANSFER) return null;
  if (ix.accountIndexes.length < 2) return null;
  const fromIdx = ix.accountIndexes[0]!;
  const toIdx = ix.accountIndexes[1]!;
  // Both accounts must be static (an ALT-loaded account can't be resolved offline).
  if (fromIdx >= n || toIdx >= n) return null;
  return {
    from: base58Encode(message.staticAccountKeys[fromIdx]!),
    to: base58Encode(message.staticAccountKeys[toIdx]!),
    lamports: readU64LE(ix.data, 4),
  };
}

function isSystemProgram(key: Uint8Array): boolean {
  if (key.length !== 32) return false;
  for (let i = 0; i < 32; i++) if (key[i] !== 0) return false;
  return true;
}

function readU32LE(b: Uint8Array, off: number): number {
  return (b[off]! | (b[off + 1]! << 8) | (b[off + 2]! << 16) | (b[off + 3]! << 24)) >>> 0;
}

function readU64LE(b: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i]!);
  return v;
}
