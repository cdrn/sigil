import { test } from 'node:test';
import { equal, ok, throws } from 'node:assert/strict';
import { base58Encode } from '../../src/svm/base58.js';
import { decodeTx, parseMessage } from '../../src/svm/transaction.js';

// --- builders ---------------------------------------------------------------
// Minimal Solana message serializer (all counts < 128, so shortvec == 1 byte).
// Used to drive the parser; an explicit byte-vector anchor below guards against
// the builder and parser sharing a bug.

function key(n: number): Uint8Array { const k = new Uint8Array(32); k.fill(n); return k; }
const SYSTEM = new Uint8Array(32); // all zeros

interface Ix { programIdIndex: number; accounts: number[]; data: Uint8Array }

function transferIx(programIdIndex: number, from: number, to: number, lamports: bigint): Ix {
  const data = new Uint8Array(12);
  data[0] = 2; // System Transfer discriminant (u32 LE)
  let v = lamports;
  for (let i = 0; i < 8; i++) { data[4 + i] = Number(v & 0xffn); v >>= 8n; }
  return { programIdIndex, accounts: [from, to], data };
}

function buildMessage(opts: {
  version?: 'legacy' | 0;
  header?: [number, number, number];
  accounts: Uint8Array[];
  blockhash?: Uint8Array;
  instructions: Ix[];
  altLookups?: { key: Uint8Array; writable: number[]; readonly: number[] }[];
}): Uint8Array {
  const out: number[] = [];
  const version = opts.version ?? 'legacy';
  if (version === 0) out.push(0x80);
  const [a, b, c] = opts.header ?? [1, 0, 1];
  out.push(a, b, c);
  out.push(opts.accounts.length);
  for (const k of opts.accounts) out.push(...k);
  out.push(...(opts.blockhash ?? key(9)));
  out.push(opts.instructions.length);
  for (const ix of opts.instructions) {
    out.push(ix.programIdIndex);
    out.push(ix.accounts.length, ...ix.accounts);
    out.push(ix.data.length, ...ix.data);
  }
  if (version === 0) {
    const lookups = opts.altLookups ?? [];
    out.push(lookups.length);
    for (const l of lookups) {
      out.push(...l.key);
      out.push(l.writable.length, ...l.writable);
      out.push(l.readonly.length, ...l.readonly);
    }
  }
  return Uint8Array.from(out);
}

// --- decode -----------------------------------------------------------------

test('decodeTx: a single native SOL transfer (legacy)', () => {
  // accounts: [signer=0, recipient=1, system=2]
  const accounts = [key(1), key(2), SYSTEM];
  const msg = buildMessage({ accounts, instructions: [transferIx(2, 0, 1, 5_000_000n)] });
  const d = decodeTx(msg);
  equal(d.allDecoded, true);
  equal(d.transfers.length, 1);
  equal(d.transfers[0]!.from, base58Encode(key(1)));
  equal(d.transfers[0]!.to, base58Encode(key(2)));
  equal(d.transfers[0]!.lamports, 5_000_000n);
  equal(d.message.version, 'legacy');
  equal(d.message.numRequiredSignatures, 1);
});

test('decodeTx: multiple transfers all decode', () => {
  const accounts = [key(1), key(2), key(3), SYSTEM];
  const msg = buildMessage({
    accounts,
    instructions: [transferIx(3, 0, 1, 100n), transferIx(3, 0, 2, 200n)],
  });
  const d = decodeTx(msg);
  equal(d.allDecoded, true);
  equal(d.transfers.length, 2);
  equal(d.transfers[0]!.lamports + d.transfers[1]!.lamports, 300n);
});

test('decodeTx: a non-System instruction makes allDecoded false', () => {
  // account[2] is some program (key 7), not the System program.
  const accounts = [key(1), key(2), key(7)];
  const msg = buildMessage({
    accounts,
    instructions: [{ programIdIndex: 2, accounts: [0, 1], data: Uint8Array.from([9, 9, 9]) }],
  });
  const d = decodeTx(msg);
  equal(d.allDecoded, false);
  equal(d.transfers.length, 0);
});

test('decodeTx: a System instruction that is not Transfer is not decoded', () => {
  const accounts = [key(1), key(2), SYSTEM];
  // discriminant 0 (CreateAccount) with 12 bytes — recognized System program
  // but not a Transfer, so it must NOT be auto-decoded.
  const data = new Uint8Array(12); data[0] = 0;
  const msg = buildMessage({ accounts, instructions: [{ programIdIndex: 2, accounts: [0, 1], data }] });
  const d = decodeTx(msg);
  equal(d.allDecoded, false);
  equal(d.transfers.length, 0);
});

test('decodeTx: v0 message with a transfer decodes; ALT-referenced accounts do not', () => {
  const accounts = [key(1), key(2), SYSTEM];
  // A transfer over static accounts in a v0 message → decodes.
  const ok0 = decodeTx(buildMessage({ version: 0, accounts, instructions: [transferIx(2, 0, 1, 42n)] }));
  equal(ok0.allDecoded, true);
  equal(ok0.transfers[0]!.lamports, 42n);

  // A transfer whose recipient index (3) points beyond the static keys (ALT
  // account) cannot be resolved offline → undecoded.
  const altMsg = buildMessage({
    version: 0,
    accounts,
    instructions: [transferIx(2, 0, 3, 42n)],
    altLookups: [{ key: key(8), writable: [0], readonly: [] }],
  });
  const d = decodeTx(altMsg);
  equal(d.allDecoded, false);
  equal(d.transfers.length, 0);
});

test('parseMessage: rejects truncated and trailing-byte messages', () => {
  const accounts = [key(1), key(2), SYSTEM];
  const good = buildMessage({ accounts, instructions: [transferIx(2, 0, 1, 1n)] });
  throws(() => parseMessage(good.subarray(0, good.length - 3)), /unexpected end|trailing/);
  const withTrailer = Uint8Array.from([...good, 0xff]);
  throws(() => parseMessage(withTrailer), /trailing bytes/);
  throws(() => parseMessage(new Uint8Array(0)), /empty message/);
});

test('decodeTx: explicit byte-vector anchor (independent of the builder)', () => {
  // Hand-assembled legacy transfer of 1 lamport from key(1) to key(2):
  const bytes = Uint8Array.from([
    1, 0, 1,                    // header
    3,                          // 3 account keys
    ...key(1), ...key(2), ...SYSTEM,
    ...key(9),                  // blockhash
    1,                          // 1 instruction
    2,                          // programIdIndex -> system
    2, 0, 1,                    // 2 accounts: [0,1]
    12, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, // data: Transfer + 1 lamport LE
  ]);
  const d = decodeTx(bytes);
  equal(d.allDecoded, true);
  equal(d.transfers.length, 1);
  equal(d.transfers[0]!.lamports, 1n);
  ok(d.transfers[0]!.to === base58Encode(key(2)));
});
