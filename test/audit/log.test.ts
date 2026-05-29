import { test } from 'node:test';
import { deepEqual, equal, notEqual, ok, throws } from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AuditChainError,
  AuditWriter,
  type AuditEntry,
  HASH_HEX_LEN,
  type StoredAuditEntry,
  ZERO_HASH,
  canonicalJSON,
  hashEntry,
  parseLine,
  readHead,
  sealEntry,
  serializeEntry,
  verifyChain,
} from '../../src/audit/log.js';
import { makeRng, rngBool, rngBytes, rngInt, rngPick, rngString } from '../_prop.js';

// ============================================================================
// canonicalJSON
// ============================================================================

test('canonicalJSON sorts object keys lexicographically', () => {
  equal(canonicalJSON({ b: 1, a: 2 }), '{"a":2,"b":1}');
  equal(canonicalJSON({ z: { y: 1, x: 2 }, a: 3 }), '{"a":3,"z":{"x":2,"y":1}}');
});

test('canonicalJSON is stable across insertion orders', () => {
  const a = { x: 1, y: 2, z: 3 };
  const b: Record<string, number> = {};
  b.z = 3; b.x = 1; b.y = 2;
  equal(canonicalJSON(a), canonicalJSON(b));
});

test('canonicalJSON handles primitives', () => {
  equal(canonicalJSON(null), 'null');
  equal(canonicalJSON(undefined), 'null');
  equal(canonicalJSON(true), 'true');
  equal(canonicalJSON(false), 'false');
  equal(canonicalJSON(42), '42');
  equal(canonicalJSON('hi'), '"hi"');
  equal(canonicalJSON(-1.5), '-1.5');
});

test('canonicalJSON handles arrays (order preserved)', () => {
  equal(canonicalJSON([3, 1, 2]), '[3,1,2]');
  equal(canonicalJSON([{ b: 1, a: 2 }]), '[{"a":2,"b":1}]');
});

test('canonicalJSON strips undefined fields', () => {
  equal(canonicalJSON({ a: 1, b: undefined }), '{"a":1}');
});

test('canonicalJSON throws on NaN / Infinity', () => {
  throws(() => canonicalJSON(NaN), /non-finite/);
  throws(() => canonicalJSON(Infinity), /non-finite/);
});

test('canonicalJSON encodes bigint as its decimal-string representation', () => {
  equal(canonicalJSON(123n), '"123"');
  equal(canonicalJSON({ amount: 10n ** 18n }), '{"amount":"1000000000000000000"}');
});

// ============================================================================
// hashEntry / sealEntry
// ============================================================================

const SAMPLE_ENTRY: AuditEntry = {
  seq: 0,
  ts: 1715_000_000_000,
  prev_hash: ZERO_HASH,
  kind: 'eth_sign_message',
  portal: 'evm:bot',
  payload: { message: 'hello' },
  decision: 'allow',
  sig: '0xdeadbeef',
};

test('hashEntry returns 64-char lowercase hex', () => {
  const h = hashEntry(SAMPLE_ENTRY);
  equal(h.length, HASH_HEX_LEN);
  ok(/^[0-9a-f]{64}$/.test(h), `not lowercase hex: ${h}`);
});

test('hashEntry is deterministic', () => {
  equal(hashEntry(SAMPLE_ENTRY), hashEntry({ ...SAMPLE_ENTRY }));
});

test('hashEntry is insensitive to top-level key insertion order', () => {
  // Build a reshuffled copy by walking entries in reverse insertion order.
  // Object.fromEntries with reversed pairs preserves a different key-iteration
  // order under the hood while keeping the same type.
  const reshuffled = Object.fromEntries(Object.entries(SAMPLE_ENTRY).reverse()) as AuditEntry;
  equal(hashEntry(SAMPLE_ENTRY), hashEntry(reshuffled));
});

test('hashEntry is insensitive to nested payload key insertion order', () => {
  const a: AuditEntry = { ...SAMPLE_ENTRY, payload: { x: 1, y: 2, z: 3 } };
  const b: AuditEntry = { ...SAMPLE_ENTRY, payload: { z: 3, x: 1, y: 2 } };
  equal(hashEntry(a), hashEntry(b));
});

test('hashEntry differs when any field changes', () => {
  const baseHash = hashEntry(SAMPLE_ENTRY);
  notEqual(hashEntry({ ...SAMPLE_ENTRY, seq: 1 }), baseHash);
  notEqual(hashEntry({ ...SAMPLE_ENTRY, ts: 999 }), baseHash);
  notEqual(hashEntry({ ...SAMPLE_ENTRY, kind: 'x' }), baseHash);
  notEqual(hashEntry({ ...SAMPLE_ENTRY, portal: 'x' }), baseHash);
  notEqual(hashEntry({ ...SAMPLE_ENTRY, decision: 'deny' }), baseHash);
  notEqual(hashEntry({ ...SAMPLE_ENTRY, payload: { message: 'goodbye' } }), baseHash);
  notEqual(hashEntry({ ...SAMPLE_ENTRY, sig: '0xcafe' }), baseHash);
  notEqual(hashEntry({ ...SAMPLE_ENTRY, prev_hash: '1'.repeat(64) }), baseHash);
});

test('sealEntry appends a hash field equal to hashEntry of the original', () => {
  const sealed = sealEntry(SAMPLE_ENTRY);
  equal(sealed.hash, hashEntry(SAMPLE_ENTRY));
  for (const k of Object.keys(SAMPLE_ENTRY) as (keyof AuditEntry)[]) {
    deepEqual(sealed[k], SAMPLE_ENTRY[k]);
  }
});

// ============================================================================
// parseLine
// ============================================================================

test('parseLine round trips a sealed entry', () => {
  const sealed = sealEntry(SAMPLE_ENTRY);
  const line = serializeEntry(sealed);
  // Strip the trailing newline (parseLine takes a single line).
  const parsed = parseLine(line.slice(0, -1));
  deepEqual(parsed, sealed);
});

test('parseLine rejects malformed JSON', () => {
  throws(() => parseLine('{not json'), AuditChainError);
});

test('parseLine rejects a non-object (array, string, number)', () => {
  throws(() => parseLine('[]'), AuditChainError);
  throws(() => parseLine('"hi"'), AuditChainError);
  throws(() => parseLine('42'), AuditChainError);
});

test('parseLine rejects missing hash field', () => {
  const line = canonicalJSON(SAMPLE_ENTRY);
  throws(() => parseLine(line), /missing or malformed hash/);
});

test('parseLine rejects wrong-length hash', () => {
  const line = canonicalJSON({ ...SAMPLE_ENTRY, hash: 'too-short' });
  throws(() => parseLine(line), /missing or malformed hash/);
});

test('parseLine rejects bad hash value (corrupted)', () => {
  const sealed = sealEntry(SAMPLE_ENTRY);
  const tampered = { ...sealed, hash: 'f'.repeat(64) };
  throws(() => parseLine(canonicalJSON(tampered)), /hash mismatch/);
});

test('parseLine rejects missing required fields', () => {
  const bad: Record<string, unknown> = { ...sealEntry(SAMPLE_ENTRY) };
  delete bad['kind'];
  throws(() => parseLine(canonicalJSON(bad)), /missing required field: kind/);
});

test('parseLine rejects negative or non-integer seq', () => {
  throws(() => parseLine(canonicalJSON(sealEntry({ ...SAMPLE_ENTRY, seq: -1 }))), /seq must be/);
  throws(() => parseLine(canonicalJSON(sealEntry({ ...SAMPLE_ENTRY, seq: 1.5 }))), /seq must be/);
});

// ============================================================================
// verifyChain — structural
// ============================================================================

function chainOf(n: number): { entries: AuditEntry[]; sealed: StoredAuditEntry[]; buf: Buffer } {
  const entries: AuditEntry[] = [];
  const sealed: StoredAuditEntry[] = [];
  let prevHash = ZERO_HASH;
  for (let i = 0; i < n; i++) {
    const e: AuditEntry = {
      seq: i,
      ts: 1715_000_000_000 + i,
      prev_hash: prevHash,
      kind: 'eth_sign_message',
      portal: 'evm:bot',
      payload: { i },
      decision: 'allow',
      sig: `0x${i.toString(16).padStart(2, '0')}`,
    };
    const s = sealEntry(e);
    entries.push(e);
    sealed.push(s);
    prevHash = s.hash;
  }
  const buf = Buffer.from(sealed.map(serializeEntry).join(''), 'utf8');
  return { entries, sealed, buf };
}

test('verifyChain on empty buffer returns empty array', () => {
  deepEqual(verifyChain(Buffer.alloc(0)), []);
  deepEqual(verifyChain(''), []);
});

test('verifyChain returns each entry in order for valid N-entry chain', () => {
  for (const n of [1, 2, 3, 10, 100]) {
    const { sealed, buf } = chainOf(n);
    const result = verifyChain(buf);
    equal(result.length, n);
    for (let i = 0; i < n; i++) deepEqual(result[i], sealed[i]);
  }
});

test('verifyChain detects torn write (no trailing newline)', () => {
  const { buf } = chainOf(3);
  // Drop the trailing newline → simulates a torn write of the last line.
  const torn = buf.subarray(0, buf.length - 1);
  throws(() => verifyChain(torn), /torn write/);
});

test('verifyChain detects torn write where last line was partially written', () => {
  const { buf } = chainOf(2);
  // Drop the last several chars (including newline) — partial last entry.
  const torn = buf.subarray(0, buf.length - 20);
  throws(() => verifyChain(torn), AuditChainError);
});

test('verifyChain detects seq skip (entry deleted from middle)', () => {
  const { sealed } = chainOf(5);
  // Remove the middle entry; everything else stays.
  const truncated = [...sealed.slice(0, 2), ...sealed.slice(3)];
  const buf = Buffer.from(truncated.map(serializeEntry).join(''), 'utf8');
  throws(() => verifyChain(buf), /seq gap|prev_hash mismatch/);
});

test('verifyChain detects swapped neighboring entries', () => {
  const { sealed } = chainOf(4);
  const swapped = [sealed[0]!, sealed[2]!, sealed[1]!, sealed[3]!];
  const buf = Buffer.from(swapped.map(serializeEntry).join(''), 'utf8');
  throws(() => verifyChain(buf), AuditChainError);
});

test('verifyChain detects an inserted fake entry', () => {
  const { sealed } = chainOf(3);
  // Build a fake entry with a self-consistent hash but wrong seq/prev_hash.
  const fake = sealEntry({
    seq: 99,
    ts: 0,
    prev_hash: ZERO_HASH,
    kind: 'fake',
    portal: 'fake',
    payload: null,
    decision: 'allow',
  });
  const tampered = [sealed[0]!, fake, sealed[1]!, sealed[2]!];
  const buf = Buffer.from(tampered.map(serializeEntry).join(''), 'utf8');
  throws(() => verifyChain(buf), AuditChainError);
});

test('verifyChain detects tampered payload (single-byte content change)', () => {
  const { sealed } = chainOf(3);
  // Re-stringify entry 1 with a different payload, KEEPING the stored hash.
  // That hash now no longer matches the (modified) content.
  const tampered = { ...sealed[1]!, payload: { i: 999 } };
  const lines = [
    serializeEntry(sealed[0]!),
    canonicalJSON(tampered) + '\n',
    serializeEntry(sealed[2]!),
  ];
  const buf = Buffer.from(lines.join(''), 'utf8');
  throws(() => verifyChain(buf), /hash mismatch/);
});

test('verifyChain detects entry with stale prev_hash (chain rebase attempt)', () => {
  const { sealed } = chainOf(3);
  // Strip the stored hash before re-sealing so the new entry is self-consistent.
  const { hash: _drop, ...auditFields } = sealed[1]!;
  void _drop;
  const evil = sealEntry({ ...auditFields, prev_hash: ZERO_HASH });
  const buf = Buffer.from(
    [serializeEntry(sealed[0]!), serializeEntry(evil), serializeEntry(sealed[2]!)].join(''),
    'utf8',
  );
  throws(() => verifyChain(buf), /prev_hash mismatch/);
});

test('verifyChain succeeds after legitimate truncation (tail removed at line boundary)', () => {
  // This is a documented limitation: chain alone cannot detect tail truncation.
  // The test asserts the limitation explicitly so future changes don't silently break it.
  const { sealed } = chainOf(5);
  const truncatedChain = sealed.slice(0, 3);
  const buf = Buffer.from(truncatedChain.map(serializeEntry).join(''), 'utf8');
  const result = verifyChain(buf);
  equal(result.length, 3);
});

// ============================================================================
// Fuzz / property tests (seeded)
// ============================================================================

function fuzzEntry(rng: () => number, seq: number, prevHash: string): AuditEntry {
  return {
    seq,
    ts: rngInt(rng, 1_700_000_000_000, 1_800_000_000_000),
    prev_hash: prevHash,
    kind: rngPick(rng, ['eth_sign_message', 'eth_sign_transaction', 'eth_sign_typed_data']),
    portal: 'evm:' + rngString(rng, 8).replace(/[^\w]/g, '_') || 'evm:bot',
    payload: { nonce: rngInt(rng, 0, 1_000_000), data: rngBytes(rng, rngInt(rng, 0, 32)).toString('hex') },
    decision: rngPick(rng, ['allow', 'deny', 'confirm_required'] as const),
    ...(rngBool(rng) ? { sig: '0x' + rngBytes(rng, 65).toString('hex') } : {}),
    ...(rngBool(rng) ? { reason: rngString(rng, 40) } : {}),
  };
}

function fuzzChain(rng: () => number, n: number): { sealed: StoredAuditEntry[]; buf: Buffer } {
  const sealed: StoredAuditEntry[] = [];
  let prevHash = ZERO_HASH;
  for (let i = 0; i < n; i++) {
    const e = fuzzEntry(rng, i, prevHash);
    const s = sealEntry(e);
    sealed.push(s);
    prevHash = s.hash;
  }
  const buf = Buffer.from(sealed.map(serializeEntry).join(''), 'utf8');
  return { sealed, buf };
}

test('fuzz: random chains always self-verify (200 iters, seed=1)', () => {
  const rng = makeRng(1);
  for (let i = 0; i < 200; i++) {
    const n = rngInt(rng, 1, 20);
    const { sealed, buf } = fuzzChain(rng, n);
    const verified = verifyChain(buf);
    equal(verified.length, n, `iter ${i}`);
    for (let k = 0; k < n; k++) equal(verified[k]!.hash, sealed[k]!.hash);
  }
});

test('fuzz: any tampering of a parsed field breaks verification (200 iters, seed=2)', () => {
  const rng = makeRng(2);
  let succeededInBreaking = 0;
  for (let i = 0; i < 200; i++) {
    const n = rngInt(rng, 2, 10);
    const { sealed } = fuzzChain(rng, n);
    const victimIdx = rngInt(rng, 0, n);
    const victim = sealed[victimIdx]!;
    // Choose a field to mutate.
    const field = rngPick(rng, ['kind', 'portal', 'decision', 'ts'] as const);
    const mutated: StoredAuditEntry = { ...victim };
    if (field === 'ts') mutated.ts = victim.ts + 1;
    else if (field === 'decision') mutated.decision = victim.decision === 'allow' ? 'deny' : 'allow';
    else (mutated[field] as string) = (mutated[field] as string) + '!';
    // Re-stringify the tampered entry but keep the original hash → hash mismatch.
    const lines = sealed.map((s, j) =>
      j === victimIdx ? canonicalJSON(mutated) + '\n' : serializeEntry(s),
    );
    const buf = Buffer.from(lines.join(''), 'utf8');
    let threw = false;
    try { verifyChain(buf); } catch { threw = true; }
    ok(threw, `tamper of ${field} on entry ${victimIdx} (n=${n}, iter=${i}) did not break verification`);
    succeededInBreaking++;
  }
  equal(succeededInBreaking, 200);
});

test('fuzz: random single-byte content flips break verification (300 iters, seed=3)', () => {
  const rng = makeRng(3);
  let attempted = 0;
  let detected = 0;
  for (let i = 0; i < 300; i++) {
    const n = rngInt(rng, 1, 5);
    const { buf } = fuzzChain(rng, n);
    const arr = Buffer.from(buf);
    const pos = rngInt(rng, 0, arr.length);
    const original = arr[pos]!;
    arr[pos] = original ^ 0xff;
    // Whether parsing remains valid JSON is data-dependent. Either it throws,
    // OR it parses to a different entry whose hash doesn't match. Both are
    // "detected". A no-op flip (same byte) would mean undetected — but XOR
    // 0xff can never produce the same byte.
    attempted++;
    try {
      verifyChain(arr);
      // Reaching here means verifyChain returned without throwing. That's
      // only acceptable if the flip happened in whitespace that doesn't
      // affect parsed entry data. In our canonical serialization there is
      // NO whitespace, so any flip must alter parsed semantics or syntax.
      // Therefore this code path is a real bug if hit.
    } catch {
      detected++;
    }
  }
  equal(detected, attempted, `expected all ${attempted} flips to be detected, only ${detected} were`);
});

test('fuzz: rebuild and verify is round-trip stable (200 iters, seed=4)', () => {
  const rng = makeRng(4);
  for (let i = 0; i < 200; i++) {
    const n = rngInt(rng, 1, 15);
    const { sealed, buf } = fuzzChain(rng, n);
    const verified = verifyChain(buf);
    // Re-serialize from verified and compare bytes.
    const reBuf = Buffer.from(verified.map(serializeEntry).join(''), 'utf8');
    ok(reBuf.equals(buf), `round trip drift at iter ${i}, n=${n}, sealed[0].hash=${sealed[0]!.hash.slice(0, 8)}`);
  }
});

// ============================================================================
// AuditWriter (filesystem)
// ============================================================================

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-audit-'));
}

test('AuditWriter writes a verifiable single entry', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    const w = new AuditWriter(path, { now: () => 1_700_000_000_000 });
    const e = w.append({
      kind: 'eth_sign_message',
      portal: 'evm:bot',
      payload: { msg: 'hi' },
      decision: 'allow',
      sig: '0xabcd',
    });
    w.close();
    equal(e.seq, 0);
    equal(e.prev_hash, ZERO_HASH);
    const buf = readFileSync(path);
    const verified = verifyChain(buf);
    equal(verified.length, 1);
    deepEqual(verified[0], e);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('AuditWriter appends multiple entries with linked hashes', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    let now = 1_700_000_000_000;
    const w = new AuditWriter(path, { now: () => ++now });
    const e0 = w.append({ kind: 'a', portal: 'p', payload: { i: 0 }, decision: 'allow' });
    const e1 = w.append({ kind: 'b', portal: 'p', payload: { i: 1 }, decision: 'deny', reason: 'policy' });
    const e2 = w.append({ kind: 'c', portal: 'p', payload: { i: 2 }, decision: 'allow', sig: '0xfeed' });
    w.close();
    equal(e0.seq, 0); equal(e1.seq, 1); equal(e2.seq, 2);
    equal(e1.prev_hash, e0.hash);
    equal(e2.prev_hash, e1.hash);
    const verified = verifyChain(readFileSync(path));
    equal(verified.length, 3);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('AuditWriter resumes from existing file (chain continues across instances)', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    let now = 1_700_000_000_000;
    const a = new AuditWriter(path, { now: () => ++now });
    a.append({ kind: 'first', portal: 'p', payload: {}, decision: 'allow' });
    a.append({ kind: 'second', portal: 'p', payload: {}, decision: 'allow' });
    a.close();
    // New instance picks up where the previous left off.
    const b = new AuditWriter(path, { now: () => ++now });
    equal(b.head.nextSeq, 2);
    const third = b.append({ kind: 'third', portal: 'p', payload: {}, decision: 'allow' });
    b.close();
    equal(third.seq, 2);
    const verified = verifyChain(readFileSync(path));
    equal(verified.length, 3);
    equal(verified[2]!.kind, 'third');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('AuditWriter constructor throws on a corrupted existing file', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    writeFileSync(path, '{"not": "a valid entry"}\n', { mode: 0o600 });
    throws(() => new AuditWriter(path), AuditChainError);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('AuditWriter throws on append after close', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    const w = new AuditWriter(path);
    w.close();
    throws(() => w.append({ kind: 'x', portal: 'p', payload: {}, decision: 'allow' }), /closed/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('AuditWriter on missing file initializes the genesis head', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    const w = new AuditWriter(path);
    equal(w.head.nextSeq, 0);
    equal(w.head.prevHash, ZERO_HASH);
    w.close();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('readHead on a torn-write file throws AuditChainError', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    // Write a valid chain then truncate a few bytes.
    const w = new AuditWriter(path, { now: () => 1 });
    w.append({ kind: 'a', portal: 'p', payload: {}, decision: 'allow' });
    w.append({ kind: 'b', portal: 'p', payload: {}, decision: 'allow' });
    w.close();
    const buf = readFileSync(path);
    writeFileSync(path, buf.subarray(0, buf.length - 5));
    throws(() => readHead(path), AuditChainError);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ============================================================================
// Filesystem-level fuzz: random append sequences + restart cycles verify.
// ============================================================================

test('fuzz: many append + restart cycles produce a verifiable chain (50 iters, seed=5)', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    const rng = makeRng(5);
    let ts = 1_700_000_000_000;
    let totalAppended = 0;
    for (let iter = 0; iter < 50; iter++) {
      const w = new AuditWriter(path, { now: () => ++ts });
      const batchSize = rngInt(rng, 0, 5);
      for (let j = 0; j < batchSize; j++) {
        w.append({
          kind: rngPick(rng, ['eth_sign_message', 'eth_sign_transaction']),
          portal: 'evm:bot',
          payload: { i: totalAppended + j, blob: rngBytes(rng, rngInt(rng, 0, 8)).toString('hex') },
          decision: rngPick(rng, ['allow', 'deny', 'confirm_required'] as const),
          ...(rngBool(rng) ? { sig: '0x' + rngBytes(rng, 65).toString('hex') } : {}),
        });
      }
      w.close();
      totalAppended += batchSize;
      // Verify after every restart cycle.
      const verified = verifyChain(readFileSync(path));
      equal(verified.length, totalAppended, `iter ${iter}`);
    }
  } finally {
    rmSync(dir, { recursive: true });
  }
});
