import { closeSync, fsyncSync, openSync, readFileSync, statSync } from 'node:fs';
import { keccak256 } from '../eth/keccak.js';
import { type AcquireLockOptions, acquireLockSync, writeAllSync } from './lock.js';

export type AuditDecision = 'allow' | 'deny' | 'confirm_required';

export interface AuditEntry {
  seq: number;
  ts: number; // ms since epoch
  prev_hash: string; // 64-char hex (32 bytes)
  kind: string; // method name, e.g. "eth_sign_transaction"
  portal: string; // handle, e.g. "evm:bot"
  payload: unknown; // method-specific structured data
  decision: AuditDecision;
  reason?: string; // populated for deny / confirm_required
  sig?: string; // hex-encoded signature for an allowed sign decision
}

export interface StoredAuditEntry extends AuditEntry {
  hash: string;
}

export const ZERO_HASH = '0'.repeat(64);
export const HASH_HEX_LEN = 64;

export class AuditChainError extends Error {
  readonly atSeq: number | undefined;
  constructor(msg: string, atSeq?: number) {
    super(`audit chain error${atSeq !== undefined ? ` at seq=${atSeq}` : ''}: ${msg}`);
    this.name = 'AuditChainError';
    this.atSeq = atSeq;
  }
}

/**
 * Canonical JSON serialization: keys sorted lexicographically, recursive.
 * This is what we hash, so it must be deterministic across engine
 * versions and across re-serializations.
 */
export function canonicalJSON(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonicalJSON: non-finite numbers are not representable');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'bigint') {
    // Store as a decimal string; up to caller to know the type.
    return JSON.stringify(value.toString());
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJSON).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
  }
  throw new Error(`canonicalJSON: unsupported value type ${typeof value}`);
}

/**
 * Compute the keccak256 hash of an entry (without the `hash` field).
 * Returns lowercase hex.
 */
export function hashEntry(entry: AuditEntry): string {
  return keccak256(Buffer.from(canonicalJSON(entry), 'utf8')).toString('hex');
}

/**
 * Stamp an entry with its hash.
 */
export function sealEntry(entry: AuditEntry): StoredAuditEntry {
  return { ...entry, hash: hashEntry(entry) };
}

/**
 * Serialize a stored entry to a single JSON line (newline-terminated).
 */
export function serializeEntry(entry: StoredAuditEntry): string {
  return canonicalJSON(entry) + '\n';
}

/**
 * Parse a single line and verify its self-hash. Does NOT check chain linkage.
 */
export function parseLine(line: string): StoredAuditEntry {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch (err) {
    throw new AuditChainError(`malformed JSON: ${(err as Error).message}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new AuditChainError('line is not a JSON object');
  }
  const obj = parsed as Record<string, unknown>;
  const hash = obj['hash'];
  if (typeof hash !== 'string' || hash.length !== HASH_HEX_LEN) {
    throw new AuditChainError('missing or malformed hash field');
  }
  // Validate required top-level fields exist and have the right shape.
  for (const required of ['seq', 'ts', 'prev_hash', 'kind', 'portal', 'decision'] as const) {
    if (!(required in obj)) {
      throw new AuditChainError(`missing required field: ${required}`);
    }
  }
  if (typeof obj['seq'] !== 'number' || !Number.isInteger(obj['seq']) || obj['seq'] < 0) {
    throw new AuditChainError('seq must be a non-negative integer');
  }
  if (typeof obj['prev_hash'] !== 'string' || obj['prev_hash'].length !== HASH_HEX_LEN) {
    throw new AuditChainError('prev_hash must be 64-char hex');
  }
  // Re-hash without the hash field and compare.
  const rest: AuditEntry = {
    seq: obj['seq'] as number,
    ts: obj['ts'] as number,
    prev_hash: obj['prev_hash'] as string,
    kind: obj['kind'] as string,
    portal: obj['portal'] as string,
    payload: obj['payload'],
    decision: obj['decision'] as AuditDecision,
    ...(obj['reason'] !== undefined ? { reason: obj['reason'] as string } : {}),
    ...(obj['sig'] !== undefined ? { sig: obj['sig'] as string } : {}),
  };
  const expected = hashEntry(rest);
  if (hash !== expected) {
    throw new AuditChainError(`hash mismatch: stored=${hash} expected=${expected}`, rest.seq);
  }
  return { ...rest, hash };
}

/**
 * Verify a buffer's worth of JSONL audit entries.
 * - Empty buffer → empty chain.
 * - Each entry must self-hash correctly.
 * - Each entry's seq must be expected (0, 1, 2, ...).
 * - Each entry's prev_hash must match the previous entry's hash.
 * - A trailing non-empty fragment (no terminating newline) is a torn write.
 *
 * Returns the entries in order. Throws AuditChainError on any failure.
 */
export function verifyChain(buf: Buffer | string): StoredAuditEntry[] {
  const text = typeof buf === 'string' ? buf : buf.toString('utf8');
  if (text === '') return [];
  const lines = text.split('\n');
  // Well-formed JSONL ends with a newline, so split yields a trailing empty string.
  const last = lines[lines.length - 1];
  if (last !== '') {
    throw new AuditChainError(
      `torn write: trailing fragment of ${last!.length} bytes without newline`,
    );
  }
  lines.pop();

  const entries: StoredAuditEntry[] = [];
  let expectedPrevHash = ZERO_HASH;
  let expectedSeq = 0;
  for (const line of lines) {
    const entry = parseLine(line);
    if (entry.seq !== expectedSeq) {
      throw new AuditChainError(`seq gap: expected ${expectedSeq}, got ${entry.seq}`, entry.seq);
    }
    if (entry.prev_hash !== expectedPrevHash) {
      throw new AuditChainError(
        `prev_hash mismatch: expected ${expectedPrevHash}, got ${entry.prev_hash}`,
        entry.seq,
      );
    }
    entries.push(entry);
    expectedPrevHash = entry.hash;
    expectedSeq++;
  }
  return entries;
}

/**
 * The head state of an audit chain: enough to append the next entry.
 */
export interface ChainHead {
  nextSeq: number;
  prevHash: string;
}

/**
 * Read the chain head plus the byte length it was derived from. The size lets
 * a writer cheaply detect (via stat) that another process appended since the
 * head was read. Missing file → genesis head at size 0.
 */
function readHeadAndSize(path: string): { head: ChainHead; size: number } {
  let buf: Buffer;
  try {
    buf = readFileSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { head: { nextSeq: 0, prevHash: ZERO_HASH }, size: 0 };
    }
    throw err;
  }
  const entries = verifyChain(buf);
  if (entries.length === 0) {
    return { head: { nextSeq: 0, prevHash: ZERO_HASH }, size: buf.length };
  }
  const last = entries[entries.length - 1]!;
  return { head: { nextSeq: last.seq + 1, prevHash: last.hash }, size: buf.length };
}

/**
 * Read the chain head from an existing audit file. Verifies the whole chain
 * during read. If the file does not exist or is empty, returns the genesis head.
 */
export function readHead(path: string): ChainHead {
  return readHeadAndSize(path).head;
}

/**
 * Append-only audit writer with fsync after every write.
 *
 * Typical use:
 *   const w = new AuditWriter('/path/to/audit.log');
 *   w.append({ kind: 'eth_sign_message', portal: 'evm:bot', payload, decision: 'allow', sig });
 *   w.close();
 *
 * The seq and prev_hash fields are managed by the writer; callers supply
 * everything else.
 *
 * Multiple processes (one sigil-mcp per Claude session) share one audit file,
 * so every append serializes through a sidecar `<path>.lock`. The in-memory
 * head is only a cache: under the lock, the writer stats the file and, if the
 * on-disk tail moved since the head was last read, re-reads (and re-verifies)
 * the chain before computing the next entry. Without this, concurrent writers
 * each extend their own stale tail and the interleaved lines fail startup
 * verification with seq gaps and broken prev_hash links.
 */
export class AuditWriter {
  readonly path: string;
  readonly lockPath: string;
  #head: ChainHead;
  #size: number;
  #closed = false;
  // Allow tests to inject a fixed clock. Defaults to Date.now.
  #now: () => number;
  #lockOpts: AcquireLockOptions;

  constructor(path: string, opts: { now?: () => number; lock?: AcquireLockOptions } = {}) {
    this.path = path;
    this.lockPath = `${path}.lock`;
    this.#now = opts.now ?? (() => Date.now());
    this.#lockOpts = opts.lock ?? {};
    // Take the lock even for the initial read so startup verification never
    // observes a mid-append view of the file.
    const release = acquireLockSync(this.lockPath, this.#lockOpts);
    try {
      const { head, size } = readHeadAndSize(path);
      this.#head = head;
      this.#size = size;
    } finally {
      release();
    }
  }

  get head(): ChainHead {
    return { ...this.#head };
  }

  append(input: {
    kind: string;
    portal: string;
    payload: unknown;
    decision: AuditDecision;
    reason?: string;
    sig?: string;
  }): StoredAuditEntry {
    if (this.#closed) throw new Error('AuditWriter is closed');
    const release = acquireLockSync(this.lockPath, this.#lockOpts);
    try {
      // Another process may have appended since we last read the tail. The
      // cached head is only trusted when the on-disk size still matches;
      // otherwise re-read (and re-verify) the chain from disk.
      let diskSize = 0;
      try {
        diskSize = statSync(this.path).size;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      }
      if (diskSize !== this.#size) {
        const { head, size } = readHeadAndSize(this.path);
        this.#head = head;
        this.#size = size;
      }

      const entry: AuditEntry = {
        seq: this.#head.nextSeq,
        ts: this.#now(),
        prev_hash: this.#head.prevHash,
        kind: input.kind,
        portal: input.portal,
        payload: input.payload,
        decision: input.decision,
        ...(input.reason !== undefined ? { reason: input.reason } : {}),
        ...(input.sig !== undefined ? { sig: input.sig } : {}),
      };
      const stored = sealEntry(entry);
      const line = serializeEntry(stored);

      const fd = openSync(this.path, 'a', 0o600);
      try {
        writeAllSync(fd, line);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }

      this.#head = { nextSeq: stored.seq + 1, prevHash: stored.hash };
      this.#size += Buffer.byteLength(line, 'utf8');
      return stored;
    } finally {
      release();
    }
  }

  close(): void {
    this.#closed = true;
  }
}
