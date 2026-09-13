import {
  closeSync,
  fsyncSync,
  linkSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
  unlinkSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { keccak256 } from '../eth/keccak.js';
import { type AcquireLockOptions, withFileLock, writeAllSync } from '../fs/lock.js';

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
export interface AuditWriterOpts {
  /** Clock override for tests. Defaults to Date.now. */
  now?: () => number;
  lock?: AcquireLockOptions;
  /**
   * What to do when the file on disk fails chain verification:
   *   - 'throw' (default): raise AuditChainError; the caller decides.
   *   - 'quarantine': move the file to `<path>.corrupt-<timestamp>` (never
   *     overwriting an existing file), report via `warn`, and start a fresh
   *     chain. Nothing is deleted. sigil-mcp uses this so one damaged log
   *     can't lock the user out of signing until they hand-edit it.
   */
  onCorrupt?: 'throw' | 'quarantine';
  warn?: (message: string) => void;
}

export class AuditWriter {
  readonly path: string;
  readonly lockPath: string;
  #head: ChainHead;
  #size: number;
  #closed = false;
  #now: () => number;
  #lockOpts: AcquireLockOptions;
  #onCorrupt: 'throw' | 'quarantine';
  #warn: (message: string) => void;

  constructor(path: string, opts: AuditWriterOpts = {}) {
    this.path = path;
    this.lockPath = `${path}.lock`;
    this.#now = opts.now ?? (() => Date.now());
    this.#lockOpts = opts.lock ?? {};
    this.#onCorrupt = opts.onCorrupt ?? 'throw';
    this.#warn = opts.warn ?? ((m) => process.stderr.write(m + '\n'));
    this.#head = { nextSeq: 0, prevHash: ZERO_HASH };
    this.#size = -1;
    // Take the lock even for the initial read so startup verification never
    // observes a mid-append view of the file.
    withFileLock(this.path, () => this.#syncHead(), this.#lockOpts);
  }

  /**
   * Bring the cached head in line with the file on disk. Must be called
   * under the lock. Two cheap checks decide whether the cache is current:
   * the byte length, and the hash of the file's last line — a replacement
   * chain of identical length (another process quarantined a torn log and
   * started over, and its genesis entry happens to serialize to the same
   * size) is caught by the second. Only when either differs is the whole
   * chain re-read and re-verified.
   */
  #syncHead(): void {
    let diskSize = 0;
    try {
      diskSize = statSync(this.path).size;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    if (
      diskSize === this.#size &&
      (diskSize === 0 || lastLineHash(this.path, diskSize) === this.#head.prevHash)
    ) {
      return;
    }
    try {
      const { head, size } = readHeadAndSize(this.path);
      this.#head = head;
      this.#size = size;
    } catch (err) {
      if (!(err instanceof AuditChainError) || this.#onCorrupt !== 'quarantine') throw err;
      const quarantined = quarantine(this.path, this.#now());
      // Our own state is reset before control passes to the warn callback:
      // if it throws, this writer already describes the fresh chain.
      this.#head = { nextSeq: 0, prevHash: ZERO_HASH };
      this.#size = 0;
      this.#warn(
        `sigil: audit log ${this.path} failed verification (${err.message}); ` +
          `moved it to ${quarantined} and started a fresh chain`,
      );
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
    return withFileLock(
      this.path,
      () => {
        // Another process may have appended since we last read the tail. The
        // cached head is only trusted when the on-disk size still matches;
        // otherwise re-read (and re-verify) the chain from disk.
        this.#syncHead();

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

        // Only now — after the bytes are durably on disk — is the cache advanced.
        this.#head = { nextSeq: stored.seq + 1, prevHash: stored.hash };
        this.#size += Buffer.byteLength(line, 'utf8');
        return stored;
      },
      this.#lockOpts,
    );
  }

  close(): void {
    this.#closed = true;
  }
}

/**
 * Move a failed log aside as `<path>.corrupt-<iso timestamp>[-n]` without
 * ever replacing an existing file, and without a crash window in which the
 * evidence is on neither name. rename(2) silently overwrites its target, so
 * publication goes through link(2), which fails with EEXIST if the name is
 * taken. The new directory entry is then fsynced (the file's data already
 * was, by the writer that produced it) before the original name is
 * unlinked, and the directory is synced again afterwards. A power cut at
 * any point leaves the bytes reachable under at least one name; a plain
 * process crash between link and unlink leaves both, and the next writer
 * simply quarantines the original again under a fresh suffix.
 */
function quarantine(path: string, nowMs: number): string {
  const base = `${path}.corrupt-${new Date(nowMs).toISOString().replace(/[:.]/g, '-')}`;
  for (let i = 0; ; i++) {
    const candidate = i === 0 ? base : `${base}-${i}`;
    try {
      linkSync(path, candidate);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EEXIST') continue;
      throw err;
    }
    // Every step before the unlink may fail; if one does, the original is
    // still in place and the error propagates (a half-published quarantine
    // must not report success). The linked name, if it exists, is a
    // harmless extra copy the next open re-quarantines under a suffix.
    _auditTestHooks.quarantineStep?.('fsync-evidence');
    fsyncFile(candidate);
    _auditTestHooks.quarantineStep?.('fsync-dir');
    fsyncDir(dirname(path));
    _auditTestHooks.quarantineStep?.('unlink');
    unlinkSync(path);
    fsyncDir(dirname(path));
    return candidate;
  }
}

function fsyncFile(path: string): void {
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Directory entries need their own fsync to be durable (fsync(2)). A
 * failure here is a durability failure and propagates; the caller must not
 * remove the original name on the strength of an unconfirmed publication.
 */
function fsyncDir(dir: string): void {
  const fd = openSync(dir, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Test-only seams. `quarantineStep` is invoked before each step of
 * quarantine publication and may throw to simulate that step failing;
 * `tailScanMax` overrides the scan cap so the fallback path can be tested
 * without writing tens of megabytes. Never set by production code.
 */
export const _auditTestHooks: {
  quarantineStep?: (step: 'fsync-evidence' | 'fsync-dir' | 'unlink') => void;
  tailScanMax?: number;
} = {};

/**
 * Hash of the last newline-terminated line, read from the tail in fixed
 * chunks so a large log isn't re-read on every append. Each chunk is
 * scanned once as it arrives and the pieces are joined once, so a huge
 * final line costs O(line), not O(line²/chunk) — this runs under the
 * audit lock, and a caller-controlled payload must not be able to stall
 * every other session. Lines longer than MAX_TAIL_SCAN fall back to a
 * full re-verify — which bounds the *tail scan*, not the lock hold: the
 * full re-verify is O(file) like every resync (see readHeadAndSize). Returns null for a file that doesn't end in a newline
 * (torn) or whose last line doesn't parse — either way the caller falls
 * through to readHeadAndSize.
 */
const TAIL_CHUNK = 64 * 1024;
const MAX_TAIL_SCAN = 64 * 1024 * 1024;
function lastLineHash(path: string, size: number): string | null {
  if (size === 0) return null;
  const fd = openSync(path, 'r');
  try {
    const tail = Buffer.alloc(1);
    readSync(fd, tail, 0, 1, size - 1);
    if (tail[0] !== 0x0a) return null;
    // Pieces of the last line, in reverse file order, excluding the final
    // newline. `lineEnd` is the offset of that newline.
    const lineEnd = size - 1;
    const pieces: Buffer[] = [];
    let pos = lineEnd;
    let scanned = 0;
    for (;;) {
      if (pos === 0) break;
      const start = Math.max(0, pos - TAIL_CHUNK);
      const buf = Buffer.alloc(pos - start);
      readSync(fd, buf, 0, buf.length, start);
      scanned += buf.length;
      const nl = buf.lastIndexOf(0x0a);
      if (nl !== -1) {
        pieces.push(buf.subarray(nl + 1));
        break;
      }
      pieces.push(buf);
      pos = start;
      if (scanned > (_auditTestHooks.tailScanMax ?? MAX_TAIL_SCAN)) return null;
    }
    const line = Buffer.concat(pieces.reverse()).toString('utf8');
    try {
      return parseLine(line).hash;
    } catch {
      return null;
    }
  } finally {
    closeSync(fd);
  }
}
