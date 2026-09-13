import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { withFileLock, writeAllSync } from '../fs/index.js';
import { checkWindowCaps, DAY_MS, type SpendAsset, type WindowCap } from './window.js';

/**
 * What the sign path needs from the spend ledger. `reserve` is the only
 * mutating call: it checks every cap against what is already recorded and,
 * only if all hold, records the new amount — atomically with respect to
 * other sigil-mcp processes, so two windows can't both squeeze under a cap
 * in the same instant.
 *
 * The ledger owns the clock. Time is sampled *inside* the critical section
 * so a process that read the clock, got descheduled, and then took the lock
 * cannot judge a competitor's later spend as "in the future" and ignore it.
 * Entries dated after now (another process's later sample, or a clock that
 * stepped back) are always counted: a spend that has happened has happened.
 */
export interface SpendLedger {
  /** Total recorded for (handle, asset) with ts > now - windowMs, including any ts > now. */
  spent(handle: string, asset: SpendAsset, windowMs: number): bigint;
  /**
   * Check-then-record. Returns null on success (amount recorded), or the
   * deny reason (nothing recorded). A zero amount is a no-op success.
   */
  reserve(
    handle: string,
    asset: SpendAsset,
    amount: bigint,
    caps: readonly WindowCap[],
  ): string | null;
}

export class SpendLedgerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SpendLedgerError';
  }
}

/** A negative spend is a caller bug, never a credit: refuse without touching the file. */
const NEGATIVE_REASON = 'denied — negative amount is not a valid spend';

export interface SpendLedgerOpts {
  /** Clock override for tests. Defaults to Date.now. */
  now?: () => number;
}

interface LedgerEntry {
  ts: number;
  asset: SpendAsset;
  amount: bigint;
}

function sumWindow(
  entries: readonly LedgerEntry[],
  asset: SpendAsset,
  windowMs: number,
  now: number,
): bigint {
  const floor = now - windowMs;
  let total = 0n;
  for (const e of entries) {
    if (e.asset === asset && e.ts > floor) total += e.amount;
  }
  return total;
}

/** In-memory ledger for tests and for callers that don't persist. */
export class MemorySpendLedger implements SpendLedger {
  readonly #entries = new Map<string, LedgerEntry[]>();
  readonly #now: () => number;

  constructor(opts: SpendLedgerOpts = {}) {
    this.#now = opts.now ?? (() => Date.now());
  }

  #for(handle: string): LedgerEntry[] {
    let list = this.#entries.get(handle);
    if (!list) {
      list = [];
      this.#entries.set(handle, list);
    }
    return list;
  }

  spent(handle: string, asset: SpendAsset, windowMs: number): bigint {
    return sumWindow(this.#for(handle), asset, windowMs, this.#now());
  }

  reserve(
    handle: string,
    asset: SpendAsset,
    amount: bigint,
    caps: readonly WindowCap[],
  ): string | null {
    if (amount < 0n) return NEGATIVE_REASON;
    const list = this.#for(handle);
    const now = this.#now();
    const reason = checkWindowCaps(caps, amount, (w) => sumWindow(list, asset, w, now), asset);
    if (reason !== null) return reason;
    if (amount > 0n) list.push({ ts: now, asset, amount });
    return null;
  }
}

/**
 * File-backed ledger: one append-only JSONL file per portal at
 * `<stateDir>/<handle>.ledger`, lines of `{"ts":…,"asset":"wei","amount":"…"}`.
 *
 * Every read and write runs under the cross-process file lock, the clock is
 * sampled inside it, and each `reserve` re-reads the file before deciding,
 * so the decision is always made against the union of every window's
 * spends.
 *
 * Integrity is fail-closed: a line that does not parse makes every reserve
 * for that portal deny with a message naming the file, until a human fixes
 * or removes it. Skipping bad lines would silently loosen the cap, which is
 * the one thing a rate limit must not do. A crash can leave a torn final
 * line (writes are complete and fsynced, so only power loss does this); the
 * next append starts on a fresh line so the torn fragment stays isolated —
 * and still trips the check, on purpose.
 *
 * Entries older than the longest window sigil supports (24h) can never
 * influence a decision again; when more than COMPACT_AFTER of them have
 * piled up the file is rewritten (tmp + fsync + rename + directory fsync,
 * under the same lock) with only the live tail. Entries dated in the future
 * are always kept.
 *
 * Threat model: an attacker who can delete or rewrite this file can also
 * rewrite the policy file beside it and remove the cap outright, so the
 * ledger earns no extra protection beyond its 0600 mode inside the 0700
 * sigil home; a missing file is an empty ledger. What it does defend
 * against is the prompt-injected *agent*, which never touches the
 * filesystem directly. The hash-chained audit log is the record.
 */
export class FileSpendLedger implements SpendLedger {
  static readonly COMPACT_AFTER = 256;
  readonly #dir: string;
  readonly #now: () => number;

  constructor(stateDir: string, opts: SpendLedgerOpts = {}) {
    this.#dir = stateDir;
    this.#now = opts.now ?? (() => Date.now());
  }

  pathFor(handle: string): string {
    return join(this.#dir, `${handle}.ledger`);
  }

  /**
   * Create the state dir and make its directory entry durable. Not cached:
   * a sync that failed must not be remembered as done, and a reservation
   * from another daemon must not mistake the directory's existence for
   * established durability. One mkdir + one fsync per reserve is cheap.
   */
  #ensureDir(): void {
    mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
    fsyncDirOrFail(dirname(this.#dir));
  }

  spent(handle: string, asset: SpendAsset, windowMs: number): bigint {
    const path = this.pathFor(handle);
    return ledgerIo(path, () => {
      mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
      return withFileLock(path, () =>
        sumWindow(readEntries(path).entries, asset, windowMs, this.#now()),
      );
    });
  }

  reserve(
    handle: string,
    asset: SpendAsset,
    amount: bigint,
    caps: readonly WindowCap[],
  ): string | null {
    if (amount < 0n) return NEGATIVE_REASON;
    const path = this.pathFor(handle);
    return ledgerIo(path, () => {
      this.#ensureDir();
      return withFileLock(path, () => {
        const { entries, endsWithNewline, size } = readEntries(path);
        const now = this.#now();
        const reason = checkWindowCaps(
          caps,
          amount,
          (w) => sumWindow(entries, asset, w, now),
          asset,
        );
        if (reason !== null) return reason;
        if (amount === 0n) return null;
        const entry: LedgerEntry = { ts: now, asset, amount };
        const stale = entries.filter((e) => e.ts <= now - DAY_MS).length;
        if (stale > FileSpendLedger.COMPACT_AFTER) {
          const live = entries.filter((e) => e.ts > now - DAY_MS);
          live.push(entry);
          const tmp = `${path}.tmp`;
          const fd = openSync(tmp, 'w', 0o600);
          try {
            writeAllSync(fd, live.map(serialize).join(''));
            fsyncSync(fd);
          } finally {
            closeSync(fd);
          }
          renameSync(tmp, path);
          fsyncDirOrFail(dirname(path));
        } else {
          const fd = openSync(path, 'a', 0o600);
          try {
            // Never merge with a torn fragment: start on a fresh line.
            writeAllSync(fd, (size > 0 && !endsWithNewline ? '\n' : '') + serialize(entry));
            fsyncSync(fd);
          } finally {
            closeSync(fd);
          }
          // The directory entry needs its own fsync, or a power cut right after
          // a signature can lose a brand-new ledger and hand back a fresh
          // allowance on reboot. Done on every append rather than only the
          // first: if a previous attempt's sync failed, the file's mere
          // existence proves nothing about durability.
          fsyncDirOrFail(dirname(path));
        }
        return null;
      });
    });
  }
}

/**
 * Run a ledger operation, turning any I/O failure — read, open, write,
 * fsync, rename, lock — into a SpendLedgerError naming the file, so the
 * sign path records an audited deny rather than surfacing a bare
 * filesystem error (#91). Errors that are already SpendLedgerError (parse
 * failures, durability failures) pass through unchanged. Signing stops
 * either way; this only makes the audit log say why.
 */
function ledgerIo<T>(path: string, fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof SpendLedgerError) throw err;
    const e = err as NodeJS.ErrnoException;
    throw new SpendLedgerError(
      `spend ledger ${path}: I/O failure (${e.code ?? e.name}: ${e.message}) — refusing to sign`,
    );
  }
}

/**
 * Test-only seam: replaces the directory fsync so a test can make it fail.
 * Never set by production code.
 */
export const _ledgerTestHooks: { fsyncDir?: (dir: string) => void } = {};

/**
 * fsync a directory, converting any failure into a SpendLedgerError. The
 * spend may already be on disk at this point; refusing to sign then errs
 * on the side of over-counting, never under-counting. Nothing is swallowed:
 * a filesystem that can't confirm durability can't back a rate limit.
 */
function fsyncDirOrFail(dir: string): void {
  try {
    if (_ledgerTestHooks.fsyncDir) {
      _ledgerTestHooks.fsyncDir(dir);
      return;
    }
    const fd = openSync(dir, 'r');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch (err) {
    throw new SpendLedgerError(
      `spend ledger: could not make ${dir} durable (${(err as Error).message}) — refusing to sign`,
    );
  }
}

function serialize(e: LedgerEntry): string {
  return JSON.stringify({ ts: e.ts, asset: e.asset, amount: e.amount.toString() }) + '\n';
}

/**
 * Parse the ledger. Any line that does not parse — including a torn final
 * line — throws SpendLedgerError naming the file: the cap cannot be
 * evaluated against unknown history, so every reserve denies until a human
 * repairs or removes the file. A missing file is an empty ledger.
 */
function readEntries(path: string): {
  entries: LedgerEntry[];
  endsWithNewline: boolean;
  size: number;
} {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { entries: [], endsWithNewline: true, size: 0 };
    }
    throw err;
  }
  const out: LedgerEntry[] = [];
  const lines = text.split('\n');
  const endsWithNewline = text === '' || text.endsWith('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line === '') {
      // Blank lines (the split's trailing empty string, or a separator we
      // wrote to isolate a torn fragment) carry no information.
      continue;
    }
    const e = parseEntry(line);
    if (!e) {
      throw new SpendLedgerError(
        `spend ledger ${path} has an unreadable line ${i + 1} — refusing to sign against ` +
          `unknown history; inspect and repair or remove the file (this resets the allowance)`,
      );
    }
    out.push(e);
  }
  return { entries: out, endsWithNewline, size: Buffer.byteLength(text, 'utf8') };
}

function parseEntry(line: string): LedgerEntry | null {
  let obj: unknown;
  try {
    obj = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof obj !== 'object' || obj === null) return null;
  const r = obj as Record<string, unknown>;
  const ts = r['ts'];
  const asset = r['asset'];
  const amount = r['amount'];
  if (typeof ts !== 'number' || !Number.isFinite(ts)) return null;
  if (asset !== 'wei' && asset !== 'lamports') return null;
  if (typeof amount !== 'string' || !/^[0-9]+$/.test(amount)) return null;
  return { ts, asset, amount: BigInt(amount) };
}
