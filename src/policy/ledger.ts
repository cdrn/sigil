import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeSync,
} from 'node:fs';
import { join } from 'node:path';
import { withFileLock } from '../fs/index.js';
import { checkWindowCaps, DAY_MS, type SpendAsset, type WindowCap } from './window.js';

/**
 * What the sign path needs from the spend ledger. `reserve` is the only
 * mutating call: it checks every cap against what is already recorded and,
 * only if all hold, records the new amount — atomically with respect to
 * other sigil-mcp processes, so two windows can't both squeeze under a cap
 * in the same instant.
 */
export interface SpendLedger {
  /** Total recorded for (handle, asset) with ts in (now - windowMs, now]. */
  spent(handle: string, asset: SpendAsset, windowMs: number, now: number): bigint;
  /**
   * Check-then-record. Returns null on success (amount recorded), or the
   * deny reason (nothing recorded). A zero amount is a no-op success.
   */
  reserve(
    handle: string,
    asset: SpendAsset,
    amount: bigint,
    caps: readonly WindowCap[],
    now: number,
  ): string | null;
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
    if (e.asset === asset && e.ts > floor && e.ts <= now) total += e.amount;
  }
  return total;
}

/** In-memory ledger for tests and for callers that don't persist. */
export class MemorySpendLedger implements SpendLedger {
  readonly #entries = new Map<string, LedgerEntry[]>();

  #for(handle: string): LedgerEntry[] {
    let list = this.#entries.get(handle);
    if (!list) {
      list = [];
      this.#entries.set(handle, list);
    }
    return list;
  }

  spent(handle: string, asset: SpendAsset, windowMs: number, now: number): bigint {
    return sumWindow(this.#for(handle), asset, windowMs, now);
  }

  reserve(
    handle: string,
    asset: SpendAsset,
    amount: bigint,
    caps: readonly WindowCap[],
    now: number,
  ): string | null {
    const list = this.#for(handle);
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
 * Every read and write runs under the cross-process file lock, and each
 * `reserve` re-reads the file inside the lock before deciding, so the
 * decision is always made against the union of every window's spends.
 *
 * Entries older than the longest window sigil supports (24h) can never
 * influence a decision again; when more than COMPACT_AFTER of them have
 * piled up the file is rewritten (tmp + rename, under the same lock) with
 * only the live tail. Rolling-window caps are a rate limit, not an audit
 * trail — the hash-chained audit log is the record.
 *
 * The file is not hash-chained. An attacker who can edit it can also edit
 * the policy file next to it, so it earns no extra protection; it lives in
 * ~/.sigil (0700) like everything else.
 */
export class FileSpendLedger implements SpendLedger {
  static readonly COMPACT_AFTER = 256;
  readonly #dir: string;

  constructor(stateDir: string) {
    this.#dir = stateDir;
  }

  pathFor(handle: string): string {
    return join(this.#dir, `${handle}.ledger`);
  }

  spent(handle: string, asset: SpendAsset, windowMs: number, now: number): bigint {
    const path = this.pathFor(handle);
    return withFileLock(path, () => sumWindow(readEntries(path), asset, windowMs, now));
  }

  reserve(
    handle: string,
    asset: SpendAsset,
    amount: bigint,
    caps: readonly WindowCap[],
    now: number,
  ): string | null {
    mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
    const path = this.pathFor(handle);
    return withFileLock(path, () => {
      const entries = readEntries(path);
      const reason = checkWindowCaps(caps, amount, (w) => sumWindow(entries, asset, w, now), asset);
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
          writeSync(fd, live.map(serialize).join(''));
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
        renameSync(tmp, path);
      } else {
        const fd = openSync(path, 'a', 0o600);
        try {
          writeSync(fd, serialize(entry));
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
      }
      return null;
    });
  }
}

function serialize(e: LedgerEntry): string {
  return JSON.stringify({ ts: e.ts, asset: e.asset, amount: e.amount.toString() }) + '\n';
}

/**
 * Parse the ledger, skipping anything unreadable. A torn trailing line from
 * a crashed writer, or a hand-edited junk line, must not turn into a
 * permanent inability to sign; skipping it is the conservative direction
 * only in the sense that a lost entry loosens the cap by one spend, which
 * the audit log still records. Malformed files are logged nowhere — the
 * ledger is best-effort state, not evidence.
 */
function readEntries(path: string): LedgerEntry[] {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
  const out: LedgerEntry[] = [];
  for (const line of text.split('\n')) {
    if (line === '') continue;
    let obj: unknown;
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof obj !== 'object' || obj === null) continue;
    const r = obj as Record<string, unknown>;
    const ts = r['ts'];
    const asset = r['asset'];
    const amount = r['amount'];
    if (typeof ts !== 'number' || !Number.isFinite(ts)) continue;
    if (asset !== 'wei' && asset !== 'lamports') continue;
    if (typeof amount !== 'string' || !/^[0-9]+$/.test(amount)) continue;
    out.push({ ts, asset, amount: BigInt(amount) });
  }
  return out;
}
