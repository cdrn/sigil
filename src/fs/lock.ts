import { closeSync, mkdirSync, openSync, readdirSync, unlinkSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

/**
 * Cross-process mutex for the files several `sigil-mcp` instances append
 * to concurrently (one per Claude window: the audit log, the per-portal
 * spend ledgers). Node core has no flock(2) and sigil takes no native
 * deps, so this is built from two atomic filesystem operations only:
 * exclusive create and unlink of a process's *own* files.
 *
 * It is Lamport's bakery algorithm on a directory:
 *
 *   1. create   c-<pid>-<token>            "I am choosing a number"
 *   2. read the directory; my number is 1 + the largest ticket number
 *   3. create   t-<number>-<pid>-<token>   my ticket
 *   4. unlink   c-<pid>-<token>
 *   5. wait until no other live process is choosing, and no other live
 *      process holds a ticket ordered before mine (number, pid, token)
 *   6. critical section
 *   7. unlink my ticket
 *
 * Why this and not a single lock file: with one file, recovering from a
 * holder that died means deleting a path some other process may just
 * have re-created, and every "check, then unlink" sequence is a race —
 * in the lock, and again in any sidecar used to serialise the breaking.
 * Here no process ever unlinks a live process's file. Tickets of dead
 * pids are simply ignored (and swept, which is safe because their owner
 * cannot act), so a crashed holder costs nothing and there is nothing to
 * "break". Correctness needs only that a file present for the whole of a
 * readdir is listed, which every filesystem gives.
 *
 * A process also recognises tickets carrying its own pid: a token it
 * minted but no longer holds is an orphan of its own (a release that
 * failed), and a token it never minted belongs to a dead predecessor that
 * had this pid; both are swept.
 *
 * Residual gap, documented rather than hidden: pid reuse across
 * *different* processes. A dead holder whose pid was recycled by an
 * unrelated live process looks alive, and its ticket blocks everyone
 * until that process exits or a human removes the file. That is an
 * availability limit, not an exclusion failure; closing it needs OS-level
 * locking.
 */
export class FileLockError extends Error {
  constructor(msg: string) {
    super(`file lock error: ${msg}`);
    this.name = 'FileLockError';
  }
}
/** @deprecated alias kept for the audit module's public surface. */
export const AuditLockError = FileLockError;

export interface AcquireLockOptions {
  timeoutMs?: number;
  pollMs?: number;
}

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_POLL_MS = 25;

/**
 * Test-only seam: runs after our ticket is created and before we start
 * waiting, so a test can interpose a contender at the moment that matters.
 * Never set by production code.
 */
export const _testHooks: { afterTicket?: (lockDir: string) => void } = {};

// Tokens this process has minted, and those it currently holds.
const minted = new Set<string>();
const held = new Set<string>();

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function writeAllSync(fd: number, data: string): void {
  const buf = Buffer.from(data, 'utf8');
  let written = 0;
  while (written < buf.length) {
    const n = writeSync(fd, buf, written, buf.length - written);
    if (n <= 0) throw new Error(`short write (${written}/${buf.length} bytes)`);
    written += n;
  }
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the pid exists but belongs to another user — still alive.
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

const TICKET_RE = /^t-(\d+)-(\d+)-([0-9a-f]{16})$/;
const CHOOSING_RE = /^c-(\d+)-([0-9a-f]{16})$/;

interface Entry {
  name: string;
  kind: 'ticket' | 'choosing';
  /** Ticket number; 0 for a choosing marker. */
  seq: number;
  pid: number;
  token: string;
}

function parseEntry(name: string): Entry | null {
  const t = TICKET_RE.exec(name);
  if (t) return { name, kind: 'ticket', seq: Number(t[1]), pid: Number(t[2]), token: t[3]! };
  const c = CHOOSING_RE.exec(name);
  if (c) return { name, kind: 'choosing', seq: 0, pid: Number(c[1]), token: c[2]! };
  return null; // not ours to interpret, never touched
}

function ticketName(seq: number, pid: number, token: string): string {
  return `t-${seq}-${pid}-${token}`;
}

function before(a: Entry, b: Entry): boolean {
  if (a.seq !== b.seq) return a.seq < b.seq;
  if (a.pid !== b.pid) return a.pid < b.pid;
  return a.token < b.token;
}

function createExclusive(path: string): void {
  closeSync(openSync(path, 'wx', 0o600));
}

function unlinkQuiet(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    /* already gone */
  }
}

/**
 * List the live contenders in `dir`, sweeping entries whose owner cannot
 * act: dead pids, and this pid's own orphans (minted-but-unheld tokens,
 * or tokens never minted by this process — a dead predecessor with the
 * same pid). Our own currently held entries are returned too, so a
 * nested acquire sees the outer ticket as a contender and times out
 * rather than deadlocking silently or entering twice.
 */
function liveEntries(dir: string): Entry[] {
  const out: Entry[] = [];
  for (const name of readdirSync(dir)) {
    const e = parseEntry(name);
    if (!e) continue;
    const sweep = e.pid === process.pid ? !held.has(e.token) : !isAlive(e.pid);
    if (sweep) {
      unlinkQuiet(join(dir, name));
      continue;
    }
    out.push(e);
  }
  return out;
}

/**
 * Acquire an exclusive cross-process lock over `lockDir` (created if
 * absent). Returns an idempotent release function. Throws FileLockError
 * if the lock cannot be acquired within `timeoutMs`.
 */
export function acquireLockSync(lockDir: string, opts: AcquireLockOptions = {}): () => void {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = opts.pollMs ?? DEFAULT_POLL_MS;
  const deadline = Date.now() + timeoutMs;
  mkdirSync(lockDir, { recursive: true, mode: 0o700 });

  const token = randomBytes(8).toString('hex');
  minted.add(token);
  const choosing = join(lockDir, `c-${process.pid}-${token}`);
  let mine: Entry;
  createExclusive(choosing);
  try {
    // Marking the choosing token as held for the duration keeps the sweep
    // in liveEntries from treating our own marker as an orphan.
    held.add(token);
    let max = 0;
    for (const e of liveEntries(lockDir)) if (e.kind === 'ticket' && e.seq > max) max = e.seq;
    const seq = max + 1;
    mine = {
      name: ticketName(seq, process.pid, token),
      kind: 'ticket',
      seq,
      pid: process.pid,
      token,
    };
    createExclusive(join(lockDir, mine.name));
  } catch (err) {
    held.delete(token);
    minted.delete(token);
    unlinkQuiet(choosing);
    throw err;
  }
  unlinkQuiet(choosing);
  _testHooks.afterTicket?.(lockDir);

  const ticketPath = join(lockDir, mine.name);
  let released = false;
  const release = (): void => {
    if (released) return;
    // Drop "held" first: if the unlink fails for good, the ticket on disk
    // is then minted-but-unheld, i.e. recognisably our own orphan, and the
    // next acquire in this process sweeps it. A failed release stays
    // retryable (released is only set on success).
    held.delete(token);
    try {
      unlinkSync(ticketPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    released = true;
    minted.delete(token);
  };

  for (;;) {
    const blocked = liveEntries(lockDir).some(
      (e) => e.token !== token && (e.kind === 'choosing' || before(e, mine)),
    );
    if (!blocked) return release;
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      release();
      throw new FileLockError(`timed out after ${timeoutMs}ms waiting for ${lockDir}`);
    }
    sleepSync(Math.min(pollMs, remaining));
  }
}

/** Sidecar lock directory for a data file: `<target>.lock.d`. */
export function lockPathFor(target: string): string {
  return `${target}.lock.d`;
}

/**
 * Run `fn` while holding the sidecar lock for `target`. Synchronous by
 * design (callers are synchronous append paths) and therefore not
 * re-entrant: a nested acquire of the same target times out.
 */
export function withFileLock<T>(target: string, fn: () => T, opts: AcquireLockOptions = {}): T {
  const lockDir = lockPathFor(target);
  const release = acquireLockSync(lockDir, opts);
  try {
    return fn();
  } finally {
    releaseWithRetry(release, lockDir);
  }
}

/**
 * A ticket with a live pid blocks every other session until it is gone,
 * so a release that fails would stall them until this process exits.
 * Retry a transient failure with backoff; if it still won't go, report on
 * stderr — never replace fn's outcome (a committed append must not be
 * reported as a failure, and fn's own error must not be masked). The
 * ticket is not lost for good: it stays minted, so this process sweeps it
 * as its own orphan on its next acquire.
 */
const RELEASE_ATTEMPTS = 5;
export function releaseWithRetry(release: () => void, lockDir: string): void {
  let last: unknown;
  for (let i = 0; i < RELEASE_ATTEMPTS; i++) {
    try {
      release();
      return;
    } catch (err) {
      last = err;
      sleepSync(10 * (i + 1));
    }
  }
  process.stderr.write(
    `sigil: failed to release a ticket in ${lockDir} after ${RELEASE_ATTEMPTS} attempts ` +
      `(${(last as Error)?.message ?? String(last)}); this process will sweep it on its ` +
      `next acquire, other sessions will wait until then\n`,
  );
}
