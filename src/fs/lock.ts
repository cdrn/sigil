import {
  closeSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
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
 * A process also recognises files carrying its own pid that no live
 * acquisition in it holds: an orphan of its own (a release that failed)
 * or a dead predecessor that had this pid. Both are swept.
 *
 * Residual gap, documented rather than hidden: pid reuse across
 * *different* processes. A dead holder whose pid was recycled by an
 * unrelated live process looks alive, and its ticket blocks everyone
 * until that process exits or a human removes the file. That is an
 * availability limit, not an exclusion failure; closing it needs OS-level
 * locking.
 *
 * Cross-version: a daemon from before this change locks `<target>.lock`
 * (a single stamped file) and never touches the bakery directory. A new
 * acquisition, once it is the bakery holder, also takes that legacy file
 * (see acquireLegacy), so old and new writers still mutually exclude
 * during an upgrade with a straggler window open.
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
 * Test-only seams. `afterTicket` runs once our ticket exists (before the
 * choosing marker is withdrawn); `betweenScans` runs between the marker
 * scan and the ticket scan of each admission check. Either may throw to
 * simulate a failure at that point. Never set by production code.
 */
export const _testHooks: {
  afterTicket?: (lockDir: string) => void;
  betweenScans?: (lockDir: string) => void;
} = {};

// Tokens this process currently holds (ticket or marker on disk that a
// live acquisition in this module instance owns). One module instance per
// process is assumed: worker threads or a second copy of this module would
// keep separate sets and could sweep each other's live files. sigil-mcp
// is single-threaded and loads this once.
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

function before(a: Entry, b: Entry): boolean {
  if (a.seq !== b.seq) return a.seq < b.seq;
  if (a.pid !== b.pid) return a.pid < b.pid;
  return a.token < b.token;
}

/** Exclusive create of an empty file; if close fails the file is removed. */
function createExclusive(path: string): void {
  const fd = openSync(path, 'wx', 0o600);
  try {
    closeSync(fd);
  } catch (err) {
    unlinkQuiet(path);
    throw err;
  }
}

function unlinkQuiet(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    /* already gone, or will be swept later */
  }
}

/** Unlink that treats ENOENT as success and rethrows anything else. */
function unlinkOwn(path: string): void {
  try {
    unlinkSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}

/**
 * List the live contenders in `dir`, sweeping entries whose owner cannot
 * act: dead pids, and this pid's own files that no live acquisition holds
 * (an orphan of a failed release, or a dead predecessor that had this
 * pid). Our own held entries are returned too, so a nested acquire sees
 * the outer ticket as a contender and times out rather than deadlocking
 * silently or entering twice.
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
 * Admission check. Two separate enumerations, in this order:
 *   1. is any other live process choosing?  (if so, not admitted)
 *   2. does any other live ticket order before mine?
 *
 * Why two: readdir is not a snapshot. A contender that withdraws its
 * marker and publishes its ticket while one enumeration is in flight can
 * be missed by that enumeration on both counts. With the marker read
 * strictly before the ticket read, the argument is:
 *   - If C's marker existed for the whole of scan 1, we see it and retry.
 *   - If C's marker was created after scan 1 began, C picks its number
 *     after that, and our ticket (created before scan 1) is present for
 *     the whole of C's selection scan, so C's number is larger than ours.
 *   - If C's marker was withdrawn during scan 1, C's ticket already existed
 *     when scan 1 ended, so it is present for the whole of scan 2 and we
 *     see it.
 * This is exactly Lamport's per-variable "wait until not choosing, then
 * read number", with each variable read as one enumeration.
 */
function admitted(dir: string, mine: Entry): boolean {
  const others = (es: Entry[]): Entry[] => es.filter((e) => e.token !== mine.token);
  if (others(liveEntries(dir)).some((e) => e.kind === 'choosing')) return false;
  _testHooks.betweenScans?.(dir);
  return !others(liveEntries(dir)).some((e) => e.kind === 'ticket' && before(e, mine));
}

/**
 * Acquire an exclusive cross-process lock over `lockDir` (created if
 * absent). Returns an idempotent, retryable release function. Throws
 * FileLockError if the lock cannot be acquired within `timeoutMs`. Any
 * failure to acquire — timeout or error — withdraws our files first.
 */
export function acquireLockSync(lockDir: string, opts: AcquireLockOptions = {}): () => void {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = opts.pollMs ?? DEFAULT_POLL_MS;
  const deadline = Date.now() + timeoutMs;
  mkdirSync(lockDir, { recursive: true, mode: 0o700 });

  const token = randomBytes(8).toString('hex');
  const markerPath = join(lockDir, `c-${process.pid}-${token}`);
  let ticketPath: string | undefined;
  let markerOnDisk = false;
  let legacyPath: string | undefined;
  const legacyToken = randomBytes(8).toString('hex');

  // Withdraw everything we put on disk. Throws if something we own could
  // not be removed (the caller's retry path handles that); the held flag
  // is dropped first so a leftover is recognisably our own orphan.
  const withdraw = (): void => {
    held.delete(token);
    // Release the legacy bridge first (outermost lock last-acquired).
    if (legacyPath) {
      releaseLegacy(legacyPath, legacyToken);
      legacyPath = undefined;
    }
    if (ticketPath) unlinkOwn(ticketPath);
    if (markerOnDisk) unlinkOwn(markerPath);
    markerOnDisk = false;
  };

  let mine: Entry;
  try {
    held.add(token);
    createExclusive(markerPath);
    markerOnDisk = true;
    let max = 0;
    for (const e of liveEntries(lockDir)) if (e.kind === 'ticket' && e.seq > max) max = e.seq;
    const seq = max + 1;
    // Fail closed rather than hand out a number that isn't strictly larger
    // than a live holder's: past MAX_SAFE_INTEGER, max + 1 === max, and two
    // holders with the same number could both be admitted. One line per
    // sign op, so this is unreachable in practice; refusing is still safer
    // than a silent tie. (Withdraw runs via the catch below.)
    if (!Number.isSafeInteger(seq) || seq <= max) {
      throw new FileLockError(`ticket number space exhausted in ${lockDir}`);
    }
    mine = {
      name: `t-${seq}-${process.pid}-${token}`,
      kind: 'ticket',
      seq,
      pid: process.pid,
      token,
    };
    ticketPath = join(lockDir, mine.name);
    createExclusive(ticketPath);
    _testHooks.afterTicket?.(lockDir);
    // A marker we fail to withdraw now is retried at release; meanwhile it
    // is ours (held), so our own admission check ignores it.
    try {
      unlinkOwn(markerPath);
      markerOnDisk = false;
    } catch {
      /* release() will retry */
    }

    for (;;) {
      if (admitted(lockDir, mine)) break;
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new FileLockError(`timed out after ${timeoutMs}ms waiting for ${lockDir}`);
      }
      sleepSync(Math.min(pollMs, remaining));
    }
    // Cross-version bridge. A daemon built before this change locks the
    // pre-PR single file `<target>.lock`; it knows nothing of the bakery
    // directory `<target>.lock.d`. While we are the bakery holder — so only
    // one new-version acquisition is ever here at once — take that legacy
    // file too, so an old and a new session mutually exclude. Because the
    // bakery already serialises new-vs-new, the legacy file is contended
    // only across the version boundary (transient: the old code was never
    // published), never among new sessions, so its single-file break race
    // can't affect the common path.
    legacyPath = legacyLockFor(lockDir) ?? undefined;
    if (legacyPath) acquireLegacy(legacyPath, deadline, pollMs, legacyToken);
  } catch (err) {
    try {
      withdraw();
    } catch {
      /* our leftovers are held-less now; this process sweeps them next time */
    }
    throw err;
  }

  let released = false;
  return () => {
    if (released) return;
    withdraw(); // throws on failure, leaving the closure retryable
    released = true;
  };
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
 * A ticket or marker with a live pid blocks every other session until it
 * is gone, so a release that fails would stall them until this process
 * exits. Retry a transient failure with backoff; if it still won't go,
 * report on stderr — never replace fn's outcome (a committed append must
 * not be reported as a failure, and fn's own error must not be masked).
 * The files are not lost for good: no live acquisition holds their token
 * any more, so this process sweeps them as its own orphans on its next
 * acquire.
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

// ---------------------------------------------------------------------------
// Cross-version bridge to the pre-PR single-file lock (`<target>.lock`).
// ---------------------------------------------------------------------------

const LEGACY_STALE_MS = 10_000;

/** `<target>.lock` for a bakery dir named `<target>.lock.d`; else null. */
function legacyLockFor(lockDir: string): string | null {
  return lockDir.endsWith('.lock.d') ? lockDir.slice(0, -2) : null;
}

function legacyStale(path: string): boolean {
  let content: string;
  let mtimeMs: number;
  try {
    content = readFileSync(path, 'utf8');
    mtimeMs = statSync(path).mtimeMs;
  } catch {
    return false; // vanished — released
  }
  const m = /^(\d+) [0-9a-f]{16}\n$/.exec(content);
  if (m) return !isAlive(Number.parseInt(m[1]!, 10));
  return Date.now() - mtimeMs > LEGACY_STALE_MS; // torn/foreign: age out
}

function acquireLegacy(path: string, deadline: number, pollMs: number, token: string): void {
  const stamp = `${process.pid} ${token}\n`;
  for (;;) {
    try {
      const fd = openSync(path, 'wx', 0o600);
      try {
        writeAllSync(fd, stamp);
      } finally {
        closeSync(fd);
      }
      return;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    }
    if (legacyStale(path)) {
      unlinkQuiet(path);
      continue;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new FileLockError(`timed out waiting for legacy lock ${path}`);
    sleepSync(Math.min(pollMs, remaining));
  }
}

function releaseLegacy(path: string, token: string): void {
  // Only remove it if it is still our stamp (a stale-breaker may have taken
  // over). ENOENT is success.
  try {
    if (readFileSync(path, 'utf8') === `${process.pid} ${token}\n`) unlinkSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
}
