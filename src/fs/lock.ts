import {
  closeSync,
  fsyncSync,
  linkSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { randomBytes } from 'node:crypto';

/**
 * Cross-process mutex over a sidecar file, for the files several
 * `sigil-mcp` instances append to concurrently (one per Claude window: the
 * audit log, the per-portal spend ledgers). Node core has no flock(2) and
 * sigil takes no native deps, so this is built from atomic filesystem
 * operations only.
 *
 * Establishment. The holder writes its stamp (`<pid> <token>\n`) to a
 * private temp file, fsyncs it, and publishes it with link(2) onto the
 * lock path. link is atomic and fails with EEXIST if the name is taken, so
 * the lock file is *never* observable in an unstamped state: there is no
 * window in which a contender can misjudge a freshly created lock as torn.
 * (An earlier design created the file exclusively and stamped it
 * afterwards; a holder that stalled in between could be evicted and then
 * co-hold with its evictor. That class of race is gone.)
 *
 * Staleness. A lock whose stamp names a dead pid is orphaned and may be
 * broken immediately. A stamp naming a live pid is never broken, however
 * old — except by the process that issued it: if this process finds a lock
 * carrying its own pid and a token it minted but no longer holds (a release
 * that failed after retries), it reclaims it. Only unparsable content
 * (hand edits, files left by pre-link versions) falls back to an age rule.
 * Breaking is serialized through a breaker sidecar so two contenders can't
 * both judge a lock stale and unlink a successor's fresh lock.
 *
 * Residual gap, documented rather than hidden: pid reuse. If the original
 * holder died and its pid was recycled by an unrelated live process before
 * anyone noticed, the lock stays until that process exits or a human
 * removes the file. Closing this needs OS-level locking.
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
  /** Age after which an *unparsable* lock file is treated as abandoned. */
  staleMs?: number;
}

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_POLL_MS = 25;
const DEFAULT_STALE_MS = 10_000;

/**
 * Test-only seams. `beforeLink` runs after the temp stamp file is written
 * and before it is linked onto the lock path, so a test can interpose a
 * contender at the only moment that matters. Never set by production code.
 */
export const _testHooks: { beforeLink?: (lockPath: string) => void } = {};

// Tokens this process has minted, and those it currently holds. A stamp
// with our pid and a minted-but-unheld token is our own orphan.
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

const STAMP_RE = /^(\d+) ([0-9a-f]{16})\n$/;

/**
 * Judge whether the lock file at `path` is abandoned. Returns false when
 * the file vanished (owner released it — nothing to break).
 */
function isStale(path: string, staleMs: number): boolean {
  let content: string;
  let mtimeMs: number;
  try {
    content = readFileSync(path, 'utf8');
    mtimeMs = statSync(path).mtimeMs;
  } catch {
    return false;
  }
  const stamp = STAMP_RE.exec(content);
  if (stamp) {
    const pid = Number.parseInt(stamp[1]!, 10);
    const token = stamp[2]!;
    if (pid === process.pid) return minted.has(token) && !held.has(token);
    return !isAlive(pid);
  }
  return Date.now() - mtimeMs > staleMs;
}

/**
 * Atomically publish a stamped lock file at `path`. Returns true if we now
 * hold it, false if the name was already taken. The stamp is complete and
 * durable before the name exists; on any failure only our private temp
 * file is removed — never anything at `path`.
 */
function establish(path: string, stamp: string): boolean {
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  const fd = openSync(tmp, 'wx', 0o600);
  try {
    writeAllSync(fd, stamp);
    fsyncSync(fd);
  } catch (err) {
    closeSync(fd);
    unlinkQuiet(tmp);
    throw err;
  }
  closeSync(fd);
  try {
    _testHooks.beforeLink?.(path);
    linkSync(tmp, path);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw err;
  } finally {
    unlinkQuiet(tmp);
  }
}

function unlinkQuiet(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    /* already gone, or will age out */
  }
}

/**
 * If the main lock looks stale, remove it — serialized via the breaker lock
 * so two contenders cannot both "break" and unlink a just-reacquired lock.
 * Best effort: on any contention or judgment change, do nothing; the caller
 * polls and retries.
 */
function tryBreakStaleLock(lockPath: string, staleMs: number): void {
  if (!isStale(lockPath, staleMs)) return;
  const breakerPath = `${lockPath}.break`;
  const breakerToken = randomBytes(8).toString('hex');
  minted.add(breakerToken);
  if (!establish(breakerPath, `${process.pid} ${breakerToken}\n`)) {
    if (isStale(breakerPath, staleMs)) unlinkQuiet(breakerPath);
    return;
  }
  held.add(breakerToken);
  try {
    // Authoritative re-check now that breakers are serialized.
    if (isStale(lockPath, staleMs)) unlinkQuiet(lockPath);
  } finally {
    unlinkQuiet(breakerPath);
    held.delete(breakerToken);
    minted.delete(breakerToken);
  }
}

/**
 * Acquire an exclusive cross-process lock. Returns an idempotent release
 * function. Throws FileLockError if the lock cannot be acquired within
 * `timeoutMs`.
 */
export function acquireLockSync(lockPath: string, opts: AcquireLockOptions = {}): () => void {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = opts.pollMs ?? DEFAULT_POLL_MS;
  const staleMs = opts.staleMs ?? DEFAULT_STALE_MS;
  const token = randomBytes(8).toString('hex');
  const stamp = `${process.pid} ${token}\n`;
  const deadline = Date.now() + timeoutMs;
  minted.add(token);

  for (;;) {
    if (establish(lockPath, stamp)) {
      held.add(token);
      let released = false;
      return () => {
        if (released) return;
        // Drop "held" before the unlink: if the unlink fails for good, the
        // stamp on disk is then minted-but-unheld, i.e. recognisably our
        // own orphan, and the next acquire in this process reclaims it.
        held.delete(token);
        try {
          if (readFileSync(lockPath, 'utf8') === stamp) unlinkSync(lockPath);
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        }
        released = true;
        minted.delete(token);
      };
    }
    tryBreakStaleLock(lockPath, staleMs);
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      minted.delete(token);
      throw new FileLockError(`timed out after ${timeoutMs}ms waiting for ${lockPath}`);
    }
    sleepSync(Math.min(pollMs, remaining));
  }
}

/** Sidecar lock path for a data file: `<target>.lock`. */
export function lockPathFor(target: string): string {
  return `${target}.lock`;
}

/**
 * Run `fn` while holding the sidecar lock for `target`. Synchronous by
 * design (callers are synchronous append paths) and therefore not
 * re-entrant: a nested acquire of the same target times out.
 */
export function withFileLock<T>(target: string, fn: () => T, opts: AcquireLockOptions = {}): T {
  const lockPath = lockPathFor(target);
  const release = acquireLockSync(lockPath, opts);
  try {
    return fn();
  } finally {
    releaseWithRetry(release, lockPath);
  }
}

/**
 * A lock stamped with a live pid is not broken by other processes, so a
 * release that fails would block every other session until this process
 * exits. Retry a transient failure with backoff; if it still won't go,
 * report on stderr — never replace fn's outcome (a committed append must
 * not be reported as a failure, and fn's own error must not be masked).
 * The lock is not lost for good: `minted`/`held` bookkeeping lets this
 * process recognise the orphan as its own and reclaim it on its next
 * acquire, once whatever blocked the unlink has cleared.
 */
const RELEASE_ATTEMPTS = 5;
export function releaseWithRetry(release: () => void, lockPath: string): void {
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
    `sigil: failed to release ${lockPath} after ${RELEASE_ATTEMPTS} attempts ` +
      `(${(last as Error)?.message ?? String(last)}); this process will reclaim it on ` +
      `its next acquire, other sessions will wait until then\n`,
  );
}
