import {
  closeSync,
  fsyncSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { randomBytes } from 'node:crypto';

/**
 * Cross-process advisory lock for the audit log.
 *
 * Node has no flock(2) binding in core, so this uses the next-best portable
 * primitive: O_CREAT|O_EXCL creation of a sidecar lock file. The create is
 * atomic at the filesystem level (no exists-then-create TOCTOU), so exactly
 * one process can hold the lock at a time.
 *
 * Crash recovery rules, chosen so that a LIVE holder can never lose the lock:
 *  - The lock file records `pid token`. A lock whose pid is alive is never
 *    broken, no matter how old — contenders simply time out with an error.
 *  - A lock whose pid is dead is breakable immediately.
 *  - A lock with unreadable content (a crash between create and write) is
 *    breakable only once its mtime is older than `staleMs`.
 *
 * Breaking is serialized through a second O_EXCL file (`<lock>.break`) that
 * is held only for the microseconds of a re-check + unlink. With breakers
 * serialized, the re-check under the breaker lock is authoritative: the main
 * lock cannot be concurrently replaced (creation requires absence; only
 * breakers unlink other processes' locks), so the unlink removes exactly the
 * file that was judged stale. The one residual hole — a breaker crashing
 * inside its microsecond critical section AND its pid being judged dead by
 * two racing contenders — is accepted and documented; closing it fully
 * requires OS-level locking that core Node does not expose.
 */

export class AuditLockError extends Error {
  constructor(msg: string) {
    super(`audit lock error: ${msg}`);
    this.name = 'AuditLockError';
  }
}

export interface AcquireLockOptions {
  /** Give up and throw after this long waiting for the lock. */
  timeoutMs?: number;
  /** Delay between acquisition attempts while contended. */
  pollMs?: number;
  /** Age past which an unreadable (torn) lock file is considered abandoned. */
  staleMs?: number;
}

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_POLL_MS = 25;
const DEFAULT_STALE_MS = 10_000;

/** Synchronous sleep without spinning: Atomics.wait on a throwaway buffer. */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * writeSync until the whole buffer is on the fd. POSIX permits short writes;
 * a partially written audit line that we then fsync and count as durable
 * would corrupt the chain.
 */
export function writeAllSync(fd: number, data: string): void {
  const buf = Buffer.from(data, 'utf8');
  let written = 0;
  while (written < buf.length) {
    written += writeSync(fd, buf, written, buf.length - written);
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

/**
 * Judge whether the lock file at `path` is abandoned. Returns false when the
 * file vanished (owner released it — nothing to break).
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
  const pid = Number.parseInt(content, 10);
  if (Number.isInteger(pid) && pid > 0) {
    // A live holder is never evicted; a dead one is stale immediately.
    return !isAlive(pid);
  }
  // Unreadable content: a holder crashed between create and write, or we read
  // in that window. Fresh files get the benefit of the doubt.
  return Date.now() - mtimeMs > staleMs;
}

/**
 * Create `path` exclusively and stamp it with our pid. Returns true on
 * success. On EEXIST returns false. Cleans up after itself if stamping fails
 * so a half-initialized lock is not left behind.
 */
function createStamped(path: string, token: string): boolean {
  let fd: number;
  try {
    fd = openSync(path, 'wx', 0o600);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw err;
  }
  try {
    writeAllSync(fd, `${process.pid} ${token}\n`);
    fsyncSync(fd);
  } catch (err) {
    try {
      closeSync(fd);
    } catch {
      /* the unlink below is the cleanup that matters */
    }
    try {
      unlinkSync(path);
    } catch {
      /* worst case a torn lock ages out via staleMs */
    }
    throw err;
  }
  closeSync(fd);
  return true;
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
  if (!createStamped(breakerPath, randomBytes(8).toString('hex'))) {
    // Another contender is mid-break. If they crashed and left the breaker
    // behind, clear it (same staleness rules) and let the next poll retry.
    if (isStale(breakerPath, staleMs)) {
      try {
        unlinkSync(breakerPath);
      } catch {
        /* lost the race to another cleaner — fine */
      }
    }
    return;
  }
  try {
    // Authoritative re-check now that breakers are serialized.
    if (isStale(lockPath, staleMs)) {
      try {
        unlinkSync(lockPath);
      } catch {
        /* released in the meantime — nothing to break */
      }
    }
  } finally {
    try {
      unlinkSync(breakerPath);
    } catch {
      /* if this fails the breaker ages out via staleMs */
    }
  }
}

/**
 * Acquire an exclusive cross-process lock. Returns an idempotent release
 * function. Throws AuditLockError if the lock cannot be acquired within
 * `timeoutMs`.
 */
export function acquireLockSync(lockPath: string, opts: AcquireLockOptions = {}): () => void {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = opts.pollMs ?? DEFAULT_POLL_MS;
  const staleMs = opts.staleMs ?? DEFAULT_STALE_MS;
  const token = randomBytes(8).toString('hex');
  const stamp = `${process.pid} ${token}\n`;
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    if (createStamped(lockPath, token)) {
      let released = false;
      return () => {
        if (released) return;
        // Because a live holder is never evicted, the lock is still ours;
        // the token check is belt and braces against misuse.
        try {
          if (readFileSync(lockPath, 'utf8') === stamp) {
            unlinkSync(lockPath);
          }
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
        }
        released = true;
      };
    }
    tryBreakStaleLock(lockPath, staleMs);
    if (Date.now() >= deadline) {
      throw new AuditLockError(`timed out after ${timeoutMs}ms waiting for ${lockPath}`);
    }
    sleepSync(pollMs);
  }
}
