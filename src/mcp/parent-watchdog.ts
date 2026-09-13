/**
 * Exit when the parent process goes away (#90).
 *
 * sigil-mcp is spawned by Claude Code with its stdin as the MCP pipe, and
 * normally exits when that pipe closes. In practice daemons were found alive
 * weeks after their session had ended: a request stuck mid-flight (an
 * out-of-band confirm waiting on a phone) can keep the drain from resolving,
 * and a parent killed hard can leave the pipe's write end held by something
 * else. A live-but-orphaned daemon holds decrypted keys in memory and, after
 * an upgrade, is exactly the mixed-version writer the audit log must not
 * have.
 *
 * The watchdog polls the parent: if our ppid changes (an orphan is
 * reparented to launchd/init) or the original parent is no longer alive,
 * `onGone` fires. The timer is unref'd so it never keeps the process alive
 * by itself. Liveness and clock are injectable for tests.
 */
export interface ParentWatchdogOpts {
  /** The pid to watch. Defaults to process.ppid at start. */
  ppid?: number;
  /** Current ppid getter; defaults to () => process.ppid. */
  currentPpid?: () => number;
  /** Liveness probe; defaults to kill(pid, 0). */
  isAlive?: (pid: number) => boolean;
  /** Poll interval. Default 5000 ms. */
  intervalMs?: number;
  /** Called once when the parent is gone. */
  onGone: (reason: string) => void;
}

export function startParentWatchdog(opts: ParentWatchdogOpts): () => void {
  const startPpid = opts.ppid ?? process.ppid;
  const currentPpid = opts.currentPpid ?? (() => process.ppid);
  const isAlive = opts.isAlive ?? defaultIsAlive;
  const intervalMs = opts.intervalMs ?? 5_000;
  let fired = false;
  const check = (): void => {
    if (fired) return;
    const now = currentPpid();
    let reason: string | null = null;
    if (now !== startPpid) reason = `reparented from pid ${startPpid} to ${now}`;
    else if (!isAlive(startPpid)) reason = `parent pid ${startPpid} is gone`;
    if (reason !== null) {
      fired = true;
      clearInterval(timer);
      opts.onGone(reason);
    }
  };
  const timer = setInterval(check, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}

function defaultIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}
