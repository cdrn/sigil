import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { startParentWatchdog } from '../../src/mcp/parent-watchdog.js';

function wait(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

test('watchdog fires once when the parent pid is reported dead', async () => {
  let alive = true;
  const reasons: string[] = [];
  const stop = startParentWatchdog({
    ppid: 4242,
    currentPpid: () => 4242,
    isAlive: () => alive,
    intervalMs: 10,
    onGone: (r) => reasons.push(r),
  });
  await wait(40);
  equal(reasons.length, 0, 'parent alive: quiet');
  alive = false;
  await wait(60);
  equal(reasons.length, 1, 'fires exactly once');
  ok(/parent pid 4242 is gone/.test(reasons[0]!));
  stop();
});

test('watchdog fires when we are reparented (orphan adopted by init/launchd)', async () => {
  let ppid = 4242;
  const reasons: string[] = [];
  const stop = startParentWatchdog({
    ppid: 4242,
    currentPpid: () => ppid,
    isAlive: () => true, // the old pid may even still "exist" (reuse); reparenting is decisive
    intervalMs: 10,
    onGone: (r) => reasons.push(r),
  });
  ppid = 1;
  await wait(60);
  equal(reasons.length, 1);
  ok(/reparented from pid 4242 to 1/.test(reasons[0]!));
  stop();
});

test('watchdog can be stopped and then never fires', async () => {
  let alive = true;
  let fired = 0;
  const stop = startParentWatchdog({
    ppid: 1,
    currentPpid: () => 1,
    isAlive: () => alive,
    intervalMs: 10,
    onGone: () => fired++,
  });
  stop();
  alive = false;
  await wait(50);
  equal(fired, 0);
});

test('watchdog treats EPERM as alive (parent owned by another user) and ESRCH as gone', async () => {
  // Real probe against real pids: our own parent is alive; a huge pid is not.
  const reasons: string[] = [];
  const stopAlive = startParentWatchdog({
    ppid: process.ppid,
    intervalMs: 10,
    onGone: (r) => reasons.push(r),
  });
  const stopDead = startParentWatchdog({
    ppid: 2147483647,
    currentPpid: () => 2147483647,
    intervalMs: 10,
    onGone: (r) => reasons.push(r),
  });
  await wait(60);
  stopAlive();
  stopDead();
  equal(reasons.length, 1);
  ok(/2147483647 is gone/.test(reasons[0]!));
});

test('integration: a real sigil-mcp exits when its parent is SIGKILLed while stdin stays open', async () => {
  const { spawn } = await import('node:child_process');
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const bin = fileURLToPath(new URL('../../src/bin/sigil-mcp.js', import.meta.url));
  const home = mkdtempSync(join(tmpdir(), 'sigil-orphan-'));
  // A throwaway parent that runs the daemon as a background child and
  // waits. sh gives background jobs /dev/null as stdin, which would end the
  // daemon through the ordinary EOF path — so the test's own stdin pipe is
  // passed through on fd 3 and the daemon reads it as fd 0. The test keeps
  // that pipe open; killing the parent leaves it open, so only the
  // watchdog can end the daemon.
  const parent = spawn('sh', ['-c', `node "${bin}" 0<&3 & echo "DAEMON=$!"; wait`, 'sh'], {
    env: { ...process.env, SIGIL_HOME: home, SIGIL_PARENT_POLL_MS: '100' },
    stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
  });
  // fd 3 of the parent is our 4th stdio pipe; sh's `0<&3` dups it in.
  const daemonPid: number = await new Promise((resolve, reject) => {
    let out = '';
    parent.stdout.on('data', (d) => {
      out += d;
      const m = /DAEMON=(\d+)/.exec(out);
      if (m) resolve(Number(m[1]));
    });
    parent.once('exit', (c) => reject(new Error(`parent exited early (${c})`)));
    setTimeout(() => reject(new Error('no daemon pid')), 10_000);
  });
  const alive = (pid: number): boolean => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return (e as NodeJS.ErrnoException).code === 'EPERM';
    }
  };
  // Give the daemon a moment to boot, confirm it is alive, then orphan it.
  await wait(1_000);
  ok(alive(daemonPid), 'daemon booted');
  parent.kill('SIGKILL');
  const t0 = Date.now();
  while (alive(daemonPid) && Date.now() - t0 < 8_000) await wait(100);
  const gone = !alive(daemonPid);
  if (!gone) {
    try {
      process.kill(daemonPid, 'SIGKILL');
    } catch {
      /* already gone */
    }
  }
  rmSync(home, { recursive: true, force: true });
  ok(gone, `orphaned daemon exited within ${Date.now() - t0}ms`);
});
