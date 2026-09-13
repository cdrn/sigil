import { test } from 'node:test';
import { equal, ok, throws } from 'node:assert/strict';
import { type ChildProcess, execFile, spawn } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { _testHooks, acquireLockSync } from '../../src/fs/lock.js';
import { FileLockError, lockPathFor, withFileLock } from '../../src/fs/index.js';

// The lock is Lamport's bakery on a directory: each contender owns a
// ticket file `t-<seq>-<pid>-<token>`; the holder is the lowest live
// ticket; nobody ever unlinks a live process's file.

const DEAD_PID = 2147483647; // above any real pid_max; kill(pid, 0) → ESRCH
const TOKEN = 'deadbeefdeadbeef';

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-lock-'));
}

/** Tickets currently in the lock directory, as [seq, pid, token]. */
function tickets(target: string): [number, number, string][] {
  const dir = lockPathFor(target);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .map((n) => /^t-(\d+)-(\d+)-([0-9a-f]{16})$/.exec(n))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => [Number(m[1]), Number(m[2]), m[3]!]);
}

/** Plant a ticket as another process would have left it. */
function plantTicket(target: string, pid: number, seq = 0, token = TOKEN): string {
  const dir = lockPathFor(target);
  mkdirSync(dir, { recursive: true });
  const p = join(dir, `t-${seq}-${pid}-${token}`);
  writeFileSync(p, '');
  return p;
}

/** Resolve when the child prints "ready"; reject if it exits first or stalls. */
function awaitReady(k: ChildProcess, timeoutMs = 10_000): Promise<void> {
  return new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => reject(new Error('child never reported ready')), timeoutMs);
    k.stdout!.on('data', (d) => {
      buf += d;
      if (buf.includes('ready')) {
        clearTimeout(t);
        resolve();
      }
    });
    k.once('exit', (code) => {
      clearTimeout(t);
      reject(new Error(`child exited (${code}) before reporting ready`));
    });
  });
}

test('lockPathFor names a sidecar directory next to the target', () => {
  equal(lockPathFor('/x/y/audit.log'), '/x/y/audit.log.lock.d');
});

test('withFileLock runs fn holding a ticket in our name, returns its value, and removes it', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    let seen: [number, number, string][] = [];
    const result = withFileLock(target, () => {
      seen = tickets(target);
      return 42;
    });
    equal(result, 42);
    equal(seen.length, 1);
    equal(seen[0]![1], process.pid, 'ticket carries our pid');
    equal(tickets(target).length, 0, 'ticket removed on release');
    equal(
      readdirSync(lockPathFor(target)).filter((n) => n.startsWith('c-')).length,
      0,
      'no choosing marker left behind',
    );
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('withFileLock releases the ticket when fn throws, and rethrows', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    throws(
      () =>
        withFileLock(target, () => {
          throw new Error('boom');
        }),
      /boom/,
    );
    equal(tickets(target).length, 0);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('release is idempotent', () => {
  const dir = mkTmp();
  try {
    const release = acquireLockSync(lockPathFor(join(dir, 'file')));
    release();
    release();
    equal(tickets(join(dir, 'file')).length, 0);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('a ticket held by a live process blocks us until timeout, and is never removed', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    const planted = plantTicket(target, process.pid, 0, TOKEN); // our pid, a token we never minted…
    // …would be swept as a dead predecessor's. Use a live *other* pid instead:
    rmSync(planted);
    const other = plantTicket(target, process.ppid, 0, TOKEN);
    const t0 = Date.now();
    throws(
      () => withFileLock(target, () => 1, { timeoutMs: 80 }),
      (err: unknown) => err instanceof FileLockError && /timed out/.test(err.message),
    );
    ok(Date.now() - t0 >= 70, 'waited for roughly the timeout');
    ok(existsSync(other), "live holder's ticket untouched");
    equal(tickets(target).length, 1, 'our own timed-out ticket was withdrawn');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('a ticket whose holder pid is dead is swept and does not block', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    const dead = plantTicket(target, DEAD_PID, 0);
    const t0 = Date.now();
    equal(
      withFileLock(target, () => 'ran', { timeoutMs: 5_000 }),
      'ran',
    );
    ok(Date.now() - t0 < 500, 'no waiting');
    ok(!existsSync(dead), 'dead ticket swept');
    equal(tickets(target).length, 0);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('a ticket bearing our pid but a token we never minted is a dead predecessor: swept', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    const stale = plantTicket(target, process.pid, 0, TOKEN);
    equal(
      withFileLock(target, () => 'ran', { timeoutMs: 500 }),
      'ran',
    );
    ok(!existsSync(stale));
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('a live choosing marker blocks contenders (bakery invariant)', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    const lockDir = lockPathFor(target);
    mkdirSync(lockDir, { recursive: true });
    writeFileSync(join(lockDir, `c-${process.ppid}-${TOKEN}`), '');
    throws(() => withFileLock(target, () => 1, { timeoutMs: 60 }), FileLockError);
    ok(existsSync(join(lockDir, `c-${process.ppid}-${TOKEN}`)), 'marker untouched');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('ordering: a lower live ticket wins, a higher one waits', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    // Our ticket will be max+1 = 6. A live ticket at 5 must block us; one at 7 must not.
    const lower = plantTicket(target, process.ppid, 5, 'aaaaaaaaaaaaaaaa');
    throws(() => withFileLock(target, () => 1, { timeoutMs: 60 }), FileLockError);
    rmSync(lower);
    // Same seq as ours would be 1 now (dir empty) — plant 1 with a *higher* pid
    // than ours so the tiebreak favours us.
    plantTicket(target, DEAD_PID - 1, 1, 'ffffffffffffffff'); // dead → swept anyway
    equal(
      withFileLock(target, () => 'ran', { timeoutMs: 500 }),
      'ran',
    );
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('non-reentrant: a nested acquire of the same target times out', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    throws(
      () =>
        withFileLock(target, () => withFileLock(target, () => 1, { timeoutMs: 40 }), {
          timeoutMs: 40,
        }),
      FileLockError,
    );
    equal(tickets(target).length, 0, 'both tickets withdrawn');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('a missing parent directory surfaces instead of retrying forever', () => {
  const dir = mkTmp();
  try {
    chmodSync(dir, 0o500);
    if (process.getuid?.() === 0) return;
    const target = join(dir, 'file');
    throws(
      () => withFileLock(target, () => 1, { timeoutMs: 100 }),
      (err: unknown) => (err as NodeJS.ErrnoException).code === 'EACCES',
    );
  } finally {
    chmodSync(dir, 0o700);
    rmSync(dir, { recursive: true });
  }
});

test('a contender that takes a ticket while we are about to wait is ordered correctly', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    // After our ticket exists, plant a live-looking (parent pid) ticket with
    // a LOWER number: bakery says it goes first, so we must wait.
    let fired = 0;
    _testHooks.afterTicket = (d) => {
      if (d !== lockPathFor(target) || fired++ > 0) return;
      plantTicket(target, process.ppid, 0, 'bbbbbbbbbbbbbbbb');
    };
    let ran = false;
    try {
      throws(
        () =>
          withFileLock(
            target,
            () => {
              ran = true;
            },
            { timeoutMs: 80 },
          ),
        FileLockError,
      );
    } finally {
      delete _testHooks.afterTicket;
    }
    ok(!ran);
    equal(fired, 1);
    equal(
      tickets(target).filter(([, pid]) => pid === process.ppid).length,
      1,
      'their ticket intact',
    );
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('a process sweeps its own orphaned ticket (release failed for good) on the next acquire', () => {
  if (process.getuid?.() === 0) return;
  const dir = mkTmp();
  const savedWrite = process.stderr.write;
  let warned = '';
  try {
    const target = join(dir, 'file');
    const lockDir = lockPathFor(target);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      warned += String(chunk);
      return true;
    }) as typeof process.stderr.write;
    let result: string;
    try {
      result = withFileLock(target, () => {
        chmodSync(lockDir, 0o500); // unlink of our ticket will fail throughout the retries
        return 'committed';
      });
    } finally {
      chmodSync(lockDir, 0o700);
    }
    equal(result, 'committed');
    ok(/failed to release/.test(warned), 'stranded ticket reported');
    equal(tickets(target).length, 1, 'ticket stranded with our live pid');
    // Another process would wait on it; we recognise it as our own orphan.
    equal(
      withFileLock(target, () => 'again', { timeoutMs: 500 }),
      'again',
    );
    equal(tickets(target).length, 0);
  } finally {
    process.stderr.write = savedWrite;
    chmodSync(lockPathFor(join(dir, 'file')), 0o700);
    rmSync(dir, { recursive: true });
  }
});

test('a transient release failure is retried and the lock is free afterwards', async () => {
  if (process.getuid?.() === 0) return;
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    const lockDir = lockPathFor(target);
    mkdirSync(lockDir, { recursive: true });
    const fixer = spawn('sh', ['-c', `sleep 0.05; chmod 700 "${lockDir}"`], { stdio: 'ignore' });
    const done = new Promise<void>((r) => fixer.once('exit', () => r()));
    const result = withFileLock(target, () => {
      chmodSync(lockDir, 0o500);
      return 'value';
    });
    await done;
    chmodSync(lockDir, 0o700);
    equal(result, 'value');
    equal(tickets(target).length, 0, 'released after the retry');
  } finally {
    chmodSync(lockPathFor(join(dir, 'file')), 0o700);
    rmSync(dir, { recursive: true });
  }
});

test('withFileLock waits for a lock held by another process, then acquires it', async () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    const mod = fileURLToPath(new URL('../../src/fs/index.js', import.meta.url));
    const script = `
      import { withFileLock } from ${JSON.stringify(mod)};
      const s = new Int32Array(new SharedArrayBuffer(4));
      withFileLock(process.argv[1], () => { process.stdout.write('ready\\n'); Atomics.wait(s, 0, 0, 250); });
    `;
    const child = execFile(process.execPath, ['--input-type=module', '-e', script, target]);
    await awaitReady(child);
    equal(tickets(target).length, 1, 'child holds a ticket');
    const t0 = Date.now();
    const waited = withFileLock(target, () => Date.now() - t0, { timeoutMs: 5_000 });
    ok(waited >= 150, `parent waited for the child (${waited}ms)`);
    await new Promise<void>((resolve) => child.once('exit', () => resolve()));
    equal(tickets(target).length, 0);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('competing processes: barrier-released contenders never overlap inside the section', async () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    const barrier = join(dir, 'go');
    const marker = join(dir, 'inside'); // O_EXCL canary: exists only while someone is inside
    const counter = join(dir, 'count');
    const mod = fileURLToPath(new URL('../../src/fs/index.js', import.meta.url));
    // Start with a dead holder's ticket in place so sweeping races too.
    plantTicket(target, DEAD_PID, 0);
    const N = 4;
    const ITER = 40;
    const script = `
      import { withFileLock } from ${JSON.stringify(mod)};
      import { openSync, closeSync, unlinkSync, existsSync, appendFileSync } from 'node:fs';
      const [target, barrier, marker, counter, iter] = process.argv.slice(1);
      const s = new Int32Array(new SharedArrayBuffer(4));
      process.stdout.write('ready\\n');
      while (!existsSync(barrier)) Atomics.wait(s, 0, 0, 1);
      for (let i = 0; i < Number(iter); i++) {
        withFileLock(target, () => {
          let fd;
          try { fd = openSync(marker, 'wx'); } catch (e) { console.error('EXCLUSION VIOLATED', e.code); process.exit(1); }
          Atomics.wait(s, 0, 0, 1);
          appendFileSync(counter, process.pid + '\\n');
          closeSync(fd); unlinkSync(marker);
        });
      }
    `;
    const kids = Array.from({ length: N }, () =>
      execFile(process.execPath, [
        '--input-type=module',
        '-e',
        script,
        target,
        barrier,
        marker,
        counter,
        String(ITER),
      ]),
    );
    const exits = kids.map(
      (k) =>
        new Promise<{ code: number | null; err: string }>((resolve) => {
          let err = '';
          k.stderr!.on('data', (d) => (err += d));
          k.once('exit', (code) => resolve({ code, err }));
        }),
    );
    try {
      await Promise.all(kids.map((k) => awaitReady(k)));
    } catch (err) {
      for (const k of kids) k.kill('SIGKILL');
      throw err;
    }
    writeFileSync(barrier, '');
    for (const r of await Promise.all(exits)) equal(r.code, 0, r.err);
    const lines = readFileSync(counter, 'utf8').split('\n').filter(Boolean);
    equal(lines.length, N * ITER);
    equal(new Set(lines).size, N, 'every child got in');
    ok(!existsSync(marker));
    equal(tickets(target).length, 0, 'no tickets left behind');
  } finally {
    rmSync(dir, { recursive: true });
  }
});
