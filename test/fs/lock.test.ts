import { test } from 'node:test';
import { equal, ok, throws } from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FileLockError, lockPathFor, withFileLock } from '../../src/fs/index.js';

// The primitive itself (acquireLockSync) is covered in test/audit/concurrency.test.ts.
// These tests cover the withFileLock wrapper the audit log and spend ledgers share.

const DEAD_PID = 2147483647; // above any real pid_max; kill(pid, 0) → ESRCH
const TOKEN = 'deadbeefdeadbeef';

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-lock-'));
}

/** Plant a lock file as a crashed or foreign holder would have left it. */
function plantLock(target: string, content: string, ageMs = 0): string {
  const lock = lockPathFor(target);
  writeFileSync(lock, content);
  const t = (Date.now() - ageMs) / 1000;
  utimesSync(lock, t, t);
  return lock;
}

test('lockPathFor appends .lock to the target path', () => {
  equal(lockPathFor('/x/y/audit.log'), '/x/y/audit.log.lock');
});

test('withFileLock runs fn, returns its value, and releases the lock', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    let stamp = '';
    const result = withFileLock(target, () => {
      stamp = readFileSync(lockPathFor(target), 'utf8');
      return 42;
    });
    equal(result, 42);
    ok(stamp.startsWith(`${process.pid} `), 'holder pid recorded in the lock');
    ok(!existsSync(lockPathFor(target)));
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('withFileLock releases the lock when fn throws, and rethrows', () => {
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
    ok(!existsSync(lockPathFor(target)));
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('withFileLock times out with FileLockError while a live holder has it', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    plantLock(target, `${process.pid} ${TOKEN}\n`, 10 * 60_000); // old, but alive
    const t0 = Date.now();
    throws(
      () => withFileLock(target, () => 1, { timeoutMs: 60, staleMs: 1 }),
      (err: unknown) => err instanceof FileLockError && /timed out/.test(err.message),
    );
    ok(Date.now() - t0 >= 50, 'waited for roughly the timeout');
    ok(existsSync(lockPathFor(target)), 'live holder still owns it');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('withFileLock breaks a lock whose holder is dead, regardless of age', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    plantLock(target, `${DEAD_PID} ${TOKEN}\n`);
    const t0 = Date.now();
    equal(
      withFileLock(target, () => 'ran', { timeoutMs: 5_000, staleMs: 60_000 }),
      'ran',
    );
    ok(Date.now() - t0 < 1_000, 'did not wait for staleMs');
    ok(!existsSync(lockPathFor(target)));
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('withFileLock treats an unparsable lock by age: fresh waits, stale is broken', () => {
  const dir = mkTmp();
  try {
    throws(
      () => withFileLock(join(dir, 'fresh'), () => 1, { timeoutMs: 40, staleMs: 60_000 }),
      FileLockError,
    );
    plantLock(join(dir, 'fresh'), 'garbage');
    throws(
      () => withFileLock(join(dir, 'fresh'), () => 1, { timeoutMs: 40, staleMs: 60_000 }),
      FileLockError,
    );
    plantLock(join(dir, 'stale'), 'garbage', 120_000);
    equal(
      withFileLock(join(dir, 'stale'), () => 'ran', { timeoutMs: 40, staleMs: 30_000 }),
      'ran',
    );
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('withFileLock never removes a lock this process no longer owns', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'file');
    const lock = lockPathFor(target);
    const foreign = `${DEAD_PID} ${TOKEN}\n`;
    withFileLock(target, () => {
      writeFileSync(lock, foreign); // simulate a successor taking the slot
    });
    ok(existsSync(lock), "successor's lock left alone");
    equal(readFileSync(lock, 'utf8'), foreign);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('withFileLock is not re-entrant: a nested acquire of the same target times out', () => {
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
    ok(!existsSync(lockPathFor(target)), 'outer lock released after inner failure');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('withFileLock surfaces a missing parent directory instead of retrying forever', () => {
  const dir = mkTmp();
  try {
    const target = join(dir, 'no', 'such', 'dir', 'file');
    throws(
      () => withFileLock(target, () => 1, { timeoutMs: 100 }),
      (err: unknown) => (err as NodeJS.ErrnoException).code === 'ENOENT',
    );
  } finally {
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
      withFileLock(process.argv[1], () => { process.stdout.write('held\\n'); Atomics.wait(s, 0, 0, 250); });
    `;
    const child = execFile(process.execPath, ['--input-type=module', '-e', script, target]);
    await new Promise<void>((resolve) => child.stdout!.once('data', () => resolve()));
    ok(existsSync(lockPathFor(target)), 'child holds the lock');
    const t0 = Date.now();
    const waited = withFileLock(target, () => Date.now() - t0, { timeoutMs: 5_000 });
    ok(waited >= 150, `parent waited for the child (${waited}ms)`);
    await new Promise<void>((resolve) => child.once('exit', () => resolve()));
    ok(!existsSync(lockPathFor(target)));
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
    // Start every contender on a dead holder's lock so the breakers race too.
    plantLock(target, `${DEAD_PID} ${TOKEN}\n`);
    const N = 4;
    const ITER = 40;
    const script = `
      import { withFileLock } from ${JSON.stringify(mod)};
      import { openSync, closeSync, unlinkSync, existsSync, appendFileSync } from 'node:fs';
      const [target, barrier, marker, counter, iter] = process.argv.slice(1);
      const s = new Int32Array(new SharedArrayBuffer(4));
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
    await new Promise((r) => setTimeout(r, 150)); // let every child reach the barrier
    writeFileSync(barrier, '');
    for (const r of await Promise.all(exits)) equal(r.code, 0, r.err);
    const lines = readFileSync(counter, 'utf8').split('\n').filter(Boolean);
    equal(lines.length, N * ITER);
    equal(new Set(lines).size, N, 'every child got in');
    ok(!existsSync(marker));
    ok(!existsSync(lockPathFor(target)));
  } finally {
    rmSync(dir, { recursive: true });
  }
});
