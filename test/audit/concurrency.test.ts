import { test } from 'node:test';
import { equal, notEqual, ok, throws } from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter, verifyChain } from '../../src/audit/log.js';
import { AuditLockError, acquireLockSync } from '../../src/audit/lock.js';

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-audit-conc-'));
}

// ============================================================================
// acquireLockSync
// ============================================================================

test('acquireLockSync creates the lock file and release removes it', () => {
  const dir = mkTmp();
  try {
    const lockPath = join(dir, 'audit.log.lock');
    const release = acquireLockSync(lockPath);
    ok(existsSync(lockPath));
    const content = readFileSync(lockPath, 'utf8');
    equal(content, `${process.pid} ${content.split(' ')[1]!.trim()}\n`);
    release();
    ok(!existsSync(lockPath));
    // Release is idempotent.
    release();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('acquireLockSync times out while a live lock is held', () => {
  const dir = mkTmp();
  try {
    const lockPath = join(dir, 'audit.log.lock');
    const release = acquireLockSync(lockPath);
    throws(() => acquireLockSync(lockPath, { timeoutMs: 100, pollMs: 10 }), AuditLockError);
    release();
    // Once released, acquisition succeeds again.
    const release2 = acquireLockSync(lockPath, { timeoutMs: 100, pollMs: 10 });
    release2();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('acquireLockSync breaks a lock whose holder pid is dead', async () => {
  const dir = mkTmp();
  try {
    const lockPath = join(dir, 'audit.log.lock');
    // Spawn a process that exits immediately so we hold a guaranteed-dead pid.
    const child = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
    const deadPid: number = await new Promise((resolve) => {
      child.once('exit', () => resolve(child.pid!));
    });
    writeFileSync(lockPath, `${deadPid} deadbeefdeadbeef\n`, { mode: 0o600 });
    const release = acquireLockSync(lockPath, { timeoutMs: 2_000, pollMs: 10 });
    ok(existsSync(lockPath));
    notEqual(readFileSync(lockPath, 'utf8'), `${deadPid} deadbeefdeadbeef\n`);
    // The breaker sidecar must not linger after a successful break.
    ok(!existsSync(`${lockPath}.break`));
    release();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('acquireLockSync never evicts a live holder, even past staleMs', () => {
  const dir = mkTmp();
  try {
    const lockPath = join(dir, 'audit.log.lock');
    const release = acquireLockSync(lockPath);
    // Make the live lock look ancient. Liveness must win over age.
    const past = (Date.now() - 3_600_000) / 1000;
    utimesSync(lockPath, past, past);
    throws(
      () => acquireLockSync(lockPath, { timeoutMs: 150, pollMs: 10, staleMs: 50 }),
      AuditLockError,
    );
    ok(existsSync(lockPath), 'live lock must survive contenders');
    release();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('acquireLockSync breaks an unparsable lock only after it goes stale by age', () => {
  const dir = mkTmp();
  try {
    const lockPath = join(dir, 'audit.log.lock');
    writeFileSync(lockPath, 'not a pid\n', { mode: 0o600 });
    // Fresh garbage lock: treated as live, acquisition times out.
    throws(
      () => acquireLockSync(lockPath, { timeoutMs: 100, pollMs: 10, staleMs: 60_000 }),
      AuditLockError,
    );
    // Backdate the mtime past staleMs: now breakable.
    const past = (Date.now() - 120_000) / 1000;
    utimesSync(lockPath, past, past);
    const release = acquireLockSync(lockPath, { timeoutMs: 2_000, pollMs: 10, staleMs: 60_000 });
    release();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('release does not remove a lock it no longer owns', () => {
  const dir = mkTmp();
  try {
    const lockPath = join(dir, 'audit.log.lock');
    const release = acquireLockSync(lockPath);
    // Simulate a stale-breaker replacing our lock with someone else's.
    writeFileSync(lockPath, '99999 aaaaaaaaaaaaaaaa\n', { mode: 0o600 });
    release();
    ok(existsSync(lockPath), 'foreign lock must survive our release');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('AuditWriter construction respects a held lock (startup read is serialized)', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    const release = acquireLockSync(`${path}.lock`);
    throws(() => new AuditWriter(path, { lock: { timeoutMs: 100, pollMs: 10 } }), AuditLockError);
    release();
    const w = new AuditWriter(path, { lock: { timeoutMs: 100, pollMs: 10 } });
    w.close();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ============================================================================
// Interleaved writers in one process (two independent in-memory heads)
// ============================================================================

test('two interleaved AuditWriter instances produce one verifiable chain', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    let now = 1_700_000_000_000;
    const a = new AuditWriter(path, { now: () => ++now });
    const b = new AuditWriter(path, { now: () => ++now });
    // Both saw an empty file at construction; without cross-writer tail
    // reconciliation, both would emit seq 0.
    for (let i = 0; i < 10; i++) {
      const w = i % 2 === 0 ? a : b;
      const e = w.append({
        kind: 'eth_sign_message',
        portal: 'evm:bot',
        payload: { i },
        decision: 'allow',
      });
      equal(e.seq, i);
    }
    a.close();
    b.close();
    const verified = verifyChain(readFileSync(path));
    equal(verified.length, 10);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('a writer resumes correctly after another writer advanced the tail', () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    let now = 1_700_000_000_000;
    const a = new AuditWriter(path, { now: () => ++now });
    a.append({ kind: 'a', portal: 'p', payload: {}, decision: 'allow' });
    // b appends several entries behind a's back.
    const b = new AuditWriter(path, { now: () => ++now });
    b.append({ kind: 'b1', portal: 'p', payload: {}, decision: 'allow' });
    b.append({ kind: 'b2', portal: 'p', payload: {}, decision: 'deny', reason: 'policy' });
    b.close();
    // a's cached head says nextSeq=1, but the on-disk tail is at seq=2.
    const e = a.append({ kind: 'a2', portal: 'p', payload: {}, decision: 'allow' });
    a.close();
    equal(e.seq, 3);
    const verified = verifyChain(readFileSync(path));
    equal(verified.length, 4);
    equal(verified[3]!.kind, 'a2');
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ============================================================================
// True cross-process concurrency: two node processes hammer one file.
// ============================================================================

// Each child constructs its writer (caching a head), signals readiness, then
// blocks on a shared start file so both writers begin appending with the SAME
// stale view — the exact interleaving that used to corrupt the chain.
const CHILD_SCRIPT = `
  const { writeFileSync, existsSync } = await import('node:fs');
  const { setTimeout: delay } = await import('node:timers/promises');
  const { AuditWriter } = await import(process.env.SIGIL_AUDIT_MODULE);
  const w = new AuditWriter(process.env.SIGIL_AUDIT_PATH);
  writeFileSync(process.env.SIGIL_AUDIT_READY, '');
  while (!existsSync(process.env.SIGIL_AUDIT_START)) await delay(5);
  const n = Number(process.env.SIGIL_AUDIT_COUNT);
  for (let i = 0; i < n; i++) {
    w.append({
      kind: process.env.SIGIL_AUDIT_KIND,
      portal: 'evm:bot',
      payload: { i },
      decision: 'allow',
    });
  }
  w.close();
`;

function runChildWriter(
  dir: string,
  path: string,
  kind: string,
  count: number,
): { ready: string; done: Promise<void> } {
  const moduleUrl = new URL('../../src/audit/log.js', import.meta.url).href;
  const ready = join(dir, `ready.${kind}`);
  const done = new Promise<void>((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', CHILD_SCRIPT], {
      stdio: ['ignore', 'ignore', 'pipe'],
      env: {
        ...process.env,
        SIGIL_AUDIT_MODULE: moduleUrl,
        SIGIL_AUDIT_PATH: path,
        SIGIL_AUDIT_KIND: kind,
        SIGIL_AUDIT_COUNT: String(count),
        SIGIL_AUDIT_READY: ready,
        SIGIL_AUDIT_START: join(dir, 'start'),
      },
    });
    let stderr = '';
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    child.once('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`child writer "${kind}" exited ${code}: ${stderr}`));
    });
    child.once('error', reject);
  });
  return { ready, done };
}

test('two concurrent processes appending to one file produce a verifiable chain', async () => {
  const dir = mkTmp();
  try {
    const path = join(dir, 'audit.log');
    const perWriter = 25;
    const a = runChildWriter(dir, path, 'writer_a', perWriter);
    const b = runChildWriter(dir, path, 'writer_b', perWriter);
    // Wait for both children to construct their writers, then fire the gun.
    while (!existsSync(a.ready) || !existsSync(b.ready)) {
      await new Promise((r) => setTimeout(r, 5));
    }
    writeFileSync(join(dir, 'start'), '');
    await Promise.all([a.done, b.done]);
    const verified = verifyChain(readFileSync(path));
    equal(verified.length, perWriter * 2);
    // Every entry from both writers made it in, in a single unbroken chain.
    equal(verified.filter((e) => e.kind === 'writer_a').length, perWriter);
    equal(verified.filter((e) => e.kind === 'writer_b').length, perWriter);
    for (let i = 0; i < verified.length; i++) equal(verified[i]!.seq, i);
    // No lock file left behind.
    ok(!existsSync(`${path}.lock`));
  } finally {
    rmSync(dir, { recursive: true });
  }
});
