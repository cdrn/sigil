import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sealKey } from '../../src/crypto/index.js';
import {
  broadcast,
  isControlError,
  listSessionSockets,
  startControlServer,
  type ControlServerHandle,
} from '../../src/control/index.js';
import { sessionSocketPath } from '../../src/cli/paths.js';
import { HandleTable } from '../../src/daemon/handles.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmp(): string { return mkdtempSync(join(tmpdir(), 'sigil-bcast-')); }
const TEST_KDF = { m: 256, t: 1, p: 1 };

interface Session { pid: number; handles: HandleTable; ctl: ControlServerHandle; }

/** Bind N control servers (distinct PIDs) sharing one keysDir/controlDir. */
async function spinUp(controlDir: string, keysDir: string, policyDir: string, pids: number[]): Promise<Session[]> {
  const sessions: Session[] = [];
  for (const pid of pids) {
    const handles = new HandleTable();
    const ctl = await startControlServer({
      socketPath: sessionSocketPath(controlDir, pid),
      keysDir,
      policyDir,
      handles,
      pid,
    });
    sessions.push({ pid, handles, ctl });
  }
  return sessions;
}

async function tearDown(sessions: Session[]): Promise<void> {
  for (const s of sessions) {
    await s.ctl.close();
    s.handles.dispose();
  }
}

test('listSessionSockets: returns [] when control dir is missing', () => {
  const dir = mkTmp();
  try {
    equal(listSessionSockets(join(dir, 'nope')).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('listSessionSockets: lists <pid>.sock entries sorted by pid, ignores other files', async () => {
  const dir = mkTmp();
  const controlDir = join(dir, 'control');
  mkdirSync(controlDir, { recursive: true });
  const sessions = await spinUp(controlDir, join(dir, 'keys'), join(dir, 'policy'), [30, 10, 20]);
  try {
    // Noise that must be ignored.
    writeFileSync(join(controlDir, 'notes.txt'), 'x');
    writeFileSync(join(controlDir, 'control.sock'), 'x');
    const pids = listSessionSockets(controlDir).map((s) => s.pid);
    equal(pids.join(','), '10,20,30');
  } finally {
    await tearDown(sessions);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('broadcast unlock: one call unlocks every live session', async () => {
  const dir = mkTmp();
  const controlDir = join(dir, 'control');
  const keysDir = join(dir, 'keys');
  const policyDir = join(dir, 'policy');
  mkdirSync(controlDir, { recursive: true });
  mkdirSync(keysDir, { recursive: true });
  const pass = Buffer.from('correct-horse');
  writeFileSync(join(keysDir, 'evm:bot.sigil'), sealKey(priv(1), pass, TEST_KDF));

  const sessions = await spinUp(controlDir, keysDir, policyDir, [101, 102, 103]);
  try {
    // All locked to start.
    for (const s of sessions) equal(s.handles.isUnlocked(), false);

    const results = await broadcast(controlDir, {
      method: 'unlock',
      passphraseB64: pass.toString('base64'),
    });

    equal(results.length, 3);
    for (const r of results) {
      ok(r.response && !isControlError(r.response), `session ${r.pid} should unlock`);
      equal(r.reaped, false);
    }
    // Every in-process HandleTable is now unlocked.
    for (const s of sessions) ok(s.handles.isUnlocked(), `session ${s.pid} table unlocked`);
  } finally {
    await tearDown(sessions);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('broadcast status: aggregates a mix of locked + unlocked sessions', async () => {
  const dir = mkTmp();
  const controlDir = join(dir, 'control');
  const keysDir = join(dir, 'keys');
  mkdirSync(controlDir, { recursive: true });
  mkdirSync(keysDir, { recursive: true });

  const sessions = await spinUp(controlDir, keysDir, join(dir, 'policy'), [201, 202]);
  try {
    sessions[0]!.handles.markUnlocked(); // 201 unlocked, 202 locked

    const results = await broadcast(controlDir, { method: 'status' });
    const byPid = new Map(results.map((r) => [r.pid, r]));
    const a = byPid.get(201)!.response!;
    const b = byPid.get(202)!.response!;
    ok(!isControlError(a) && a.unlocked === true);
    ok(!isControlError(b) && b.unlocked === false);
  } finally {
    await tearDown(sessions);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('broadcast: reaps a stale socket left by a dead process', async () => {
  const dir = mkTmp();
  const controlDir = join(dir, 'control');
  const keysDir = join(dir, 'keys');
  mkdirSync(controlDir, { recursive: true });
  mkdirSync(keysDir, { recursive: true });

  // One live session...
  const sessions = await spinUp(controlDir, keysDir, join(dir, 'policy'), [301]);
  // ...and an orphan socket file from a "dead" process that never cleaned up.
  const stalePath = sessionSocketPath(controlDir, 999);
  writeFileSync(stalePath, '');
  try {
    const results = await broadcast(controlDir, { method: 'status' });
    equal(results.length, 2);
    const live = results.find((r) => r.pid === 301)!;
    const stale = results.find((r) => r.pid === 999)!;

    ok(live.response && !isControlError(live.response));
    equal(live.reaped, false);

    equal(stale.response, null);
    equal(stale.reaped, true);
    // The orphan file is gone — directory self-healed.
    ok(!existsSync(stalePath), 'stale socket should be unlinked');
  } finally {
    await tearDown(sessions);
    rmSync(dir, { recursive: true, force: true });
  }
});
