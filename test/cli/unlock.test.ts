import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { sealKey } from '../../src/crypto/index.js';
import { runCli } from '../../src/cli/main.js';
import { resolvePaths } from '../../src/cli/paths.js';
import { startControlServer } from '../../src/control/index.js';
import { HandleTable } from '../../src/daemon/handles.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmpHome(): string { return mkdtempSync(join(tmpdir(), 'sigil-cli-unlock-')); }
const TEST_KDF = { m: 256, t: 1, p: 1 };

function capture(): { stdout: Writable; stderr: Writable; out: () => string; err: () => string } {
  const outBuf: string[] = [];
  const errBuf: string[] = [];
  return {
    stdout: new Writable({ write(c, _e, cb) { outBuf.push(c.toString()); cb(); } }),
    stderr: new Writable({ write(c, _e, cb) { errBuf.push(c.toString()); cb(); } }),
    out: () => outBuf.join(''),
    err: () => errBuf.join(''),
  };
}

// Spins up a control server in-process for the CLI to connect to.
async function withRunningMcp(home: string, fn: (handles: HandleTable) => Promise<void>): Promise<void> {
  const paths = resolvePaths({ SIGIL_HOME: home });
  mkdirSync(paths.home, { recursive: true });
  mkdirSync(paths.keysDir, { recursive: true });
  const handles = new HandleTable();
  const ctl = await startControlServer({
    socketPath: paths.controlSocket,
    keysDir: paths.keysDir,
    handles,
    pid: 12345,
  });
  try {
    await fn(handles);
  } finally {
    await ctl.close();
    handles.dispose();
  }
}

test('runCli unlock: server down → exits 1 with clear message', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['unlock'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('whatever'),
    });
    equal(r.code, 1);
    ok(/not running/i.test(cap.err()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli unlock: happy path loads portals', async () => {
  const home = mkTmpHome();
  try {
    await withRunningMcp(home, async (handles) => {
      const paths = resolvePaths({ SIGIL_HOME: home });
      const pass = Buffer.from('hunter2');
      writeFileSync(join(paths.keysDir, 'eth:bot.sigil'), sealKey(priv(1), pass, TEST_KDF));

      const cap = capture();
      const r = await runCli({
        argv: ['unlock'],
        stdout: cap.stdout, stderr: cap.stderr,
        env: { SIGIL_HOME: home },
        passphrase: () => Buffer.from('hunter2'),
      });
      equal(r.code, 0);
      ok(/unlocked 1 portal/.test(cap.out()), `expected "unlocked 1 portal" in: ${cap.out()}`);
      ok(/eth:bot/.test(cap.out()));
      ok(handles.isUnlocked());
    });
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli unlock: wrong passphrase exits 2', async () => {
  const home = mkTmpHome();
  try {
    await withRunningMcp(home, async (handles) => {
      const paths = resolvePaths({ SIGIL_HOME: home });
      writeFileSync(join(paths.keysDir, 'eth:bot.sigil'), sealKey(priv(1), Buffer.from('right'), TEST_KDF));

      const cap = capture();
      const r = await runCli({
        argv: ['unlock'],
        stdout: cap.stdout, stderr: cap.stderr,
        env: { SIGIL_HOME: home },
        passphrase: () => Buffer.from('wrong'),
      });
      equal(r.code, 2);
      ok(/wrong passphrase/i.test(cap.err()));
      equal(handles.isUnlocked(), false);
    });
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli unlock: already unlocked → exits 1 with helpful message', async () => {
  const home = mkTmpHome();
  try {
    await withRunningMcp(home, async (handles) => {
      handles.markUnlocked();
      const cap = capture();
      const r = await runCli({
        argv: ['unlock'],
        stdout: cap.stdout, stderr: cap.stderr,
        env: { SIGIL_HOME: home },
        passphrase: () => Buffer.from('x'),
      });
      equal(r.code, 1);
      ok(/already unlocked/.test(cap.err()));
    });
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli unlock: passphrase buffer is zeroized after the call', async () => {
  const home = mkTmpHome();
  try {
    await withRunningMcp(home, async () => {
      const cap = capture();
      const pass = Buffer.from('hunter2');
      const seen = Array.from(pass);
      await runCli({
        argv: ['unlock'],
        stdout: cap.stdout, stderr: cap.stderr,
        env: { SIGIL_HOME: home },
        passphrase: () => pass,
      });
      ok(seen.some((b) => b !== 0));
      for (const b of pass) equal(b, 0);
    });
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli lock: server down → exits 1', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['lock'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
    });
    equal(r.code, 1);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli lock: locks a previously unlocked table', async () => {
  const home = mkTmpHome();
  try {
    await withRunningMcp(home, async (handles) => {
      handles.markUnlocked();
      const cap = capture();
      const r = await runCli({
        argv: ['lock'],
        stdout: cap.stdout, stderr: cap.stderr,
        env: { SIGIL_HOME: home },
      });
      equal(r.code, 0);
      ok(/locked/.test(cap.out()));
      equal(handles.isUnlocked(), false);
    });
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli status: reports running + unlocked + portals when MCP is alive', async () => {
  const home = mkTmpHome();
  try {
    await withRunningMcp(home, async (handles) => {
      const paths = resolvePaths({ SIGIL_HOME: home });
      const pass = Buffer.from('p');
      writeFileSync(join(paths.keysDir, 'eth:bot.sigil'), sealKey(priv(1), pass, TEST_KDF));
      handles.loadFromDir(paths.keysDir, pass);

      const cap = capture();
      const r = await runCli({
        argv: ['status'],
        stdout: cap.stdout, stderr: cap.stderr,
        env: { SIGIL_HOME: home },
      });
      equal(r.code, 0);
      const parsed = JSON.parse(cap.out()) as {
        mcpRunning: boolean; mcpPid: number; unlocked: boolean; portals: { handle: string }[];
      };
      equal(parsed.mcpRunning, true);
      equal(parsed.mcpPid, 12345);
      equal(parsed.unlocked, true);
      equal(parsed.portals.length, 1);
      equal(parsed.portals[0]!.handle, 'eth:bot');
    });
  } finally {
    rmSync(home, { recursive: true });
  }
});
