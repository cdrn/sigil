import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { connect } from 'node:net';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sealKey } from '../../src/crypto/index.js';
import { runDaemon, type RuntimeEvent } from '../../src/daemon/runtime.js';
import type { LogEvent } from '../../src/daemon/server.js';

const TEST_KDF = { m: 256, t: 1, p: 1 };

function priv(byte: number): Buffer {
  const p = Buffer.alloc(32); p[31] = byte; return p;
}

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-runtime-'));
}

function rpc(socketPath: string, requestObj: object): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const sock = connect(socketPath);
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('connect', () => {
      sock.write(JSON.stringify(requestObj) + '\n');
    });
    sock.on('data', (chunk) => {
      buf += chunk;
      const nl = buf.indexOf('\n');
      if (nl !== -1) {
        const line = buf.slice(0, nl);
        sock.end();
        resolve(JSON.parse(line));
      }
    });
    sock.on('error', reject);
  });
}

test('runDaemon creates sigilHome and keys subdir with 0o700', async () => {
  const home = mkTmp();
  // remove the dir so runtime has to create it (mkdtemp already created it,
  // so we just delete the contents and verify perms after the fact).
  const handle = await runDaemon({
    sigilHome: home,
    passphrase: () => Buffer.from('x'),
  });
  try {
    const homeStat = statSync(home);
    const keysStat = statSync(join(home, 'keys'));
    equal((homeStat.mode & 0o777), 0o700);
    equal((keysStat.mode & 0o777), 0o700);
  } finally {
    await handle.shutdown();
    rmSync(home, { recursive: true });
  }
});

test('runDaemon zeroes the passphrase buffer after use', async () => {
  const home = mkTmp();
  const passphrase = Buffer.from('hunter2', 'utf8');
  const original = Array.from(passphrase);
  const handle = await runDaemon({
    sigilHome: home,
    passphrase: () => passphrase,
  });
  try {
    // After runDaemon resolves, the passphrase buffer should be zeroed.
    for (const b of passphrase) equal(b, 0);
    // Sanity: the buffer was non-zero to start with.
    ok(original.some((b) => b !== 0));
  } finally {
    await handle.shutdown();
    rmSync(home, { recursive: true });
  }
});

test('runDaemon serves list_portals with 0 portals when no keyfiles exist', async () => {
  const home = mkTmp();
  const handle = await runDaemon({
    sigilHome: home,
    passphrase: () => Buffer.from('x'),
  });
  try {
    equal(handle.portals, 0);
    const resp = await rpc(handle.socketPath, {
      jsonrpc: '2.0',
      id: 1,
      method: 'sigil_list_portals',
    });
    const r = resp as { id: number; result: { portals: unknown[] } };
    equal(r.id, 1);
    equal(r.result.portals.length, 0);
  } finally {
    await handle.shutdown();
    rmSync(home, { recursive: true });
  }
});

test('runDaemon loads existing keyfiles and exposes them via list_portals', async () => {
  const home = mkTmp();
  // Pre-stage a keyfile.
  const passphrase = Buffer.from('p', 'utf8');
  const keysDir = join(home, 'keys');
  // mkdir manually since runDaemon will create it but we need it now.
  const { mkdirSync } = await import('node:fs');
  mkdirSync(keysDir, { recursive: true, mode: 0o700 });
  writeFileSync(join(keysDir, 'eth:bot.sigil'), sealKey(priv(1), passphrase, TEST_KDF));

  const handle = await runDaemon({
    sigilHome: home,
    passphrase: () => Buffer.from('p', 'utf8'),
  });
  try {
    equal(handle.portals, 1);
    const resp = await rpc(handle.socketPath, {
      jsonrpc: '2.0',
      id: 1,
      method: 'sigil_list_portals',
    });
    const r = resp as { result: { portals: { handle: string }[] } };
    equal(r.result.portals.length, 1);
    equal(r.result.portals[0]!.handle, 'eth:bot');
  } finally {
    await handle.shutdown();
    rmSync(home, { recursive: true });
  }
});

test('end-to-end sign call goes through runtime and writes audit', async () => {
  const home = mkTmp();
  const passphrase = Buffer.from('p', 'utf8');
  const { mkdirSync } = await import('node:fs');
  mkdirSync(join(home, 'keys'), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, 'keys', 'eth:bot.sigil'), sealKey(priv(1), passphrase, TEST_KDF));

  const handle = await runDaemon({
    sigilHome: home,
    passphrase: () => Buffer.from('p', 'utf8'),
  });
  try {
    const messageHex = '0x' + Buffer.from('hello e2e').toString('hex');
    const resp = await rpc(handle.socketPath, {
      jsonrpc: '2.0',
      id: 7,
      method: 'sigil_eth_sign_message',
      params: { portal: 'eth:bot', message: messageHex },
    });
    const r = resp as { id: number; result: { signature: string } };
    equal(r.id, 7);
    ok(r.result.signature.startsWith('0x'));
    equal(r.result.signature.length, 2 + 130);

    // Audit log file exists and contains 1 entry.
    await handle.shutdown();
    const auditBytes = readFileSync(handle.auditPath, 'utf8');
    const lines = auditBytes.split('\n').filter((l) => l.length > 0);
    equal(lines.length, 1);
    const entry = JSON.parse(lines[0]!);
    equal(entry.kind, 'eth_sign_message');
    equal(entry.portal, 'eth:bot');
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('shutdown is idempotent (safe to call twice)', async () => {
  const home = mkTmp();
  const handle = await runDaemon({
    sigilHome: home,
    passphrase: () => Buffer.from('x'),
  });
  await handle.shutdown();
  await handle.shutdown(); // should not throw or hang
  rmSync(home, { recursive: true });
});

test('runtime emits structured lifecycle events', async () => {
  const home = mkTmp();
  const events: (LogEvent | RuntimeEvent)[] = [];
  const handle = await runDaemon({
    sigilHome: home,
    passphrase: () => Buffer.from('x'),
    onLog: (e) => events.push(e),
  });
  try {
    ok(events.find((e) => e.kind === 'runtime_starting'));
    ok(events.find((e) => e.kind === 'listening'));
    ok(events.find((e) => e.kind === 'runtime_ready'));
  } finally {
    await handle.shutdown();
    ok(events.find((e) => e.kind === 'runtime_shutdown_complete'));
    rmSync(home, { recursive: true });
  }
});

test('runtime fails cleanly on wrong passphrase for existing keyfile', async () => {
  const home = mkTmp();
  const correct = Buffer.from('correct', 'utf8');
  const { mkdirSync } = await import('node:fs');
  mkdirSync(join(home, 'keys'), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, 'keys', 'eth:bot.sigil'), sealKey(priv(1), correct, TEST_KDF));

  let threw = false;
  try {
    await runDaemon({
      sigilHome: home,
      passphrase: () => Buffer.from('wrong', 'utf8'),
    });
  } catch (err) {
    threw = true;
    ok(/wrong passphrase|tampered/.test((err as Error).message));
  }
  ok(threw, 'expected runDaemon to throw on wrong passphrase');
  rmSync(home, { recursive: true });
});
