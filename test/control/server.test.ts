import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sealKey } from '../../src/crypto/index.js';
import {
  ControlClientError,
  controlRequest,
  isControlError,
  startControlServer,
} from '../../src/control/index.js';
import { HandleTable } from '../../src/daemon/handles.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmp(): string { return mkdtempSync(join(tmpdir(), 'sigil-control-')); }
const TEST_KDF = { m: 256, t: 1, p: 1 };

interface H {
  dir: string;
  keysDir: string;
  socketPath: string;
  handles: HandleTable;
  close(): Promise<void>;
}

async function setUp(): Promise<H> {
  const dir = mkTmp();
  const keysDir = join(dir, 'keys');
  // Use a short socket path to stay under the 104-byte AF_UNIX limit on darwin.
  // `mkdtempSync(tmpdir(), ...)` paths are already short enough.
  const socketPath = join(dir, 'c.sock');
  const handles = new HandleTable();
  const ctl = await startControlServer({ socketPath, keysDir, handles, pid: 999 });
  return {
    dir,
    keysDir,
    socketPath,
    handles,
    close: async () => {
      await ctl.close();
      handles.dispose();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

test('control server: status on locked table', async () => {
  const h = await setUp();
  try {
    const resp = await controlRequest({
      socketPath: h.socketPath,
      request: { method: 'status' },
    });
    ok(!isControlError(resp));
    if (!isControlError(resp)) {
      equal(resp.unlocked, false);
      equal(resp.pid, 999);
      equal(resp.portals.length, 0);
    }
  } finally {
    await h.close();
  }
});

test('control server: unlock loads keyfiles + flips unlocked', async () => {
  const h = await setUp();
  try {
    const { mkdirSync } = await import('node:fs');
    mkdirSync(h.keysDir, { recursive: true });
    const pass = Buffer.from('correct-horse');
    writeFileSync(join(h.keysDir, 'eth:bot.sigil'), sealKey(priv(1), pass, TEST_KDF));

    const resp = await controlRequest({
      socketPath: h.socketPath,
      request: { method: 'unlock', passphraseB64: pass.toString('base64') },
    });
    ok(!isControlError(resp));
    if (!isControlError(resp)) {
      equal(resp.unlocked, true);
      equal(resp.portals.length, 1);
      equal(resp.portals[0]!.handle, 'eth:bot');
    }
    ok(h.handles.isUnlocked());
  } finally {
    await h.close();
  }
});

test('control server: unlock with wrong passphrase returns WRONG_PASSPHRASE + leaves table locked', async () => {
  const h = await setUp();
  try {
    const { mkdirSync } = await import('node:fs');
    mkdirSync(h.keysDir, { recursive: true });
    writeFileSync(join(h.keysDir, 'eth:bot.sigil'), sealKey(priv(1), Buffer.from('right'), TEST_KDF));
    const resp = await controlRequest({
      socketPath: h.socketPath,
      request: { method: 'unlock', passphraseB64: Buffer.from('wrong').toString('base64') },
    });
    ok(isControlError(resp));
    if (isControlError(resp)) equal(resp.code, 'WRONG_PASSPHRASE');
    equal(h.handles.isUnlocked(), false);
  } finally {
    await h.close();
  }
});

test('control server: unlock when already unlocked returns ALREADY_UNLOCKED', async () => {
  const h = await setUp();
  try {
    h.handles.markUnlocked();
    const resp = await controlRequest({
      socketPath: h.socketPath,
      request: { method: 'unlock', passphraseB64: Buffer.from('x').toString('base64') },
    });
    ok(isControlError(resp));
    if (isControlError(resp)) equal(resp.code, 'ALREADY_UNLOCKED');
  } finally {
    await h.close();
  }
});

test('control server: lock re-locks the table; unlock works again afterwards', async () => {
  const h = await setUp();
  try {
    const { mkdirSync } = await import('node:fs');
    mkdirSync(h.keysDir, { recursive: true });
    const pass = Buffer.from('p');
    writeFileSync(join(h.keysDir, 'eth:bot.sigil'), sealKey(priv(1), pass, TEST_KDF));

    // unlock → lock → unlock cycle.
    let resp = await controlRequest({
      socketPath: h.socketPath,
      request: { method: 'unlock', passphraseB64: pass.toString('base64') },
    });
    ok(!isControlError(resp));
    ok(h.handles.isUnlocked());

    resp = await controlRequest({
      socketPath: h.socketPath,
      request: { method: 'lock' },
    });
    ok(!isControlError(resp));
    if (!isControlError(resp)) equal(resp.unlocked, false);
    equal(h.handles.isUnlocked(), false);

    resp = await controlRequest({
      socketPath: h.socketPath,
      request: { method: 'unlock', passphraseB64: pass.toString('base64') },
    });
    ok(!isControlError(resp));
    ok(h.handles.isUnlocked());
  } finally {
    await h.close();
  }
});

test('control server: malformed JSON request returns INVALID_REQUEST', async () => {
  const h = await setUp();
  try {
    // controlRequest serializes to JSON. To send malformed JSON, talk to the
    // socket directly.
    const { createConnection } = await import('node:net');
    const sock = createConnection(h.socketPath);
    sock.setEncoding('utf8');
    const line = await new Promise<string>((resolve, reject) => {
      let buf = '';
      sock.on('connect', () => sock.write('{not json\n'));
      sock.on('data', (chunk: string) => {
        buf += chunk;
        const nl = buf.indexOf('\n');
        if (nl !== -1) resolve(buf.slice(0, nl));
      });
      sock.on('error', reject);
    });
    sock.end();
    const r = JSON.parse(line) as { ok: boolean; code?: string };
    equal(r.ok, false);
    equal(r.code, 'INVALID_REQUEST');
  } finally {
    await h.close();
  }
});

// ---------------------------------------------------------------------------
// Client behavior
// ---------------------------------------------------------------------------

test('client: SERVER_DOWN when socket file does not exist', async () => {
  let err: ControlClientError | null = null;
  try {
    await controlRequest({
      socketPath: '/tmp/sigil-test-nonexistent-' + Date.now() + '.sock',
      request: { method: 'status' },
      timeoutMs: 500,
    });
  } catch (e) { err = e as ControlClientError; }
  ok(err instanceof ControlClientError);
  equal(err!.code, 'SERVER_DOWN');
});

// ---------------------------------------------------------------------------
// Stale-socket recovery
// ---------------------------------------------------------------------------

test('startControlServer: clears a stale (unowned) socket file and binds', async () => {
  const dir = mkTmp();
  try {
    const socketPath = join(dir, 'c.sock');
    // Plant an orphan file at the socket path — not a live socket.
    writeFileSync(socketPath, '');
    const handles = new HandleTable();
    const ctl = await startControlServer({
      socketPath,
      keysDir: join(dir, 'keys'),
      handles,
      pid: 1,
    });
    try {
      const resp = await controlRequest({ socketPath, request: { method: 'status' } });
      ok(!isControlError(resp));
    } finally {
      await ctl.close();
      handles.dispose();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('startControlServer: refuses to bind when another server owns the socket', async () => {
  const h = await setUp();
  try {
    let err: Error | null = null;
    const handles2 = new HandleTable();
    try {
      await startControlServer({
        socketPath: h.socketPath,
        keysDir: h.keysDir,
        handles: handles2,
      });
    } catch (e) { err = e as Error; }
    ok(err instanceof Error);
    ok(/already in use/.test(err!.message));
    handles2.dispose();
  } finally {
    await h.close();
  }
});
