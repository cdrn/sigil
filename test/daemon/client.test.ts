import { test } from 'node:test';
import { equal, ok, rejects } from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import {
  DaemonClient,
  DaemonRpcError,
} from '../../src/daemon/client.js';
import { HandleTable } from '../../src/daemon/handles.js';
import { startDaemonServer, type DaemonServerHandle } from '../../src/daemon/server.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmp(): string { return mkdtempSync(join(tmpdir(), 'sigil-client-')); }

interface H {
  dir: string;
  socketPath: string;
  server: DaemonServerHandle;
  handles: HandleTable;
  audit: AuditWriter;
}

async function startServer(): Promise<H> {
  const dir = mkTmp();
  const socketPath = join(dir, 'sock');
  const handles = new HandleTable();
  handles.addEntry('eth:bot', new SecretBuffer(priv(1)));
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => ++now });
  const server = await startDaemonServer({
    socketPath,
    context: { handles, audit },
  });
  return { dir, socketPath, server, handles, audit };
}

async function tearDown(h: H): Promise<void> {
  await h.server.close();
  h.audit.close();
  h.handles.dispose();
  rmSync(h.dir, { recursive: true });
}

test('DaemonClient connect + single call round trip', async () => {
  const h = await startServer();
  const c = new DaemonClient(h.socketPath);
  try {
    await c.connect();
    const result = await c.call('sigil_list_portals', null);
    const r = result as { portals: { handle: string }[] };
    equal(r.portals.length, 1);
    equal(r.portals[0]!.handle, 'eth:bot');
  } finally {
    c.close();
    await tearDown(h);
  }
});

test('DaemonClient handles multiple concurrent calls (id correlation)', async () => {
  const h = await startServer();
  const c = new DaemonClient(h.socketPath);
  try {
    await c.connect();
    const results = await Promise.all([
      c.call('sigil_list_portals', null),
      c.call('sigil_list_portals', null),
      c.call('sigil_list_portals', null),
    ]);
    equal(results.length, 3);
    for (const r of results) {
      const v = r as { portals: unknown[] };
      equal(v.portals.length, 1);
    }
  } finally {
    c.close();
    await tearDown(h);
  }
});

test('DaemonClient: server-side error rejects with DaemonRpcError preserving code', async () => {
  const h = await startServer();
  const c = new DaemonClient(h.socketPath);
  try {
    await c.connect();
    let caught: Error | null = null;
    try {
      await c.call('sigil_eth_sign_message', { portal: 'eth:nope', message: '0xff' });
    } catch (e) { caught = e as Error; }
    ok(caught instanceof DaemonRpcError);
    equal((caught as DaemonRpcError).code, -32000); // RPC_PORTAL_NOT_FOUND
  } finally {
    c.close();
    await tearDown(h);
  }
});

test('DaemonClient: server-side method-not-found rejects with DaemonRpcError', async () => {
  const h = await startServer();
  const c = new DaemonClient(h.socketPath);
  try {
    await c.connect();
    let caught: Error | null = null;
    try { await c.call('no_such_method', null); }
    catch (e) { caught = e as Error; }
    ok(caught instanceof DaemonRpcError);
    equal((caught as DaemonRpcError).code, -32601);
  } finally {
    c.close();
    await tearDown(h);
  }
});

test('DaemonClient: pending calls reject when client is closed', async () => {
  const h = await startServer();
  const c = new DaemonClient(h.socketPath);
  await c.connect();
  // Don't await — the call has no chance to complete before close().
  const pending = c.call('sigil_list_portals', null);
  c.close();
  await rejects(pending, /closed/);
  await tearDown(h);
});

test('DaemonClient: pending calls reject when underlying socket is destroyed server-side', async () => {
  // Use a controlled no-response server so we can force-close the connection
  // mid-request deterministically (rather than waiting for graceful drain).
  const { createServer } = await import('node:net');
  const { Socket } = await import('node:net');
  const dir = mkTmp();
  const socketPath = join(dir, 'sock');
  const serverSockets: InstanceType<typeof Socket>[] = [];
  const server = createServer((sock) => {
    serverSockets.push(sock);
  });
  await new Promise<void>((res) => server.listen(socketPath, () => res()));
  try {
    const c = new DaemonClient(socketPath);
    await c.connect();
    const pending = c.call('foo', null);
    // Let the call's write reach the server before we destroy.
    await new Promise<void>((r) => setImmediate(r));
    for (const s of serverSockets) s.destroy();
    await rejects(pending, /closed/);
    c.close();
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    rmSync(dir, { recursive: true });
  }
});

test('DaemonClient: connect to non-existent socket rejects', async () => {
  const c = new DaemonClient('/tmp/sigil-does-not-exist-' + Math.random());
  await rejects(c.connect());
});

test('DaemonClient: call after close rejects', async () => {
  const h = await startServer();
  const c = new DaemonClient(h.socketPath);
  await c.connect();
  c.close();
  await rejects(c.call('sigil_list_portals', null), /closed/);
  await tearDown(h);
});

test('DaemonClient: call before connect rejects', async () => {
  const c = new DaemonClient('/tmp/whatever');
  await rejects(c.call('foo', null), /not connected/);
});
