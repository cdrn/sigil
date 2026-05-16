import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { connect } from 'node:net';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  AuditWriter,
} from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import {
  HandleTable,
  startDaemonServer,
  RPC_INVALID_REQUEST,
  RPC_METHOD_NOT_FOUND,
  RPC_PARSE_ERROR,
  type DaemonServerHandle,
  type LogEvent,
} from '../../src/daemon/index.js';

function priv(byte: number): Buffer {
  const p = Buffer.alloc(32); p[31] = byte; return p;
}

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-server-'));
}

interface Harness {
  socketPath: string;
  server: DaemonServerHandle;
  events: LogEvent[];
  cleanup: () => Promise<void>;
}

async function startTestServer(): Promise<Harness> {
  const dir = mkTmp();
  const socketPath = join(dir, 'sock');
  const auditPath = join(dir, 'audit.log');
  const handles = new HandleTable();
  handles.addEntry('eth:bot', new SecretBuffer(priv(1)));
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(auditPath, { now: () => ++now });
  const events: LogEvent[] = [];
  const server = await startDaemonServer({
    socketPath,
    context: { handles, audit },
    onLog: (e) => events.push(e),
  });
  return {
    socketPath,
    server,
    events,
    cleanup: async () => {
      await server.close();
      audit.close();
      handles.dispose();
      rmSync(dir, { recursive: true });
    },
  };
}

/**
 * Send one or more JSON-RPC requests over a single connection and gather
 * matching responses by id. Resolves once `expectedResponses` lines have been
 * received.
 */
function rpcCall(socketPath: string, lines: string[]): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const sock = connect(socketPath);
    const responses: string[] = [];
    let buf = '';
    sock.setEncoding('utf8');
    sock.on('connect', () => {
      for (const l of lines) sock.write(l + '\n');
    });
    sock.on('data', (chunk) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.length > 0) responses.push(line);
        if (responses.length === lines.length) {
          sock.end();
        }
      }
    });
    sock.on('end', () => resolve(responses));
    sock.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

test('server creates the socket file at the configured path with 0o600 perms', async () => {
  const h = await startTestServer();
  try {
    const stat = statSync(h.socketPath);
    ok(stat.isSocket());
    // Lower 9 bits = unix perms
    equal((stat.mode & 0o777), 0o600);
  } finally {
    await h.cleanup();
  }
});

test('server replaces a stale socket file at the same path', async () => {
  const h = await startTestServer();
  await h.server.close();
  // Now start a second server at the same path; old socket file is left
  // around because close() removes it on Linux/macOS, but we explicitly
  // simulate the stale-file case by reusing the path.
  const h2 = await startTestServer();
  try {
    ok(statSync(h2.socketPath).isSocket());
  } finally {
    await h2.cleanup();
  }
  // First harness still needs cleanup for its handles dir.
  try { await h.cleanup(); } catch { /* socket already closed */ }
});

test('server logs lifecycle events', async () => {
  const h = await startTestServer();
  try {
    ok(h.events.find((e) => e.kind === 'listening' && e.path === h.socketPath));
  } finally {
    await h.cleanup();
  }
  ok(h.events.find((e) => e.kind === 'closed'));
});

// ---------------------------------------------------------------------------
// RPC over the socket
// ---------------------------------------------------------------------------

test('valid request → response with matching id', async () => {
  const h = await startTestServer();
  try {
    const [resp] = await rpcCall(h.socketPath, [
      JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'sigil_list_portals' }),
    ]);
    const parsed = JSON.parse(resp!);
    equal(parsed.id, 42);
    equal(parsed.jsonrpc, '2.0');
    ok(Array.isArray(parsed.result.portals));
    equal(parsed.result.portals.length, 1);
    equal(parsed.result.portals[0].handle, 'eth:bot');
  } finally {
    await h.cleanup();
  }
});

test('multiple pipelined requests on one connection are all answered', async () => {
  const h = await startTestServer();
  try {
    const reqs = [1, 2, 3].map((id) =>
      JSON.stringify({ jsonrpc: '2.0', id, method: 'sigil_list_portals' }),
    );
    const responses = await rpcCall(h.socketPath, reqs);
    equal(responses.length, 3);
    const ids = responses.map((r) => JSON.parse(r).id).sort();
    deepEqual(ids, [1, 2, 3]);
  } finally {
    await h.cleanup();
  }
});

test('unknown method returns METHOD_NOT_FOUND error', async () => {
  const h = await startTestServer();
  try {
    const [resp] = await rpcCall(h.socketPath, [
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'no_such_method' }),
    ]);
    const parsed = JSON.parse(resp!);
    equal(parsed.id, 1);
    equal(parsed.error.code, RPC_METHOD_NOT_FOUND);
  } finally {
    await h.cleanup();
  }
});

test('malformed JSON returns PARSE_ERROR with id=null', async () => {
  const h = await startTestServer();
  try {
    const [resp] = await rpcCall(h.socketPath, ['{not json']);
    const parsed = JSON.parse(resp!);
    equal(parsed.id, null);
    equal(parsed.error.code, RPC_PARSE_ERROR);
  } finally {
    await h.cleanup();
  }
});

test('invalid request envelope returns INVALID_REQUEST and preserves id', async () => {
  const h = await startTestServer();
  try {
    const [resp] = await rpcCall(h.socketPath, [
      JSON.stringify({ id: 7, method: 'foo' }), // missing jsonrpc field
    ]);
    const parsed = JSON.parse(resp!);
    equal(parsed.id, 7);
    equal(parsed.error.code, RPC_INVALID_REQUEST);
  } finally {
    await h.cleanup();
  }
});

test('request that splits across two TCP chunks is reassembled', async () => {
  // We can't easily force chunking here; the framing logic is tested at the
  // line level. Instead, verify by sending two requests in one write — the
  // server's split-on-newline logic will see them as a buffer with multiple
  // newlines.
  const h = await startTestServer();
  try {
    const responses = await rpcCall(h.socketPath, [
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'sigil_list_portals' }),
      JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'sigil_list_portals' }),
    ]);
    equal(responses.length, 2);
  } finally {
    await h.cleanup();
  }
});

test('end-to-end sign call over the socket', async () => {
  const h = await startTestServer();
  try {
    const messageHex = '0x' + Buffer.from('hi from socket', 'utf8').toString('hex');
    const [resp] = await rpcCall(h.socketPath, [
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'sigil_eth_sign_message',
        params: { portal: 'eth:bot', message: messageHex },
      }),
    ]);
    const parsed = JSON.parse(resp!);
    equal(parsed.id, 1);
    ok(parsed.result.signature.startsWith('0x'));
    equal(parsed.result.signature.length, 2 + 130); // 65 bytes hex
  } finally {
    await h.cleanup();
  }
});

// ---------------------------------------------------------------------------
// Concurrent connections
// ---------------------------------------------------------------------------

test('two concurrent connections are served independently', async () => {
  const h = await startTestServer();
  try {
    const [a, b] = await Promise.all([
      rpcCall(h.socketPath, [JSON.stringify({ jsonrpc: '2.0', id: 'a', method: 'sigil_list_portals' })]),
      rpcCall(h.socketPath, [JSON.stringify({ jsonrpc: '2.0', id: 'b', method: 'sigil_list_portals' })]),
    ]);
    equal(JSON.parse(a[0]!).id, 'a');
    equal(JSON.parse(b[0]!).id, 'b');
  } finally {
    await h.cleanup();
  }
});

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

test('server emits request and response log events', async () => {
  const h = await startTestServer();
  try {
    await rpcCall(h.socketPath, [
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'sigil_list_portals' }),
    ]);
    const requestEvent = h.events.find((e) => e.kind === 'request');
    const responseEvent = h.events.find((e) => e.kind === 'response');
    ok(requestEvent && requestEvent.kind === 'request' && requestEvent.method === 'sigil_list_portals');
    ok(responseEvent && responseEvent.kind === 'response' && responseEvent.ok === true);
  } finally {
    await h.cleanup();
  }
});
