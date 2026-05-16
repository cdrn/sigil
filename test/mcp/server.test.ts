import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { AuditWriter } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import { DaemonClient } from '../../src/daemon/client.js';
import { HandleTable } from '../../src/daemon/handles.js';
import { startDaemonServer, type DaemonServerHandle } from '../../src/daemon/server.js';
import {
  handleLine,
  MCP_INVALID_PARAMS,
  MCP_METHOD_NOT_FOUND,
  PROTOCOL_VERSION,
  runMcpStdio,
  SERVER_INFO,
} from '../../src/mcp/index.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmp(): string { return mkdtempSync(join(tmpdir(), 'sigil-mcp-')); }

interface H {
  dir: string;
  socketPath: string;
  server: DaemonServerHandle;
  handles: HandleTable;
  audit: AuditWriter;
  client: DaemonClient;
}

async function setUp(): Promise<H> {
  const dir = mkTmp();
  const socketPath = join(dir, 'sock');
  const handles = new HandleTable();
  handles.addEntry('eth:bot', new SecretBuffer(priv(1)));
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => ++now });
  const server = await startDaemonServer({ socketPath, context: { handles, audit } });
  const client = new DaemonClient(socketPath);
  await client.connect();
  return { dir, socketPath, server, handles, audit, client };
}

async function tearDown(h: H): Promise<void> {
  h.client.close();
  await h.server.close();
  h.audit.close();
  h.handles.dispose();
  rmSync(h.dir, { recursive: true });
}

// ---------------------------------------------------------------------------
// handleLine: protocol-level
// ---------------------------------------------------------------------------

test('handleLine: initialize returns capabilities + serverInfo', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
      { daemon: h.client },
    );
    const r = JSON.parse(resp!) as { result: { protocolVersion: string; serverInfo: { name: string } } };
    equal(r.result.protocolVersion, PROTOCOL_VERSION);
    equal(r.result.serverInfo.name, SERVER_INFO.name);
  } finally { await tearDown(h); }
});

test('handleLine: notifications/initialized has no response', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine(
      JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
      { daemon: h.client },
    );
    equal(resp, null);
  } finally { await tearDown(h); }
});

test('handleLine: tools/list returns all four tools with input schemas', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
      { daemon: h.client },
    );
    const r = JSON.parse(resp!) as { result: { tools: { name: string; inputSchema: object }[] } };
    const names = r.result.tools.map((t) => t.name).sort();
    deepEqual(names, [
      'sigil_eth_sign_message',
      'sigil_eth_sign_transaction',
      'sigil_eth_sign_typed_data',
      'sigil_list_portals',
    ]);
    for (const t of r.result.tools) {
      ok(t.inputSchema, `tool ${t.name} has no inputSchema`);
    }
  } finally { await tearDown(h); }
});

test('handleLine: tools/call sigil_list_portals returns content + structuredContent', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'sigil_list_portals', arguments: {} },
      }),
      { daemon: h.client },
    );
    const r = JSON.parse(resp!) as {
      result: {
        content: { type: string; text: string }[];
        structuredContent: { portals: { handle: string }[] };
      };
    };
    equal(r.result.content[0]!.type, 'text');
    const portals = JSON.parse(r.result.content[0]!.text) as { portals: { handle: string }[] };
    equal(portals.portals.length, 1);
    equal(r.result.structuredContent.portals[0]!.handle, 'eth:bot');
  } finally { await tearDown(h); }
});

test('handleLine: tools/call eth_sign_message succeeds end-to-end via the client', async () => {
  const h = await setUp();
  try {
    const messageHex = '0x' + Buffer.from('hello mcp').toString('hex');
    const resp = await handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 9, method: 'tools/call',
        params: { name: 'sigil_eth_sign_message', arguments: { portal: 'eth:bot', message: messageHex } },
      }),
      { daemon: h.client },
    );
    const r = JSON.parse(resp!) as {
      result: { structuredContent: { signature: string } };
    };
    ok(r.result.structuredContent.signature.startsWith('0x'));
    equal(r.result.structuredContent.signature.length, 2 + 130);
  } finally { await tearDown(h); }
});

test('handleLine: tools/call with unknown tool returns METHOD_NOT_FOUND', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'nonexistent_tool', arguments: {} },
      }),
      { daemon: h.client },
    );
    const r = JSON.parse(resp!) as { error: { code: number } };
    equal(r.error.code, MCP_METHOD_NOT_FOUND);
  } finally { await tearDown(h); }
});

test('handleLine: tools/call surfaces daemon error code (portal-not-found → -32000)', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: {
          name: 'sigil_eth_sign_message',
          arguments: { portal: 'eth:nope', message: '0xff' },
        },
      }),
      { daemon: h.client },
    );
    const r = JSON.parse(resp!) as { error: { code: number; message: string } };
    equal(r.error.code, -32000);
    ok(/portal/.test(r.error.message));
  } finally { await tearDown(h); }
});

test('handleLine: tools/call with non-object params → INVALID_PARAMS', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: 'oops',
      }),
      { daemon: h.client },
    );
    const r = JSON.parse(resp!) as { error: { code: number } };
    equal(r.error.code, MCP_INVALID_PARAMS);
  } finally { await tearDown(h); }
});

test('handleLine: unknown method (not tools/call) returns METHOD_NOT_FOUND', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'mystery_method' }),
      { daemon: h.client },
    );
    const r = JSON.parse(resp!) as { error: { code: number } };
    equal(r.error.code, MCP_METHOD_NOT_FOUND);
  } finally { await tearDown(h); }
});

test('handleLine: ping responds with empty object', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
      { daemon: h.client },
    );
    const r = JSON.parse(resp!) as { result: object };
    deepEqual(r.result, {});
  } finally { await tearDown(h); }
});

test('handleLine: malformed JSON returns PARSE_ERROR with id=null', async () => {
  const h = await setUp();
  try {
    const resp = await handleLine('{not json', { daemon: h.client });
    const r = JSON.parse(resp!) as { id: unknown; error: { code: number } };
    equal(r.id, null);
    equal(r.error.code, -32700);
  } finally { await tearDown(h); }
});

// ---------------------------------------------------------------------------
// runMcpStdio: end-to-end via streams
// ---------------------------------------------------------------------------

test('runMcpStdio: full handshake + tools/list + tools/call via in-memory streams', async () => {
  const h = await setUp();
  try {
    const messageHex = '0x' + Buffer.from('e2e via stdio').toString('hex');
    const input =
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }) + '\n' +
      JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n' +
      JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) + '\n' +
      JSON.stringify({
        jsonrpc: '2.0', id: 3, method: 'tools/call',
        params: { name: 'sigil_eth_sign_message', arguments: { portal: 'eth:bot', message: messageHex } },
      }) + '\n';

    const stdin = Readable.from([input]);
    const out: string[] = [];
    const stdout = new Writable({
      write(chunk, _enc, cb) { out.push(chunk.toString('utf8')); cb(); },
    });
    await runMcpStdio({ daemon: h.client, stdin, stdout });

    const lines = out.join('').split('\n').filter((l) => l.length > 0);
    // 3 responses: initialize, tools/list, tools/call (notification has no response)
    equal(lines.length, 3);
    const init = JSON.parse(lines[0]!) as { id: number; result: { protocolVersion: string } };
    equal(init.id, 1);
    equal(init.result.protocolVersion, PROTOCOL_VERSION);
    const list = JSON.parse(lines[1]!) as { id: number; result: { tools: unknown[] } };
    equal(list.id, 2);
    equal(list.result.tools.length, 4);
    const call = JSON.parse(lines[2]!) as { id: number; result: { structuredContent: { signature: string } } };
    equal(call.id, 3);
    ok(call.result.structuredContent.signature.startsWith('0x'));
  } finally { await tearDown(h); }
});
