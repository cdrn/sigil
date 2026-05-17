import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { AuditWriter } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import { HandleTable, type MethodContext } from '../../src/daemon/index.js';
import { permissivePolicyResolver } from '../../src/policy/index.js';
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
  ctx: MethodContext;
  handles: HandleTable;
  audit: AuditWriter;
}

function setUp(): H {
  const dir = mkTmp();
  const handles = new HandleTable();
  handles.addEntry('eth:bot', new SecretBuffer(priv(1)));
  handles.markUnlocked();
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => ++now });
  return { dir, ctx: { handles, audit, policy: permissivePolicyResolver() }, handles, audit };
}

function tearDown(h: H): void {
  h.audit.close();
  h.handles.dispose();
  rmSync(h.dir, { recursive: true });
}

// ---------------------------------------------------------------------------
// handleLine
// ---------------------------------------------------------------------------

test('handleLine: initialize returns capabilities + serverInfo', () => {
  const h = setUp();
  try {
    const resp = handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
      { context: h.ctx },
    );
    const r = JSON.parse(resp!) as { result: { protocolVersion: string; serverInfo: { name: string } } };
    equal(r.result.protocolVersion, PROTOCOL_VERSION);
    equal(r.result.serverInfo.name, SERVER_INFO.name);
  } finally { tearDown(h); }
});

test('handleLine: notifications/initialized has no response', () => {
  const h = setUp();
  try {
    const resp = handleLine(
      JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
      { context: h.ctx },
    );
    equal(resp, null);
  } finally { tearDown(h); }
});

test('handleLine: tools/list returns all four tools with input schemas', () => {
  const h = setUp();
  try {
    const resp = handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
      { context: h.ctx },
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
  } finally { tearDown(h); }
});

test('handleLine: tools/call sigil_list_portals returns content + structuredContent', () => {
  const h = setUp();
  try {
    const resp = handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'sigil_list_portals', arguments: {} },
      }),
      { context: h.ctx },
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
  } finally { tearDown(h); }
});

test('handleLine: tools/call eth_sign_message succeeds end-to-end in-process', () => {
  const h = setUp();
  try {
    const messageHex = '0x' + Buffer.from('hello mcp').toString('hex');
    const resp = handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 9, method: 'tools/call',
        params: { name: 'sigil_eth_sign_message', arguments: { portal: 'eth:bot', message: messageHex } },
      }),
      { context: h.ctx },
    );
    const r = JSON.parse(resp!) as {
      result: { structuredContent: { signature: string } };
    };
    ok(r.result.structuredContent.signature.startsWith('0x'));
    equal(r.result.structuredContent.signature.length, 2 + 130);
  } finally { tearDown(h); }
});

test('handleLine: tools/call with unknown tool returns METHOD_NOT_FOUND', () => {
  const h = setUp();
  try {
    const resp = handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: { name: 'nonexistent_tool', arguments: {} },
      }),
      { context: h.ctx },
    );
    const r = JSON.parse(resp!) as { error: { code: number } };
    equal(r.error.code, MCP_METHOD_NOT_FOUND);
  } finally { tearDown(h); }
});

test('handleLine: tools/call surfaces method error code (portal-not-found → -32000)', () => {
  const h = setUp();
  try {
    const resp = handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: {
          name: 'sigil_eth_sign_message',
          arguments: { portal: 'eth:nope', message: '0xff' },
        },
      }),
      { context: h.ctx },
    );
    const r = JSON.parse(resp!) as { error: { code: number; message: string } };
    equal(r.error.code, -32000);
    ok(/portal/.test(r.error.message));
  } finally { tearDown(h); }
});

test('handleLine: tools/call with non-object params → INVALID_PARAMS', () => {
  const h = setUp();
  try {
    const resp = handleLine(
      JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'tools/call',
        params: 'oops',
      }),
      { context: h.ctx },
    );
    const r = JSON.parse(resp!) as { error: { code: number } };
    equal(r.error.code, MCP_INVALID_PARAMS);
  } finally { tearDown(h); }
});

test('handleLine: unknown method (not tools/call) returns METHOD_NOT_FOUND', () => {
  const h = setUp();
  try {
    const resp = handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'mystery_method' }),
      { context: h.ctx },
    );
    const r = JSON.parse(resp!) as { error: { code: number } };
    equal(r.error.code, MCP_METHOD_NOT_FOUND);
  } finally { tearDown(h); }
});

test('handleLine: ping responds with empty object', () => {
  const h = setUp();
  try {
    const resp = handleLine(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
      { context: h.ctx },
    );
    const r = JSON.parse(resp!) as { result: object };
    deepEqual(r.result, {});
  } finally { tearDown(h); }
});

test('handleLine: malformed JSON returns PARSE_ERROR with id=null', () => {
  const h = setUp();
  try {
    const resp = handleLine('{not json', { context: h.ctx });
    const r = JSON.parse(resp!) as { id: unknown; error: { code: number } };
    equal(r.id, null);
    equal(r.error.code, -32700);
  } finally { tearDown(h); }
});

// ---------------------------------------------------------------------------
// runMcpStdio: end-to-end via streams
// ---------------------------------------------------------------------------

test('runMcpStdio: full handshake + tools/list + tools/call via in-memory streams', async () => {
  const h = setUp();
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
    await runMcpStdio({ context: h.ctx, stdin, stdout });

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
  } finally { tearDown(h); }
});
