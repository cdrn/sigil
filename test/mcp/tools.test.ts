import { test } from 'node:test';
import { equal, ok, rejects } from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import { DaemonClient } from '../../src/daemon/client.js';
import { HandleTable } from '../../src/daemon/handles.js';
import { startDaemonServer, type DaemonServerHandle } from '../../src/daemon/server.js';
import { findTool, MCP_INVALID_PARAMS, ToolError, TOOLS } from '../../src/mcp/index.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmp(): string { return mkdtempSync(join(tmpdir(), 'sigil-tools-')); }

interface H {
  dir: string;
  client: DaemonClient;
  server: DaemonServerHandle;
  handles: HandleTable;
  audit: AuditWriter;
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
  return { dir, client, server, handles, audit };
}

async function tearDown(h: H): Promise<void> {
  h.client.close();
  await h.server.close();
  h.audit.close();
  h.handles.dispose();
  rmSync(h.dir, { recursive: true });
}

test('TOOLS lists exactly the four sigil tools', () => {
  equal(TOOLS.length, 4);
  const names = TOOLS.map((t) => t.definition.name).sort();
  equal(JSON.stringify(names), JSON.stringify([
    'sigil_eth_sign_message',
    'sigil_eth_sign_transaction',
    'sigil_eth_sign_typed_data',
    'sigil_list_portals',
  ]));
});

test('every tool has a description and input schema', () => {
  for (const t of TOOLS) {
    ok(t.definition.description.length > 10, `${t.definition.name} description too short`);
    equal(t.definition.inputSchema.type, 'object');
  }
});

test('input schemas declare required fields where appropriate', () => {
  const sign = findTool('sigil_eth_sign_message')!;
  equal(JSON.stringify(sign.definition.inputSchema.required?.sort()), JSON.stringify(['message', 'portal']));
  const tx = findTool('sigil_eth_sign_transaction')!;
  equal(JSON.stringify(tx.definition.inputSchema.required?.sort()), JSON.stringify(['portal', 'tx']));
});

test('sigil_list_portals handler returns daemon result as text + structuredContent', async () => {
  const h = await setUp();
  try {
    const tool = findTool('sigil_list_portals')!;
    const result = await tool.handler({}, { daemon: h.client });
    equal(result.content[0]!.type, 'text');
    const parsed = JSON.parse(result.content[0]!.text) as { portals: unknown[] };
    equal(parsed.portals.length, 1);
    ok(result.structuredContent, 'structuredContent should be present');
  } finally { await tearDown(h); }
});

test('sigil_eth_sign_message handler forwards args + returns a signature', async () => {
  const h = await setUp();
  try {
    const tool = findTool('sigil_eth_sign_message')!;
    const messageHex = '0x' + Buffer.from('hi').toString('hex');
    const result = await tool.handler({ portal: 'eth:bot', message: messageHex }, { daemon: h.client });
    const sc = result.structuredContent as { signature: string };
    ok(sc.signature.startsWith('0x'));
  } finally { await tearDown(h); }
});

test('handler raises ToolError(INVALID_PARAMS) on non-object args', async () => {
  const h = await setUp();
  try {
    const tool = findTool('sigil_eth_sign_message')!;
    await rejects(() => tool.handler('oops', { daemon: h.client }), ToolError);
    await rejects(() => tool.handler(null, { daemon: h.client }), ToolError);
    let caught: ToolError | null = null;
    try { await tool.handler([1, 2], { daemon: h.client }); }
    catch (e) { caught = e as ToolError; }
    ok(caught instanceof ToolError);
    equal(caught!.code, MCP_INVALID_PARAMS);
  } finally { await tearDown(h); }
});

test('handler surfaces daemon error code unchanged (PORTAL_NOT_FOUND → ToolError(-32000))', async () => {
  const h = await setUp();
  try {
    const tool = findTool('sigil_eth_sign_message')!;
    let caught: ToolError | null = null;
    try { await tool.handler({ portal: 'eth:nope', message: '0xff' }, { daemon: h.client }); }
    catch (e) { caught = e as ToolError; }
    ok(caught instanceof ToolError);
    equal(caught!.code, -32000);
  } finally { await tearDown(h); }
});
