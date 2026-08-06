import { test } from 'node:test';
import { equal, ok, rejects } from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import { HandleTable, type MethodContext } from '../../src/daemon/index.js';
import { permissivePolicyResolver } from '../../src/policy/index.js';
import { findTool, MCP_INVALID_PARAMS, ToolError, TOOLS } from '../../src/mcp/index.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmp(): string { return mkdtempSync(join(tmpdir(), 'sigil-tools-')); }

interface H {
  dir: string;
  ctx: MethodContext;
  handles: HandleTable;
  audit: AuditWriter;
}

function setUp(): H {
  const dir = mkTmp();
  const handles = new HandleTable();
  handles.addEntry('evm:bot', new SecretBuffer(priv(1)));
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

test('TOOLS lists exactly the six sigil tools', () => {
  equal(TOOLS.length, 6);
  const names = TOOLS.map((t) => t.definition.name).sort();
  equal(JSON.stringify(names), JSON.stringify([
    'sigil_eth_sign_message',
    'sigil_eth_sign_transaction',
    'sigil_eth_sign_typed_data',
    'sigil_list_portals',
    'sigil_pay',
    'sigil_pay_discover',
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

test('sigil_list_portals handler returns method result as text + structuredContent', async () => {
  const h = setUp();
  try {
    const tool = findTool('sigil_list_portals')!;
    const result = await tool.handler({}, h.ctx);
    equal(result.content[0]!.type, 'text');
    const parsed = JSON.parse(result.content[0]!.text) as { portals: unknown[] };
    equal(parsed.portals.length, 1);
    ok(result.structuredContent, 'structuredContent should be present');
  } finally { tearDown(h); }
});

test('sigil_eth_sign_message handler forwards args + returns a signature', async () => {
  const h = setUp();
  try {
    const tool = findTool('sigil_eth_sign_message')!;
    const messageHex = '0x' + Buffer.from('hi').toString('hex');
    const result = await tool.handler({ portal: 'evm:bot', message: messageHex }, h.ctx);
    const sc = result.structuredContent as { signature: string };
    ok(sc.signature.startsWith('0x'));
  } finally { tearDown(h); }
});

test('handler raises ToolError(INVALID_PARAMS) on non-object args', async () => {
  const h = setUp();
  try {
    const tool = findTool('sigil_eth_sign_message')!;
    await rejects(() => tool.handler('oops', h.ctx), ToolError);
    await rejects(() => tool.handler(null, h.ctx), ToolError);
    let caught: ToolError | null = null;
    try { await tool.handler([1, 2], h.ctx); }
    catch (e) { caught = e as ToolError; }
    ok(caught instanceof ToolError);
    equal(caught!.code, MCP_INVALID_PARAMS);
  } finally { tearDown(h); }
});

test('handler surfaces method error code unchanged (PORTAL_NOT_FOUND → ToolError(-32000))', async () => {
  const h = setUp();
  try {
    const tool = findTool('sigil_eth_sign_message')!;
    let caught: ToolError | null = null;
    try { await tool.handler({ portal: 'evm:nope', message: '0xff' }, h.ctx); }
    catch (e) { caught = e as ToolError; }
    ok(caught instanceof ToolError);
    equal(caught!.code, -32000);
  } finally { tearDown(h); }
});
