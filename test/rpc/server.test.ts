import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter, verifyChain } from '../../src/audit/index.js';
import {
  ConfirmGate,
  startAckServer,
  type ConfirmRequest,
  type ConfirmTransport,
} from '../../src/confirm/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import { HandleTable, type MethodContext } from '../../src/daemon/index.js';
import {
  addressFromPrivateKey,
  addressFromPublicKey,
  recoverPublicKey,
  rlpDecode,
  txDigest,
  type Eip1559Tx,
} from '../../src/eth/index.js';
import {
  parsePolicy,
  permissivePolicyResolver,
  type PolicyResolver,
} from '../../src/policy/index.js';
import {
  startRpcServer,
  UpstreamRpcError,
  type JsonRpcUpstream,
  type RpcProxyServer,
} from '../../src/rpc/index.js';

const TOKEN = 'test-token-0123456789abcdef';
const PRIV = (() => {
  const b = Buffer.alloc(32);
  b[31] = 1;
  return b;
})();
const ADDR = addressFromPrivateKey(PRIV); // 0x7e5f...bdf
const DEST = '0x000000000000000000000000000000000000dead';
const GWEI = '0x3b9aca00';
const TX_HASH = '0x' + 'ab'.repeat(32);

class FakeUpstream implements JsonRpcUpstream {
  calls: { method: string; params: unknown[] }[] = [];
  responses = new Map<string, unknown>();
  async call(method: string, params: readonly unknown[]): Promise<unknown> {
    this.calls.push({ method, params: [...params] });
    if (!this.responses.has(method)) {
      throw new UpstreamRpcError(-32601, `unscripted method: ${method}`);
    }
    const r = this.responses.get(method);
    if (r instanceof Error) throw r;
    return r;
  }
}

function scriptedUpstream(): FakeUpstream {
  const up = new FakeUpstream();
  up.responses.set('eth_chainId', '0x1');
  up.responses.set('eth_getTransactionCount', '0x0');
  up.responses.set('eth_estimateGas', '0x5208');
  up.responses.set('eth_getBlockByNumber', { baseFeePerGas: GWEI });
  up.responses.set('eth_maxPriorityFeePerGas', GWEI);
  up.responses.set('eth_sendRawTransaction', TX_HASH);
  return up;
}

class ScriptedTransport implements ConfirmTransport {
  readonly name = 'scripted';
  captured: ConfirmRequest | undefined;
  async send(req: ConfirmRequest): Promise<void> {
    this.captured = req;
  }
}

interface Harness {
  server: RpcProxyServer;
  upstream: FakeUpstream;
  ctx: MethodContext;
  auditPath: string;
  transport: ScriptedTransport;
  cleanup: () => Promise<void>;
}

async function makeHarness(
  opts: {
    policy?: PolicyResolver;
    locked?: boolean;
    confirm?: boolean;
  } = {},
): Promise<Harness> {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-rpc-'));
  const auditPath = join(dir, 'audit.log');
  const handles = new HandleTable();
  handles.addEntry('evm:bot', new SecretBuffer(Buffer.from(PRIV)));
  if (!opts.locked) handles.markUnlocked();
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(auditPath, { now: () => ++now });
  const transport = new ScriptedTransport();
  const ack = opts.confirm ? await startAckServer() : undefined;
  const ctx: MethodContext = {
    handles,
    audit,
    policy: opts.policy ?? permissivePolicyResolver(),
    ...(ack ? { confirm: new ConfirmGate({ transport, ackServer: ack, timeoutMs: 2000 }) } : {}),
  };
  const upstream = scriptedUpstream();
  const server = await startRpcServer({
    config: { portal: 'evm:bot', upstream: 'http://unused.invalid', token: TOKEN },
    ctx,
    upstream,
    port: 0,
  });
  return {
    server,
    upstream,
    ctx,
    auditPath,
    transport,
    cleanup: async () => {
      await server.close();
      if (ack) await ack.close();
      audit.close();
      handles.dispose();
      rmSync(dir, { recursive: true });
    },
  };
}

type RpcResponse = {
  jsonrpc: string;
  id: unknown;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};

async function rpc(
  server: RpcProxyServer,
  method: string,
  params: unknown[] = [],
  opts: { auth?: 'bearer' | 'basic' | 'none' | 'wrong'; id?: number } = {},
): Promise<RpcResponse> {
  const res = await rawPost(
    server,
    JSON.stringify({
      jsonrpc: '2.0',
      id: opts.id ?? 1,
      method,
      params,
    }),
    opts,
  );
  equal(res.status, 200, `expected 200, got ${res.status}: ${res.body}`);
  return JSON.parse(res.body) as RpcResponse;
}

function authHeader(auth: 'bearer' | 'basic' | 'none' | 'wrong'): Record<string, string> {
  switch (auth) {
    case 'bearer':
      return { authorization: `Bearer ${TOKEN}` };
    case 'basic':
      return { authorization: `Basic ${Buffer.from(`sigil:${TOKEN}`).toString('base64')}` };
    case 'wrong':
      return { authorization: 'Bearer nope-nope-nope-nope' };
    case 'none':
      return {};
  }
}

/** Raw HTTP POST with full header control (fetch won't let us fake Host). */
function rawPost(
  server: RpcProxyServer,
  body: string,
  opts: { auth?: 'bearer' | 'basic' | 'none' | 'wrong'; host?: string; method?: string } = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: server.port,
        path: '/',
        method: opts.method ?? 'POST',
        headers: {
          'content-type': 'application/json',
          ...(opts.host !== undefined ? { host: opts.host } : {}),
          ...authHeader(opts.auth ?? 'bearer'),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

async function waitFor(cond: () => boolean, ms = 1000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error('waitFor timed out');
    await new Promise((r) => setTimeout(r, 5));
  }
}

// ---------------------------------------------------------------------------
// auth + transport hardening
// ---------------------------------------------------------------------------

test('rpc: requests without the token are 401 and never reach routing', async () => {
  const h = await makeHarness();
  try {
    for (const auth of ['none', 'wrong'] as const) {
      const res = await rawPost(h.server, '{"jsonrpc":"2.0","id":1,"method":"eth_accounts"}', {
        auth,
      });
      equal(res.status, 401);
    }
    deepEqual(h.upstream.calls, []);
  } finally {
    await h.cleanup();
  }
});

test('rpc: token is accepted via Bearer and via the Basic password half', async () => {
  const h = await makeHarness();
  try {
    for (const auth of ['bearer', 'basic'] as const) {
      const res = await rpc(h.server, 'eth_accounts', [], { auth });
      deepEqual(res.result, [ADDR]);
    }
  } finally {
    await h.cleanup();
  }
});

test('rpc: an unauthenticated eth_sendTransaction never reaches fill, sign, or audit', async () => {
  const h = await makeHarness();
  try {
    const res = await rawPost(
      h.server,
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_sendTransaction',
        params: [{ from: ADDR, to: DEST }],
      }),
      { auth: 'none' },
    );
    equal(res.status, 401);
    deepEqual(h.upstream.calls, [], 'no upstream call may happen pre-auth');
    equal(h.ctx.audit.head.nextSeq, 0, 'no audit entry may be written pre-auth');
  } finally {
    await h.cleanup();
  }
});

test('rpc: non-loopback Host header is rejected (DNS rebinding)', async () => {
  const h = await makeHarness();
  try {
    // Straight rebinding host, and the loopback-lookalike subdomain trick.
    for (const host of [
      'evil.example.com',
      '127.0.0.1.evil.example.com',
      'localhost.evil.example.com',
    ]) {
      const res = await rawPost(h.server, '{"jsonrpc":"2.0","id":1,"method":"eth_accounts"}', {
        host,
      });
      equal(res.status, 403, host);
    }
    // Loopback spellings all pass.
    for (const host of [
      `127.0.0.1:${h.server.port}`,
      `localhost:${h.server.port}`,
      `[::1]:${h.server.port}`,
    ]) {
      const okRes = await rawPost(h.server, '{"jsonrpc":"2.0","id":1,"method":"eth_accounts"}', {
        host,
      });
      equal(okRes.status, 200, host);
    }
  } finally {
    await h.cleanup();
  }
});

test('rpc: non-POST is 405; invalid JSON is -32700', async () => {
  const h = await makeHarness();
  try {
    const get = await rawPost(h.server, '', { method: 'GET' });
    equal(get.status, 405);
    const bad = await rawPost(h.server, 'not json');
    equal(bad.status, 200);
    equal((JSON.parse(bad.body) as RpcResponse).error!.code, -32700);
  } finally {
    await h.cleanup();
  }
});

// ---------------------------------------------------------------------------
// account + proxy methods
// ---------------------------------------------------------------------------

test('rpc: eth_accounts returns the portal address; empty while locked', async () => {
  const h = await makeHarness();
  try {
    deepEqual((await rpc(h.server, 'eth_accounts')).result, [ADDR]);
    deepEqual((await rpc(h.server, 'eth_requestAccounts')).result, [ADDR]);
  } finally {
    await h.cleanup();
  }
  const locked = await makeHarness({ locked: true });
  try {
    deepEqual((await rpc(locked.server, 'eth_accounts')).result, []);
  } finally {
    await locked.cleanup();
  }
});

test('rpc: unknown methods are proxied verbatim; upstream errors pass through with data', async () => {
  const h = await makeHarness();
  try {
    h.upstream.responses.set('eth_blockNumber', '0x10');
    equal((await rpc(h.server, 'eth_blockNumber')).result, '0x10');
    deepEqual(h.upstream.calls.at(-1), { method: 'eth_blockNumber', params: [] });

    h.upstream.responses.set(
      'eth_call',
      new UpstreamRpcError(3, 'execution reverted', '0x08c379a0'),
    );
    const err = (await rpc(h.server, 'eth_call', [{ to: DEST }, 'latest'])).error!;
    equal(err.code, 3);
    equal(err.message, 'execution reverted');
    equal(err.data, '0x08c379a0');
  } finally {
    await h.cleanup();
  }
});

test('rpc: message/typed-data signing methods are rejected, not proxied', async () => {
  const h = await makeHarness();
  try {
    for (const method of ['eth_sign', 'personal_sign', 'eth_signTypedData_v4']) {
      const res = await rpc(h.server, method, []);
      equal(res.error!.code, -32601);
      ok(/MCP tools/.test(res.error!.message), res.error!.message);
    }
    deepEqual(h.upstream.calls, []);
  } finally {
    await h.cleanup();
  }
});

test('rpc: batch requests are answered per-entry with matching ids', async () => {
  const h = await makeHarness();
  try {
    h.upstream.responses.set('eth_blockNumber', '0x10');
    const res = await rawPost(
      h.server,
      JSON.stringify([
        { jsonrpc: '2.0', id: 7, method: 'eth_accounts', params: [] },
        { jsonrpc: '2.0', id: 8, method: 'eth_blockNumber', params: [] },
      ]),
    );
    const parsed = JSON.parse(res.body) as RpcResponse[];
    equal(parsed.length, 2);
    deepEqual(parsed.find((r) => r.id === 7)!.result, [ADDR]);
    equal(parsed.find((r) => r.id === 8)!.result, '0x10');
  } finally {
    await h.cleanup();
  }
});

// ---------------------------------------------------------------------------
// eth_sendTransaction / eth_signTransaction
// ---------------------------------------------------------------------------

test('rpc: eth_sendTransaction fills, signs, broadcasts — raw tx recovers to the portal', async () => {
  const h = await makeHarness();
  try {
    const res = await rpc(h.server, 'eth_sendTransaction', [
      { from: ADDR, to: DEST, value: '0x64' },
    ]);
    equal(res.result, TX_HASH);

    const broadcast = h.upstream.calls.find((c) => c.method === 'eth_sendRawTransaction')!;
    const raw = broadcast.params[0] as string;
    ok(raw.startsWith('0x02'));
    const decoded = rlpDecode(Buffer.from(raw.slice(4), 'hex'));
    if (!Array.isArray(decoded)) throw new Error('expected list');
    const yParityBuf = decoded[9] as Buffer;
    const txForDigest: Eip1559Tx = {
      type: 'eip1559',
      chainId: 1,
      nonce: 0,
      maxPriorityFeePerGas: 1_000_000_000n,
      maxFeePerGas: 3_000_000_000n, // 2 × 1 gwei base + tip
      gasLimit: 25_200n, // 21000 × 1.2
      to: DEST,
      value: 100n,
      data: '0x',
    };
    const pub = recoverPublicKey(txDigest(txForDigest), {
      r: decoded[10] as Buffer,
      s: decoded[11] as Buffer,
      recovery: (yParityBuf.length === 0 ? 0 : yParityBuf[0]!) as 0 | 1,
    });
    equal(addressFromPublicKey(pub), ADDR);

    // The sign went through the daemon pipeline: audit has the allow.
    h.ctx.audit.close();
    const entries = verifyChain(readFileSync(h.auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.kind, 'eth_sign_transaction');
    equal(entries[0]!.portal, 'evm:bot');
    equal(entries[0]!.decision, 'allow');
    equal(entries[0]!.sig, raw);
  } finally {
    await h.cleanup();
  }
});

test('rpc: eth_signTransaction returns the raw tx without broadcasting', async () => {
  const h = await makeHarness();
  try {
    const res = await rpc(h.server, 'eth_signTransaction', [
      {
        from: ADDR,
        to: DEST,
        nonce: '0x0',
        gas: '0x5208',
        maxFeePerGas: GWEI,
        maxPriorityFeePerGas: GWEI,
      },
    ]);
    ok((res.result as string).startsWith('0x02'));
    equal(
      h.upstream.calls.some((c) => c.method === 'eth_sendRawTransaction'),
      false,
    );
  } finally {
    await h.cleanup();
  }
});

test('rpc: from that is not the portal address is rejected before signing', async () => {
  const h = await makeHarness();
  try {
    const res = await rpc(h.server, 'eth_sendTransaction', [{ from: DEST, to: DEST }]);
    equal(res.error!.code, -32602);
    ok(/unknown account/.test(res.error!.message));
    equal(
      h.upstream.calls.some((c) => c.method === 'eth_sendRawTransaction'),
      false,
    );
  } finally {
    await h.cleanup();
  }
});

test('rpc: signing while locked is a JSON-RPC error, not a signature', async () => {
  const h = await makeHarness({ locked: true });
  try {
    const res = await rpc(h.server, 'eth_sendTransaction', [{ from: ADDR, to: DEST }]);
    equal(res.error!.code, -32003);
    ok(/sigil unlock/.test(res.error!.message));
    deepEqual(h.upstream.calls, []);
  } finally {
    await h.cleanup();
  }
});

// ---------------------------------------------------------------------------
// policy + confirm integration (the same pipeline as the MCP tools)
// ---------------------------------------------------------------------------

function strictResolver(toml: string): PolicyResolver {
  const p = parsePolicy(toml);
  return { resolve: () => p };
}

test('rpc: strict policy deny surfaces as -32001 and nothing is broadcast', async () => {
  const h = await makeHarness({
    policy: strictResolver(`
      mode = "strict"
      chain_ids = [1]
      allow_to = []
    `),
  });
  try {
    const res = await rpc(h.server, 'eth_sendTransaction', [
      {
        from: ADDR,
        to: DEST,
        nonce: '0x0',
        gas: '0x5208',
        maxFeePerGas: GWEI,
        maxPriorityFeePerGas: GWEI,
      },
    ]);
    equal(res.error!.code, -32001);
    ok(/not in allow_to/.test(res.error!.message));
    equal(
      h.upstream.calls.some((c) => c.method === 'eth_sendRawTransaction'),
      false,
    );

    // Audit recorded the deny.
    h.ctx.audit.close();
    const entries = verifyChain(readFileSync(h.auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.decision, 'deny');
  } finally {
    await h.cleanup();
  }
});

test('rpc: policy chain check runs against the UPSTREAM chain id', async () => {
  // Policy allows chain 1 only; upstream reports chain 137. The filled tx
  // carries the upstream's chain id, so strict policy denies it.
  const h = await makeHarness({
    policy: strictResolver(`
      mode = "strict"
      chain_ids = [1]
      allow_to = ["${DEST}"]
    `),
  });
  try {
    h.upstream.responses.set('eth_chainId', '0x89');
    const res = await rpc(h.server, 'eth_sendTransaction', [
      {
        from: ADDR,
        to: DEST,
        nonce: '0x0',
        gas: '0x5208',
        maxFeePerGas: GWEI,
        maxPriorityFeePerGas: GWEI,
      },
    ]);
    equal(res.error!.code, -32001);
    ok(/chain 137 not in/.test(res.error!.message));
  } finally {
    await h.cleanup();
  }
});

const DEPLOY_POLICY = `
  mode = "strict"
  chain_ids = [1]
  allow_contract_creation = true
`;
const INITCODE = '0x6080604052600080fd';

test('rpc: confirm-gated deploy — approve tap signs and broadcasts', async () => {
  const h = await makeHarness({ policy: strictResolver(DEPLOY_POLICY), confirm: true });
  try {
    const pendingRes = rpc(h.server, 'eth_sendTransaction', [
      {
        from: ADDR,
        data: INITCODE,
        nonce: '0x0',
        gas: '0x2dc6c0',
        maxFeePerGas: GWEI,
        maxPriorityFeePerGas: GWEI,
      },
    ]);
    await waitFor(() => h.transport.captured !== undefined);
    ok(/contract creation/.test(h.transport.captured!.summary), h.transport.captured!.summary);
    ok(/9-byte initcode/.test(h.transport.captured!.summary), h.transport.captured!.summary);
    await fetch(h.transport.captured!.approveUrl, { method: 'POST' });
    const res = await pendingRes;
    equal(res.result, TX_HASH);
    const broadcast = h.upstream.calls.find((c) => c.method === 'eth_sendRawTransaction')!;
    // Creation tx: `to` RLP-encodes empty.
    const decoded = rlpDecode(Buffer.from((broadcast.params[0] as string).slice(4), 'hex'));
    if (!Array.isArray(decoded)) throw new Error('expected list');
    equal((decoded[5] as Buffer).length, 0);
  } finally {
    await h.cleanup();
  }
});

test('rpc: confirm-gated deploy — deny tap is -32001 and nothing is broadcast', async () => {
  const h = await makeHarness({ policy: strictResolver(DEPLOY_POLICY), confirm: true });
  try {
    const pendingRes = rpc(h.server, 'eth_sendTransaction', [
      {
        from: ADDR,
        data: INITCODE,
        nonce: '0x0',
        gas: '0x2dc6c0',
        maxFeePerGas: GWEI,
        maxPriorityFeePerGas: GWEI,
      },
    ]);
    await waitFor(() => h.transport.captured !== undefined);
    await fetch(h.transport.captured!.denyUrl, { method: 'POST' });
    const res = await pendingRes;
    equal(res.error!.code, -32001);
    ok(/confirm denied by human/.test(res.error!.message));
    equal(
      h.upstream.calls.some((c) => c.method === 'eth_sendRawTransaction'),
      false,
    );
  } finally {
    await h.cleanup();
  }
});

test('rpc: confirm-required deploy with no transport configured fails closed', async () => {
  const h = await makeHarness({ policy: strictResolver(DEPLOY_POLICY) }); // no confirm gate
  try {
    const res = await rpc(h.server, 'eth_sendTransaction', [
      {
        from: ADDR,
        data: INITCODE,
        nonce: '0x0',
        gas: '0x2dc6c0',
        maxFeePerGas: GWEI,
        maxPriorityFeePerGas: GWEI,
      },
    ]);
    equal(res.error!.code, -32001);
    ok(/no confirm transport is configured/.test(res.error!.message));
    equal(
      h.upstream.calls.some((c) => c.method === 'eth_sendRawTransaction'),
      false,
    );
  } finally {
    await h.cleanup();
  }
});
