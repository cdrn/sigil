import { test } from 'node:test';
import { equal, ok, rejects } from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import {
  dispatch,
  HandleTable,
  type MethodContext,
  RPC_POLICY_DENIED,
  RpcMethodError,
} from '../../src/daemon/index.js';
import type { FetchLike } from '../../src/pay/index.js';
import { parsePolicy, permissivePolicyResolver, type PolicyResolver } from '../../src/policy/index.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }

const TOKEN = '0x20c0000000000000000000000000000000000000';
const RECIPIENT = '0xaB782182720864538E26bC424460d96ff364F94C';

function mppHeader(): string {
  const request = Buffer.from(
    JSON.stringify({
      amount: '10000',
      currency: TOKEN,
      recipient: RECIPIENT,
      methodDetails: { chainId: 42431, feePayer: true },
    }),
  ).toString('base64url');
  return `Payment id="ch1", realm="api.test", method="tempo", intent="charge", expires="2030-01-01T00:00:00Z", request="${request}"`;
}

function boutiqueFetch(calls: { url: string; init: RequestInit }[]): FetchLike {
  return async (url, init) => {
    calls.push({ url, init: init ?? {} });
    if (calls.length === 1) {
      return new Response('{"title":"Payment Required"}', {
        status: 402,
        headers: { 'www-authenticate': mppHeader() },
      });
    }
    const receipt = Buffer.from(
      JSON.stringify({ status: 'success', method: 'tempo', reference: '0xsettled' }),
    ).toString('base64url');
    return new Response('{"item":"Tempo Hat","status":"paid"}', {
      status: 201,
      headers: { 'payment-receipt': receipt },
    });
  };
}

interface H {
  dir: string;
  ctx: MethodContext;
  handles: HandleTable;
  audit: AuditWriter;
}

function setUp(policy: PolicyResolver, fetchImpl: FetchLike): H {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-pay-'));
  const handles = new HandleTable();
  handles.addEntry('evm:bot', new SecretBuffer(priv(1)));
  handles.markUnlocked();
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => ++now });
  const ctx: MethodContext = {
    handles,
    audit,
    policy,
    fetchImpl,
    now: () => Date.parse('2029-12-31T23:59:00Z'),
  };
  return { dir, ctx, handles, audit };
}

function tearDown(h: H): void {
  h.audit.close();
  h.handles.dispose();
  rmSync(h.dir, { recursive: true });
}

test('sigil_pay pays a tempo challenge end to end and audits it', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const h = setUp(permissivePolicyResolver(), boutiqueFetch(calls));
  try {
    const result = (await dispatch(
      'sigil_pay',
      { portal: 'evm:bot', url: 'https://api.test/buy', method: 'POST', body: '{"name":"x"}' },
      h.ctx,
    )) as {
      status: number;
      paid: boolean;
      payment: { protocol: string; amount: string; origin: string };
      receipt: { reference: string };
    };
    equal(result.status, 201);
    equal(result.paid, true);
    equal(result.payment.protocol, 'mpp');
    equal(result.payment.amount, '10000');
    equal(result.receipt.reference, '0xsettled');
    equal(calls.length, 2);

    const headers = calls[1]!.init.headers as Record<string, string>;
    ok(headers['authorization']!.startsWith('Payment '));
  } finally {
    tearDown(h);
  }
});

test('sigil_pay denies via strict policy before any credential is built', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const strictResolver: PolicyResolver = {
    resolve: () =>
      parsePolicy(`
mode = "strict"
chain_ids = [42431]
pay_origins = ["https://other.test"]
pay_max_amount = "100000"
`),
  };
  const h = setUp(strictResolver, boutiqueFetch(calls));
  try {
    await rejects(
      () => dispatch('sigil_pay', { portal: 'evm:bot', url: 'https://api.test/buy' }, h.ctx),
      (err: unknown) =>
        err instanceof RpcMethodError &&
        err.code === RPC_POLICY_DENIED &&
        err.message.includes('pay_origins'),
    );
    equal(calls.length, 1, 'the paid retry must never fire on deny');
  } finally {
    tearDown(h);
  }
});

test('sigil_pay passes through non-402 responses without touching keys', async () => {
  const fetchImpl: FetchLike = async () => new Response('free!', { status: 200 });
  const h = setUp(permissivePolicyResolver(), fetchImpl);
  try {
    const result = (await dispatch(
      'sigil_pay',
      { portal: 'evm:bot', url: 'https://api.test/free' },
      h.ctx,
    )) as { status: number; paid: boolean; bodyPreview: string };
    equal(result.status, 200);
    equal(result.paid, false);
    equal(result.bodyPreview, 'free!');
  } finally {
    tearDown(h);
  }
});

test('sigil_pay_discover filters merged registry listings', async () => {
  const fetchImpl: FetchLike = async (url) => {
    if (url.startsWith('https://mpp.dev')) {
      return new Response(
        JSON.stringify({
          services: [
            { name: 'Boutique', url: 'https://mpp.boutique', description: 'demo shop' },
            { name: 'Other', url: 'https://other.test' },
          ],
        }),
        { status: 200 },
      );
    }
    return new Response(
      JSON.stringify({
        items: [
          {
            resource: 'https://api.x402.test/data',
            accepts: [{ amount: '100', asset: TOKEN, network: 'eip155:8453' }],
          },
        ],
      }),
      { status: 200 },
    );
  };
  const h = setUp(permissivePolicyResolver(), fetchImpl);
  try {
    const all = (await dispatch('sigil_pay_discover', {}, h.ctx)) as {
      services: { registry: string; url: string }[];
    };
    equal(all.services.length, 3);
    const filtered = (await dispatch('sigil_pay_discover', { query: 'boutique' }, h.ctx)) as {
      services: { name?: string }[];
    };
    equal(filtered.services.length, 1);
    equal(filtered.services[0]!.name, 'Boutique');
  } finally {
    tearDown(h);
  }
});
