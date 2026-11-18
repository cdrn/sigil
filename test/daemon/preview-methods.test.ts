import { test } from 'node:test';
import { deepEqual, equal, ok, rejects } from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
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
import {
  dispatch,
  HandleTable,
  type MethodContext,
  type PreviewContext,
  RPC_DAEMON_LOCKED,
  RPC_INVALID_PARAMS,
  RPC_POLICY_DENIED,
  RPC_PORTAL_NOT_FOUND,
  RpcMethodError,
} from '../../src/daemon/index.js';
import { addressFromPrivateKey } from '../../src/eth/index.js';
import { parsePolicy, type PolicyResolver } from '../../src/policy/index.js';
import { AbiRegistry } from '../../src/preview/index.js';
import { UpstreamRpcError, UpstreamTransportError } from '../../src/rpc/index.js';
import { FakeNode, MAX, simResult, SPENDER, t, TOPIC, USDC, w } from '../preview/_fixtures.js';

const PRIV = Buffer.alloc(32);
PRIV[31] = 1;
const PORTAL = addressFromPrivateKey(PRIV);
const ERROR_STF =
  '0x08c379a0' + w(0x20) + w(3) + Buffer.from('STF').toString('hex').padEnd(64, '0');
const APPROVE_MAX = `0x095ea7b3${w(SPENDER)}${MAX}`;

function resolver(toml: string): PolicyResolver {
  const p = parsePolicy(toml);
  return { resolve: () => p };
}

interface H {
  ctx: MethodContext;
  auditPath: string;
  cleanup: () => void;
}

function harness(opts: { policy?: string; preview?: PreviewContext; locked?: boolean } = {}): H {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-preview-methods-'));
  const auditPath = join(dir, 'audit.log');
  const handles = new HandleTable();
  handles.addEntry('evm:bot', new SecretBuffer(Buffer.from(PRIV)));
  if (!opts.locked) handles.markUnlocked();
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(auditPath, { now: () => ++now });
  return {
    ctx: {
      handles,
      audit,
      policy: resolver(opts.policy ?? 'mode = "permissive"'),
      ...(opts.preview ? { preview: opts.preview } : {}),
    },
    auditPath,
    cleanup: () => {
      audit.close();
      handles.dispose();
      rmSync(dir, { recursive: true });
    },
  };
}

function withNode(node: FakeNode | undefined): PreviewContext {
  return { registry: AbiRegistry.empty(), simulatorFor: () => node };
}

function txParams(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    portal: 'evm:bot',
    tx: {
      type: 'eip1559',
      chainId: 1,
      nonce: 0,
      maxPriorityFeePerGas: '1000000000',
      maxFeePerGas: '30000000000',
      gasLimit: '100000',
      to: USDC,
      value: '0',
      data: APPROVE_MAX,
      ...over,
    },
  };
}

function entries(path: string): ReturnType<typeof verifyChain> {
  return existsSync(path) ? verifyChain(readFileSync(path)) : [];
}

async function denied(p: Promise<unknown>): Promise<RpcMethodError> {
  try {
    await p;
  } catch (e) {
    ok(e instanceof RpcMethodError, String(e));
    return e;
  }
  throw new Error('expected a deny');
}

function approveNode(): FakeNode {
  return new FakeNode()
    .on(
      'eth_simulateV1',
      simResult({
        gasUsed: '0xb479',
        logs: [
          { address: USDC, topics: [TOPIC.Approval, t(PORTAL), t(SPENDER)], data: '0x' + MAX },
        ],
      }),
    )
    .token(USDC, 'USDC', 6);
}

// ---------------------------------------------------------------------------
// sign_transaction
// ---------------------------------------------------------------------------

test('sign without a preview context: decodes offline, simulation skipped, audited', async () => {
  const h = harness();
  try {
    const r = (await dispatch('sigil_eth_sign_transaction', txParams(), h.ctx)) as {
      signed: string;
      preview: string;
    };
    ok(r.signed.startsWith('0x02'));
    ok(r.preview.startsWith('call: approve(spender=0x1111…1111, amount=UNLIMITED) on 0xa0b8…eb48'));
    ok(r.preview.includes('simulation: skipped — no simulation RPC configured for chain 1'));
    const [e] = entries(h.auditPath);
    equal(e!.decision, 'allow');
    equal(e!.preview!.decoded, 'approve(spender=0x1111…1111, amount=UNLIMITED)');
    equal(e!.preview!.simulation, 'skipped — no simulation RPC configured for chain 1');
    deepEqual(e!.preview!.warnings, ['UNLIMITED approval']);
    equal(e!.preview!.text, r.preview);
  } finally {
    h.cleanup();
  }
});

test('sign with a simulator: the dry-run runs as the portal and lands in the result + audit', async () => {
  const node = approveNode();
  const h = harness({ preview: withNode(node) });
  try {
    const r = (await dispatch('sigil_eth_sign_transaction', txParams(), h.ctx)) as {
      preview: string;
    };
    ok(r.preview.includes('(USDC)'), r.preview);
    ok(r.preview.includes('approvals: USDC → 0x1111…1111 UNLIMITED'), r.preview);
    const sim = node.calls.find((c) => c.method === 'eth_simulateV1')!;
    const call = (sim.params[0] as { blockStateCalls: { calls: { from: string }[] }[] })
      .blockStateCalls[0]!.calls[0]!;
    equal(call.from, PORTAL);
    equal(entries(h.auditPath)[0]!.preview!.simulation, 'ok, 46,201 gas');
  } finally {
    h.cleanup();
  }
});

test('a simulated revert is denied by default, audited with the preview, never signed', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    simResult({ status: '0x0', returnData: ERROR_STF }),
  );
  const h = harness({ preview: withNode(node) });
  try {
    const err = await denied(dispatch('sigil_eth_sign_transaction', txParams(), h.ctx));
    equal(err.code, RPC_POLICY_DENIED);
    ok(err.message.includes('simulation reverted: Error("STF")'), err.message);
    ok(err.message.includes('sign_on_revert'), err.message);
    ok((err.data as { preview: string }).preview.includes('REVERTED'));
    const all = entries(h.auditPath);
    equal(all.length, 1);
    equal(all[0]!.decision, 'deny');
    equal(all[0]!.sig, undefined);
    equal(all[0]!.preview!.simulation, 'REVERTED — Error("STF")');
  } finally {
    h.cleanup();
  }
});

test('sign_on_revert = true signs a reverting tx and keeps the warning', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    simResult({ status: '0x0', returnData: ERROR_STF }),
  );
  const h = harness({
    policy: 'mode = "permissive"\nsign_on_revert = true',
    preview: withNode(node),
  });
  try {
    const r = (await dispatch('sigil_eth_sign_transaction', txParams(), h.ctx)) as {
      signed: string;
    };
    ok(r.signed.startsWith('0x02'));
    const [e] = entries(h.auditPath);
    equal(e!.decision, 'allow');
    ok(e!.preview!.warnings.includes('simulation reverted: Error("STF")'));
  } finally {
    h.cleanup();
  }
});

test('require_simulation: no simulator for the chain → deny (fail closed)', async () => {
  for (const preview of [undefined, withNode(undefined)]) {
    const h = harness({
      policy: 'mode = "permissive"\nrequire_simulation = true',
      ...(preview ? { preview } : {}),
    });
    try {
      const err = await denied(dispatch('sigil_eth_sign_transaction', txParams(), h.ctx));
      equal(err.code, RPC_POLICY_DENIED);
      ok(err.message.includes('require_simulation = true but the tx could not be simulated'));
      ok(err.message.includes('no simulation RPC configured for chain 1'), err.message);
      equal(entries(h.auditPath)[0]!.decision, 'deny');
    } finally {
      h.cleanup();
    }
  }
});

test('require_simulation: an unavailable simulation → deny; a resolver that throws → deny', async () => {
  const down = new FakeNode().on(
    'eth_simulateV1',
    new UpstreamTransportError('upstream RPC unreachable: fetch failed'),
  );
  const h = harness({
    policy: 'mode = "permissive"\nrequire_simulation = true',
    preview: withNode(down),
  });
  try {
    const err = await denied(dispatch('sigil_eth_sign_transaction', txParams(), h.ctx));
    ok(err.message.includes('simulation was unavailable: upstream RPC unreachable'), err.message);
  } finally {
    h.cleanup();
  }
  const h2 = harness({
    policy: 'mode = "permissive"\nrequire_simulation = true',
    preview: {
      registry: AbiRegistry.empty(),
      simulatorFor: () => Promise.reject(new Error('boom')),
    },
  });
  try {
    const err = await denied(dispatch('sigil_eth_sign_transaction', txParams(), h2.ctx));
    ok(err.message.includes('could not be simulated'), err.message);
    ok(err.message.includes('boom'), err.message);
  } finally {
    h2.cleanup();
  }
});

test('without require_simulation, an unavailable simulation still signs (warning only)', async () => {
  const down = new FakeNode().on('eth_simulateV1', new UpstreamTransportError('HTTP 502'));
  const h = harness({ preview: withNode(down) });
  try {
    await dispatch('sigil_eth_sign_transaction', txParams(), h.ctx);
    const [e] = entries(h.auditPath);
    equal(e!.decision, 'allow');
    ok(e!.preview!.warnings.includes('simulation unavailable: HTTP 502'));
  } finally {
    h.cleanup();
  }
});

test('require_simulation is satisfied by a successful simulation', async () => {
  const h = harness({
    policy: 'mode = "permissive"\nrequire_simulation = true',
    preview: withNode(approveNode()),
  });
  try {
    await dispatch('sigil_eth_sign_transaction', txParams(), h.ctx);
    equal(entries(h.auditPath)[0]!.decision, 'allow');
  } finally {
    h.cleanup();
  }
});

test('a static policy deny happens before (and without) any simulation', async () => {
  const node = approveNode();
  const h = harness({
    policy: 'mode = "strict"\nchain_ids = [1]\nallow_to = []',
    preview: withNode(node),
  });
  try {
    const err = await denied(dispatch('sigil_eth_sign_transaction', txParams(), h.ctx));
    ok(err.message.includes('not in allow_to'), err.message);
    deepEqual(node.calls, []);
    equal(entries(h.auditPath)[0]!.preview, undefined);
  } finally {
    h.cleanup();
  }
});

class CapturingTransport implements ConfirmTransport {
  readonly name = 'capture';
  captured: ConfirmRequest | undefined;
  async send(req: ConfirmRequest): Promise<void> {
    this.captured = req;
  }
}

test('confirm push carries the policy summary, the preview headline and up to 3 warnings', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-preview-confirm-'));
  const handles = new HandleTable();
  handles.addEntry('evm:bot', new SecretBuffer(Buffer.from(PRIV)));
  handles.markUnlocked();
  const audit = new AuditWriter(join(dir, 'audit.log'));
  const transport = new CapturingTransport();
  const ack = await startAckServer();
  const ctx: MethodContext = {
    handles,
    audit,
    policy: resolver('mode = "permissive"\nrequire_confirm_above_wei = "0"'),
    confirm: new ConfirmGate({ transport, ackServer: ack, timeoutMs: 2000 }),
    preview: withNode(approveNode()),
  };
  try {
    const signing = dispatch('sigil_eth_sign_transaction', txParams({ value: '1' }), ctx);
    signing.catch(() => {});
    while (!transport.captured) await new Promise((r) => setTimeout(r, 2));
    const lines = transport.captured.summary.split('\n');
    equal(lines[0], '0 ETH → 0xa0b8…eb48 on chain 1');
    ok(lines[1]!.startsWith('approve UNLIMITED USDC → 0x1111…1111'), lines[1]);
    equal(lines[2], '⚠ UNLIMITED approval');
    equal(lines.length, 3);
    await fetch(transport.captured.approveUrl, { method: 'POST' });
    await signing;
    const [e] = verifyChain(readFileSync(join(dir, 'audit.log')));
    equal(e!.decision, 'allow');
    ok(e!.preview);
  } finally {
    audit.close();
    handles.dispose();
    await ack.close();
    rmSync(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// preview_transaction
// ---------------------------------------------------------------------------

test('preview_transaction: returns the preview, signs nothing, writes no audit entry', async () => {
  const h = harness({
    policy: 'mode = "strict"\nchain_ids = [5]',
    preview: withNode(approveNode()),
  });
  try {
    const r = (await dispatch('sigil_eth_preview_transaction', txParams(), h.ctx)) as Record<
      string,
      unknown
    >;
    deepEqual(Object.keys(r).sort(), ['decoded', 'headline', 'preview', 'simulation', 'warnings']);
    ok((r['preview'] as string).includes('UNLIMITED'));
    equal(
      r['headline'],
      'approve UNLIMITED USDC → 0x1111…1111 | sim ok grants USDC → 0x1111…1111 UNLIMITED | ⚠ UNLIMITED approval',
    );
    deepEqual(r['warnings'], ['UNLIMITED approval']);
    equal((r['simulation'] as { gasUsed: string }).gasUsed, '46201');
    // JSON-serializable for the MCP wire.
    ok(JSON.stringify(r).length > 0);
    // The strict policy (wrong chain) would deny a sign; preview ignores policy.
    equal(entries(h.auditPath).length, 0);
  } finally {
    h.cleanup();
  }
});

test('preview_transaction: locked → DAEMON_LOCKED; unknown portal → PORTAL_NOT_FOUND', async () => {
  const locked = harness({ locked: true });
  try {
    await rejects(
      dispatch('sigil_eth_preview_transaction', txParams(), locked.ctx),
      (e: RpcMethodError) => e.code === RPC_DAEMON_LOCKED,
    );
  } finally {
    locked.cleanup();
  }
  const h = harness();
  try {
    await rejects(
      dispatch('sigil_eth_preview_transaction', { ...txParams(), portal: 'evm:nope' }, h.ctx),
      (e: RpcMethodError) => e.code === RPC_PORTAL_NOT_FOUND,
    );
  } finally {
    h.cleanup();
  }
});

test('tx quantities wider than uint256 are INVALID_PARAMS before any preview work', async () => {
  const h = harness();
  try {
    const max = ((1n << 256n) - 1n).toString();
    // uint256 max itself is fine as a value (the sign may fail later on funds, not here).
    await dispatch('sigil_eth_preview_transaction', txParams({ value: max, data: '0x' }), h.ctx);
    for (const [key, v] of [
      ['value', (1n << 256n).toString()],
      ['value', '9'.repeat(100_000)],
      ['gasLimit', '0x' + 'f'.repeat(65)],
      ['maxFeePerGas', (1n << 300n).toString()],
      ['nonce', (1n << 256n).toString()],
    ] as const) {
      const start = Date.now();
      await rejects(
        dispatch('sigil_eth_sign_transaction', txParams({ [key]: v }), h.ctx),
        (e: RpcMethodError) => e.code === RPC_INVALID_PARAMS && /exceeds uint256/.test(e.message),
      );
      ok(Date.now() - start < 200);
    }
    equal(entries(h.auditPath).length, 0);
  } finally {
    h.cleanup();
  }
});

test('sign_on_revert = false still denies a revert whose logs are malformed', async () => {
  const node = new FakeNode().on('eth_simulateV1', [{ calls: [{ status: '0x0', logs: 5 }] }]);
  const h = harness({ preview: withNode(node) });
  try {
    const err = await denied(dispatch('sigil_eth_sign_transaction', txParams(), h.ctx));
    equal(err.code, RPC_POLICY_DENIED);
    ok(err.message.includes('simulation reverted'), err.message);
  } finally {
    h.cleanup();
  }
});

test('require_simulation denies a gasLimit 0 tx (it cannot be simulated as signed)', async () => {
  const node = approveNode();
  const h = harness({
    policy: 'mode = "permissive"\nrequire_simulation = true',
    preview: withNode(node),
  });
  try {
    const err = await denied(
      dispatch('sigil_eth_sign_transaction', txParams({ gasLimit: '0' }), h.ctx),
    );
    ok(err.message.includes('gasLimit 0 cannot be simulated or sent'), err.message);
    deepEqual(node.calls, []);
  } finally {
    h.cleanup();
  }
});

test('JSON-number tx fields above 2^53 are INVALID_PARAMS (no 1e100 nonce gets signed)', async () => {
  const h = harness();
  try {
    for (const key of ['nonce', 'value', 'gasLimit']) {
      for (const v of [1e100, 2 ** 53, Number.MAX_VALUE]) {
        await rejects(
          dispatch('sigil_eth_sign_transaction', txParams({ [key]: v, data: '0x' }), h.ctx),
          (e: RpcMethodError) =>
            e.code === RPC_INVALID_PARAMS &&
            /use a decimal string for values above 2\^53/.test(e.message),
          `${key}=${v}`,
        );
      }
    }
    equal(entries(h.auditPath).length, 0);
    // The largest safe integer still works as a number.
    await dispatch(
      'sigil_eth_preview_transaction',
      txParams({ nonce: Number.MAX_SAFE_INTEGER, data: '0x' }),
      h.ctx,
    );
  } finally {
    h.cleanup();
  }
});

/** anvil's answer for an unfunded sender once fee fields are present. */
function feeRefusingNode(): FakeNode {
  return new FakeNode()
    .on('eth_simulateV1', (params: readonly unknown[]) => {
      const c = (params[0] as { blockStateCalls: { calls: Record<string, unknown>[] }[] })
        .blockStateCalls[0]!.calls[0]!;
      return 'maxFeePerGas' in c
        ? new UpstreamRpcError(-32003, 'Insufficient funds for gas * price + value')
        : simResult({});
    })
    .token(USDC, 'USDC', 6);
}

test('fee-stripped simulation: warning on the confirm headline; require_simulation denies it', async () => {
  const warn =
    'simulated without fee fields (node refused: insufficient funds) — the contract saw tx.gasprice = 0';
  const h = harness({ preview: withNode(feeRefusingNode()) });
  try {
    const p = (await dispatch('sigil_eth_preview_transaction', txParams(), h.ctx)) as {
      headline: string;
      warnings: string[];
    };
    ok(p.warnings.includes(warn), p.warnings.join('|'));
    ok(p.headline.includes('⚠'), p.headline);
    // Default policy signs, but the audit entry carries the warning.
    await dispatch('sigil_eth_sign_transaction', txParams(), h.ctx);
    ok(entries(h.auditPath)[0]!.preview!.warnings.includes(warn));
  } finally {
    h.cleanup();
  }
  const strict = harness({
    policy: 'mode = "permissive"\nrequire_simulation = true',
    preview: withNode(feeRefusingNode()),
  });
  try {
    const err = await denied(dispatch('sigil_eth_sign_transaction', txParams(), strict.ctx));
    equal(err.code, RPC_POLICY_DENIED);
    equal(
      err.message,
      'tx denied — require_simulation = true but the node could only simulate without the fee fields',
    );
    equal(entries(strict.auditPath)[0]!.decision, 'deny');
  } finally {
    strict.cleanup();
  }
});

test('the fee-stripped retry needs code -32003 AND an insufficient-funds message', async () => {
  for (const err of [
    new UpstreamRpcError(-32000, 'insufficient funds for gas * price + value'),
    new UpstreamRpcError(-32003, 'transaction underpriced'),
  ]) {
    const node = new FakeNode().on('eth_simulateV1', err);
    const h = harness({ preview: withNode(node) });
    try {
      const r = (await dispatch('sigil_eth_preview_transaction', txParams(), h.ctx)) as {
        simulation: { status: string };
      };
      equal(r.simulation.status, 'unavailable', err.message);
      equal(node.calls.filter((c) => c.method === 'eth_simulateV1').length, 1, 'no retry');
    } finally {
      h.cleanup();
    }
  }
});

test('default policy denies a revert even when token metadata arrives late', async () => {
  const later = <T>(ms: number, v: T): Promise<T> => new Promise((r) => setTimeout(() => r(v), ms));
  const node = new FakeNode()
    .on('eth_simulateV1', (params: readonly unknown[]) => {
      const c = (params[0] as { blockStateCalls: { calls: Record<string, unknown>[] }[] })
        .blockStateCalls[0]!.calls[0]!;
      return 'maxFeePerGas' in c
        ? later(
            700,
            new UpstreamRpcError(-32003, 'Insufficient funds for gas * price + value'),
          ).then((e) => Promise.reject(e))
        : later(700, simResult({ status: '0x0', returnData: ERROR_STF }));
    })
    .on('eth_call', () => later(950, '0x'));
  const h = harness({ preview: { ...withNode(node), timeoutMs: 1000 } });
  try {
    const err = await denied(dispatch('sigil_eth_sign_transaction', txParams(), h.ctx));
    equal(err.code, RPC_POLICY_DENIED);
    ok(err.message.includes('simulation reverted: Error("STF")'), err.message);
  } finally {
    h.cleanup();
  }
});

test('preview_transaction output omits the internal uncapped transfer list', async () => {
  const h = harness({ preview: withNode(approveNode()) });
  try {
    const r = (await dispatch('sigil_eth_preview_transaction', txParams(), h.ctx)) as {
      simulation: Record<string, unknown>;
    };
    equal('allTransfers' in r.simulation, false);
    ok('transfers' in r.simulation);
  } finally {
    h.cleanup();
  }
});
