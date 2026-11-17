import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import {
  AbiRegistry,
  auditPreview,
  buildTxPreview,
  HEADLINE_MAX,
  jsonSafe,
} from '../../src/preview/index.js';
import { UpstreamRpcError, UpstreamTransportError } from '../../src/rpc/index.js';
import {
  FakeNode,
  MAX,
  POOL,
  PORTAL,
  ROUTER,
  simResult,
  SPENDER,
  t,
  TOPIC,
  tx,
  USDC,
  w,
  WETH,
} from './_fixtures.js';

const EMPTY = AbiRegistry.empty();
const NATIVE = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const ERROR_STF =
  '0x08c379a0' + w(0x20) + w(3) + Buffer.from('STF').toString('hex').padEnd(64, '0');

test('approve UNLIMITED: text and headline (pinned)', async () => {
  const node = new FakeNode()
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
  const p = await buildTxPreview({
    tx: tx({ to: USDC, data: `0x095ea7b3${w(SPENDER)}${MAX}` }),
    from: PORTAL,
    registry: EMPTY,
    simulator: node,
  });
  equal(
    p.text,
    [
      'call: approve(spender=0x1111…1111, amount=UNLIMITED) on 0xa0b8…eb48 (USDC)',
      'value: 0 ETH   chain: 1',
      'simulation: ok, 46,201 gas',
      '  approvals: USDC → 0x1111…1111 UNLIMITED',
      '  balance changes for 0x2278…931c: none',
      'warnings:',
      '  - UNLIMITED approval',
    ].join('\n'),
  );
  equal(p.headline, 'approve UNLIMITED USDC → 0x1111…1111 | sim ok | ⚠ UNLIMITED approval');
  deepEqual(p.warnings, ['UNLIMITED approval']);
  equal(p.decoded.source, 'builtin');
});

test('swap: balance changes and transfer listing (pinned)', async () => {
  const node = new FakeNode()
    .on(
      'eth_simulateV1',
      simResult({
        gasUsed: '0x1d4c0',
        logs: [
          {
            address: NATIVE,
            topics: [TOPIC.Transfer, t(PORTAL), t(ROUTER)],
            data: '0x' + w(10n ** 16n),
          },
          {
            address: USDC,
            topics: [TOPIC.Transfer, t(PORTAL), t(POOL)],
            data: '0x' + w(1_000_000_000n),
          },
          {
            address: WETH,
            topics: [TOPIC.Transfer, t(POOL), t(PORTAL)],
            data: '0x' + w(5n * 10n ** 17n),
          },
        ],
      }),
    )
    .token(USDC, 'USDC', 6)
    .token(WETH, 'WETH', 18);
  const data =
    '0x414bf389' +
    w(USDC) +
    w(WETH) +
    w(500) +
    w(PORTAL) +
    w(1_700_000_000) +
    w(1_000_000_000n) +
    w(4n * 10n ** 17n) +
    w(0);
  const p = await buildTxPreview({
    tx: tx({ to: ROUTER, value: 10n ** 16n, data: data as `0x${string}` }),
    from: PORTAL,
    registry: EMPTY,
    simulator: node,
  });
  equal(
    p.text,
    [
      'call: exactInputSingle(tokenIn=USDC, tokenOut=WETH, fee=500, recipient=0x2278…931c, deadline=2023-11-14T22:13:20Z, amountIn=1000000000, amountOutMinimum=400000000000000000) on 0xe592…1564',
      'value: 0.01 ETH   chain: 1',
      'simulation: ok, 120,000 gas',
      '  balance changes for 0x2278…931c: -0.01 ETH, -1,000 USDC, +0.5 WETH',
      '  transfers (3):',
      '    0.01 ETH 0x2278…931c → 0xe592…1564',
      '    1,000 USDC 0x2278…931c → 0x88e6…5640',
      '    0.5 WETH 0x88e6…5640 → 0x2278…931c',
    ].join('\n'),
  );
  equal(
    p.headline,
    'swap 1,000 USDC → ≥0.4 WETH, value 0.01 ETH | sim ok -0.01 ETH -1,000 USDC +0.5 WETH',
  );
  deepEqual(p.warnings, []);
});

test('revert: warning, headline and summary carry the decoded reason', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    simResult({ status: '0x0', returnData: ERROR_STF }),
  );
  const p = await buildTxPreview({
    tx: tx({ to: USDC, data: `0xa9059cbb${w(SPENDER)}${w(1)}` }),
    from: PORTAL,
    registry: EMPTY,
    simulator: node,
  });
  equal(p.simulation.status, 'reverted');
  deepEqual(p.warnings, ['simulation reverted: Error("STF")']);
  ok(p.text.includes('simulation: REVERTED — Error("STF")'), p.text);
  equal(
    p.headline,
    'transfer 1 of 0xa0b8…eb48 → 0x1111…1111 | sim REVERTED: Error("STF") | ⚠ simulation reverted: Error("STF")',
  );
  deepEqual(auditPreview(p), {
    text: p.text,
    decoded: 'transfer(to=0x1111…1111, amount=1)',
    simulation: 'REVERTED — Error("STF")',
    warnings: ['simulation reverted: Error("STF")'],
  });
});

test('no simulator: skipped with a reason; self-send warns', async () => {
  const p = await buildTxPreview({
    tx: tx({ to: PORTAL as `0x${string}`, value: 5n * 10n ** 17n }),
    from: PORTAL,
    registry: EMPTY,
  });
  equal(
    p.text,
    [
      'call: plain ETH transfer to 0x2278…931c',
      'value: 0.5 ETH   chain: 1',
      'simulation: skipped — no simulation RPC configured for chain 1',
      'warnings:',
      "  - destination is the portal's own address",
    ].join('\n'),
  );
  equal(
    p.headline,
    "send 0.5 ETH → 0x2278…931c | no sim | ⚠ destination is the portal's own address",
  );
});

test('unavailable simulation and unknown calldata with value both warn', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    new UpstreamTransportError('upstream RPC returned HTTP 502'),
  );
  const p = await buildTxPreview({
    tx: tx({ to: ROUTER, value: 1n, data: '0x12345678' }),
    from: PORTAL,
    registry: EMPTY,
    simulator: node,
  });
  deepEqual(p.warnings, [
    'unknown selector 0x12345678 — calldata not decoded',
    'simulation unavailable: upstream RPC returned HTTP 502',
    'calldata to unknown function with ETH value',
  ]);
  ok(
    p.headline.endsWith(
      '| sim unavailable | ⚠ unknown selector 0x12345678 — calldata not decoded (+2 more)',
    ),
    p.headline,
  );
});

test('eth_call fallback: balance changes are explicitly unknown', async () => {
  const node = new FakeNode().on('eth_estimateGas', '0x5208');
  const p = await buildTxPreview({
    tx: tx({ to: SPENDER as `0x${string}`, value: 1n }),
    from: PORTAL,
    registry: EMPTY,
    simulator: node,
  });
  ok(p.text.includes('simulation: ok, 21,000 gas (eth_call)'), p.text);
  ok(p.text.includes('note: simulation: eth_call only (node lacks eth_simulateV1)'), p.text);
  ok(p.text.includes('balance changes: unknown'), p.text);
});

test('ABI load warnings appear as footer lines; skippedReason overrides the default', async () => {
  const registry = AbiRegistry.fromSources([{ name: 'broken.json', text: '{' }]);
  const p = await buildTxPreview({
    tx: tx({ to: null, data: '0x6080' }),
    from: PORTAL,
    registry,
    skippedReason: 'chain 1 is not the [rpc] upstream chain',
  });
  equal(
    p.text,
    [
      'call: contract creation, 2-byte initcode',
      'value: 0 ETH   chain: 1',
      'simulation: skipped — chain 1 is not the [rpc] upstream chain',
      'abi: skipped broken.json: invalid JSON',
    ].join('\n'),
  );
  equal(p.headline, 'contract creation, 2-byte initcode | no sim');
});

test('headline is bounded even with long content', async () => {
  const many = Array.from({ length: 40 }, () => 'x').join('');
  const node = new FakeNode().on(
    'eth_simulateV1',
    simResult({ status: '0x0', returnData: '0x08c379a0' + w(0x20) + w(160) + 'ab'.repeat(160) }),
  );
  const p = await buildTxPreview({
    tx: tx({ to: ROUTER, data: ('0x12345678' + many) as `0x${string}` }),
    from: PORTAL,
    registry: EMPTY,
    simulator: node,
  });
  ok(p.headline.length <= HEADLINE_MAX, `${p.headline.length}`);
  ok(!p.headline.includes('\n'));
});

test('jsonSafe turns bigints into strings so the preview can cross MCP', async () => {
  const node = new FakeNode().on('eth_simulateV1', simResult({}));
  const p = await buildTxPreview({ tx: tx(), from: PORTAL, registry: EMPTY, simulator: node });
  const s = JSON.stringify(jsonSafe(p.simulation));
  ok(s.includes('"gasUsed":"21000"'), s);
  deepEqual(jsonSafe({ a: [1n, { b: 2n }], c: 'x' }), { a: ['1', { b: '2' }], c: 'x' });
});

test('a revert reported as a top-level node error still yields a reverted preview', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    new UpstreamRpcError(3, 'execution reverted: nope'),
  );
  const p = await buildTxPreview({ tx: tx(), from: PORTAL, registry: EMPTY, simulator: node });
  equal(p.simulation.status, 'reverted');
  deepEqual(p.warnings, ['simulation reverted: execution reverted: nope']);
});
