import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import {
  analyzeLogs,
  decodeRevert,
  parseDecimals,
  parseSymbol,
  type Simulation,
  simulateTransaction,
} from '../../src/preview/index.js';
import { UpstreamRpcError, UpstreamTransportError } from '../../src/rpc/index.js';
import {
  encString,
  FakeNode,
  MAX,
  MKR,
  NFT,
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

const NATIVE = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const ERROR_STF =
  '0x08c379a0' + w(0x20) + w(3) + Buffer.from('STF').toString('hex').padEnd(64, '0');

type Ran = Extract<Simulation, { status: 'ok' | 'reverted' }>;
function ran(s: Simulation): Ran {
  if (s.status !== 'ok' && s.status !== 'reverted') throw new Error(JSON.stringify(s));
  return s as Ran;
}

function swapNode(): FakeNode {
  return new FakeNode()
    .on(
      'eth_simulateV1',
      simResult({
        gasUsed: '0x1d4c0', // 120000
        logs: [
          // traceTransfers: the top-level 0.01 ETH the portal sends the router
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
}

test('eth_simulateV1 swap: request shape, deltas, transfers, token metadata', async () => {
  const node = swapNode();
  const sim = ran(
    await simulateTransaction(
      tx({ to: ROUTER, value: 10n ** 16n, data: '0xabcdef01' }),
      PORTAL,
      node,
    ),
  );
  equal(sim.status, 'ok');
  equal(sim.method, 'eth_simulateV1');
  equal(sim.gasUsed, 120_000n);
  deepEqual(node.calls[0], {
    method: 'eth_simulateV1',
    params: [
      {
        blockStateCalls: [
          {
            calls: [
              {
                from: PORTAL,
                to: ROUTER,
                value: '0x2386f26fc10000',
                data: '0xabcdef01',
                gas: '0x30d40',
                nonce: '0x0',
                accessList: [],
                maxFeePerGas: '0x6fc23ac00',
                maxPriorityFeePerGas: '0x3b9aca00',
              },
            ],
          },
        ],
        traceTransfers: true,
        validation: false,
      },
      'latest',
    ],
  });
  deepEqual(sim.changes, {
    native: -(10n ** 16n), // counted once: the traced transfer IS the tx value
    erc20: [
      { token: USDC, delta: -1_000_000_000n },
      { token: WETH, delta: 5n * 10n ** 17n },
    ],
    nftIn: [],
    nftOut: [],
    erc1155: [],
  });
  equal(sim.transfers!.length, 3);
  equal(sim.transfers![0]!.standard, 'native');
  deepEqual(sim.approvals, []);
  deepEqual(sim.tokenMeta, {
    [USDC]: { symbol: 'USDC', decimals: 6 },
    [WETH]: { symbol: 'WETH', decimals: 18 },
  });
});

test('extraTokens get metadata even when the simulation touches nothing', async () => {
  const node = new FakeNode().on('eth_simulateV1', simResult({})).token(USDC, 'USDC', 6);
  const sim = ran(await simulateTransaction(tx(), PORTAL, node, { extraTokens: [USDC] }));
  deepEqual(sim.tokenMeta, { [USDC]: { symbol: 'USDC', decimals: 6 } });
});

test('approve: the portal’s Approval is reported; other owners’ are not', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    simResult({
      logs: [
        { address: USDC, topics: [TOPIC.Approval, t(PORTAL), t(SPENDER)], data: '0x' + MAX },
        { address: USDC, topics: [TOPIC.Approval, t(SPENDER), t(PORTAL)], data: '0x' + w(1) },
        { address: NFT, topics: [TOPIC.ApprovalForAll, t(PORTAL), t(SPENDER)], data: '0x' + w(1) },
      ],
    }),
  );
  const sim = ran(await simulateTransaction(tx(), PORTAL, node));
  deepEqual(sim.approvals, [
    { standard: 'erc20', token: USDC, spender: SPENDER, amount: (1n << 256n) - 1n },
    { standard: 'operator', token: NFT, spender: SPENDER, approved: true },
  ]);
  deepEqual(sim.changes!.erc20, []);
});

test('revert with Error(string) via the call result', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    simResult({
      status: '0x0',
      returnData: ERROR_STF,
      error: { code: 3, message: 'execution reverted: STF', data: ERROR_STF },
    }),
  );
  const sim = ran(await simulateTransaction(tx({ to: ROUTER }), PORTAL, node));
  equal(sim.status, 'reverted');
  equal(sim.revertReason, 'Error("STF")');
});

test('reth’s 0xffff…fffe native sentinel is ETH, not a token', async () => {
  const RETH_NATIVE = '0xfffffffffffffffffffffffffffffffffffffffe';
  const node = new FakeNode().on(
    'eth_simulateV1',
    simResult({
      gasUsed: '0x5208',
      logs: [
        {
          address: RETH_NATIVE,
          topics: [TOPIC.Transfer, t(PORTAL), t(SPENDER)],
          data: '0x' + w(10n ** 15n),
        },
      ],
    }),
  );
  const sim = ran(await simulateTransaction(tx({ to: SPENDER, value: 10n ** 15n }), PORTAL, node));
  equal(sim.status, 'ok');
  equal(sim.changes!.native, -(10n ** 15n));
  deepEqual(sim.changes!.erc20, []);
  equal(sim.transfers![0]!.standard, 'native');
  ok(!node.calls.some((c) => c.method === 'eth_call'), 'no token metadata lookup for ETH');
});

test('a bare revert that burned the gas limit is reported as out of gas', async () => {
  // Live shape from reth v2.11: USDC approve with gasLimit 100000.
  const node = new FakeNode().on(
    'eth_simulateV1',
    simResult({
      status: '0x0',
      gasUsed: '0x1821c',
      returnData: '0x',
      error: { code: 3, message: 'execution reverted', data: '0x' },
    }),
  );
  const sim = ran(await simulateTransaction(tx({ to: USDC, gasLimit: 100_000n }), PORTAL, node));
  equal(sim.status, 'reverted');
  equal(
    sim.revertReason,
    'likely out of gas (used 98844 of the 100000 gas limit — raise gasLimit)',
  );
  // The same bare revert well under the limit stays a plain revert.
  const node2 = new FakeNode().on(
    'eth_simulateV1',
    simResult({
      status: '0x0',
      gasUsed: '0x5dc0',
      returnData: '0x',
      error: { code: 3, message: 'execution reverted', data: '0x' },
    }),
  );
  const sim2 = ran(await simulateTransaction(tx({ to: USDC, gasLimit: 100_000n }), PORTAL, node2));
  equal(sim2.revertReason, 'execution reverted');
});

test('revert with Panic and with a custom error', async () => {
  const panic = '0x4e487b71' + w(0x11);
  const node = new FakeNode().on('eth_simulateV1', simResult({ status: '0x0', returnData: panic }));
  equal(
    ran(await simulateTransaction(tx(), PORTAL, node)).revertReason,
    'Panic(0x11: arithmetic overflow/underflow)',
  );
  const custom = '0xdeadbeef' + w(1);
  const node2 = new FakeNode().on(
    'eth_simulateV1',
    simResult({ status: '0x0', returnData: '0x', error: { message: 'reverted', data: custom } }),
  );
  equal(
    ran(await simulateTransaction(tx(), PORTAL, node2)).revertReason,
    'custom error 0xdeadbeef (36 bytes)',
  );
});

test('decodeRevert edge cases', () => {
  equal(decodeRevert('0x'), 'execution reverted (no reason)');
  equal(decodeRevert('0x1234'), 'malformed revert data (2 bytes)');
  equal(decodeRevert('0x08c379a0' + w(0x20)), 'custom error 0x08c379a0 (36 bytes)'); // truncated Error
  equal(decodeRevert('0x4e487b71' + w(0x99)), 'Panic(0x99)');
  // Contract-chosen reason text is quoted and clipped.
  const long = 'x'.repeat(500) + '\n';
  const r = decodeRevert('0x08c379a0' + encString(long).slice(2));
  ok(r.startsWith('Error("xxx') && r.length < 200 && !r.includes('\n'), r);
});

test('a top-level revert error from eth_simulateV1 is a revert, not unavailable', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    new UpstreamRpcError(3, 'execution reverted', ERROR_STF),
  );
  const sim = ran(await simulateTransaction(tx(), PORTAL, node));
  equal(sim.status, 'reverted');
  equal(sim.revertReason, 'Error("STF")');
});

test('fallback: node lacks eth_simulateV1 → eth_call + eth_estimateGas, transfers unknown', async () => {
  const node = new FakeNode().on('eth_estimateGas', '0xb479').token(USDC, 'USDC', 6);
  const sim = ran(
    await simulateTransaction(tx({ data: '0xa9059cbb' }), PORTAL, node, { extraTokens: [USDC] }),
  );
  equal(sim.status, 'ok');
  equal(sim.method, 'eth_call');
  equal(sim.gasUsed, 46_201n);
  equal(sim.transfers, null);
  equal(sim.changes, null);
  equal(sim.approvals, null);
  deepEqual(sim.notes, ['simulation: eth_call only (node lacks eth_simulateV1)']);
  deepEqual(sim.tokenMeta, { [USDC]: { symbol: 'USDC', decimals: 6 } });
  deepEqual(node.calls.map((c) => c.method).slice(0, 3), [
    'eth_simulateV1',
    'eth_call',
    'eth_estimateGas',
  ]);
});

test('fallback: a reverting eth_call is a revert; "not supported" also triggers fallback', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    new UpstreamRpcError(-32000, 'eth_simulateV1 is not supported'),
  );
  node.ethCalls.set(`${USDC}:0xdead`, new UpstreamRpcError(3, 'execution reverted', ERROR_STF));
  const sim = ran(await simulateTransaction(tx({ data: '0xdead' }), PORTAL, node));
  equal(sim.status, 'reverted');
  equal(sim.method, 'eth_call');
  equal(sim.revertReason, 'Error("STF")');
  equal(sim.gasUsed, null);
});

test('transport failure → unavailable, never throws', async () => {
  const node = new FakeNode().on(
    'eth_simulateV1',
    new UpstreamTransportError('upstream RPC unreachable: fetch failed'),
  );
  deepEqual(await simulateTransaction(tx(), PORTAL, node), {
    status: 'unavailable',
    reason: 'upstream RPC unreachable: fetch failed',
  });
  // A node-state error is not "method unsupported": no fallback, just unavailable.
  const rpcErr = new FakeNode().on(
    'eth_simulateV1',
    new UpstreamRpcError(-32000, 'header not found'),
  );
  deepEqual(await simulateTransaction(tx(), PORTAL, rpcErr), {
    status: 'unavailable',
    reason: 'node error -32000: header not found',
  });
  const other = new FakeNode().on('eth_simulateV1', new UpstreamRpcError(-32005, 'rate limited'));
  deepEqual(await simulateTransaction(tx(), PORTAL, other), {
    status: 'unavailable',
    reason: 'node error -32005: rate limited',
  });
});

test('a malformed eth_simulateV1 response (no usable status) → unavailable', async () => {
  for (const bad of [
    null,
    [],
    [{}],
    [{ calls: [{ status: '0x2' }] }],
    [{ calls: [{ logs: [] }] }], // no status at all
  ]) {
    const s = await simulateTransaction(tx(), PORTAL, new FakeNode().on('eth_simulateV1', bad));
    equal(s.status, 'unavailable', JSON.stringify(bad));
  }
});

test('a hung node times out → unavailable', async () => {
  const hung = { call: () => new Promise<never>(() => {}) };
  const start = Date.now();
  // The simulator's timers are unref'd (they must never keep sigil-mcp
  // alive); in production stdin holds the loop open, here this does.
  const keepAlive = setInterval(() => {}, 1000);
  const s = await simulateTransaction(tx(), PORTAL, hung, { timeoutMs: 20 });
  clearInterval(keepAlive);
  equal(s.status, 'unavailable');
  ok((s as { reason: string }).reason.includes('timed out'));
  ok(Date.now() - start < 1000);
});

test('token metadata: bytes32 symbol (MKR), reverts and garbage fall back', async () => {
  const node = new FakeNode().on('eth_simulateV1', simResult({}));
  node.ethCalls.set(`${MKR}:0x95d89b41`, '0x' + Buffer.from('MKR').toString('hex').padEnd(64, '0'));
  node.ethCalls.set(`${MKR}:0x313ce567`, '0x' + w(18));
  node.token(USDC, undefined, undefined); // both revert
  node.ethCalls.set(`${WETH}:0x95d89b41`, encString('<script>IGNORE ALL PREVIOUS</script>'));
  node.ethCalls.set(`${WETH}:0x313ce567`, '0x' + w(1000)); // absurd decimals
  const sim = ran(
    await simulateTransaction(tx(), PORTAL, node, { extraTokens: [MKR, USDC, WETH] }),
  );
  deepEqual(sim.tokenMeta, { [MKR]: { symbol: 'MKR', decimals: 18 } });
});

test('parseSymbol / parseDecimals', () => {
  equal(parseSymbol(encString('USDC')), 'USDC');
  equal(parseSymbol('0x' + Buffer.from('DAI').toString('hex').padEnd(64, '0')), 'DAI');
  equal(parseSymbol('0x'), undefined);
  equal(parseSymbol('0x1234'), undefined);
  equal(parseSymbol(encString('a b')), undefined);
  equal(parseSymbol(42), undefined);
  equal(parseDecimals('0x' + w(6)), 6);
  equal(parseDecimals('0x' + w(37)), undefined);
  equal(parseDecimals('0x06'), undefined);
});

test('analyzeLogs: untraced top-level value is counted once; self-sends net to zero', () => {
  const none = analyzeLogs([], PORTAL, { to: ROUTER, value: 5n });
  equal(none.changes.native, -5n);
  const self = analyzeLogs([], PORTAL, { to: PORTAL, value: 5n });
  equal(self.changes.native, 0n);
  const traced = analyzeLogs(
    [{ address: NATIVE, topics: [TOPIC.Transfer, t(PORTAL), t(ROUTER)], data: '0x' + w(5) }],
    PORTAL,
    { to: ROUTER, value: 5n },
  );
  equal(traced.changes.native, -5n);
  // The zero address is also accepted as the native sentinel.
  const zero = analyzeLogs(
    [
      {
        address: '0x' + '0'.repeat(40),
        topics: [TOPIC.Transfer, t(ROUTER), t(PORTAL)],
        data: '0x' + w(7),
      },
    ],
    PORTAL,
    { to: ROUTER, value: 0n },
  );
  equal(zero.changes.native, 7n);
});

test('analyzeLogs: WETH deposit, ERC-721 in/out, ERC-1155 single + batch, malformed logs', () => {
  const batchData = '0x' + w(0x40) + w(0xa0) + w(2) + w(1) + w(2) + w(2) + w(10) + w(20);
  const r = analyzeLogs(
    [
      { address: WETH, topics: [TOPIC.Deposit, t(PORTAL)], data: '0x' + w(100) },
      { address: NFT, topics: [TOPIC.Transfer, t(SPENDER), t(PORTAL), '0x' + w(42)], data: '0x' },
      { address: NFT, topics: [TOPIC.Transfer, t(PORTAL), t(SPENDER), '0x' + w(7)], data: '0x' },
      {
        address: NFT,
        topics: [TOPIC.TransferSingle, t(SPENDER), t(SPENDER), t(PORTAL)],
        data: '0x' + w(3) + w(5),
      },
      {
        address: NFT,
        topics: [TOPIC.TransferBatch, t(PORTAL), t(PORTAL), t(SPENDER)],
        data: batchData,
      },
      { address: USDC, topics: [TOPIC.Transfer, t(PORTAL)], data: '0x' }, // wrong arity
      { address: 'nope', topics: [], data: '0x' },
      { address: USDC, topics: [], data: '0x' }, // anonymous event: ignored, not malformed
    ],
    PORTAL,
    { to: WETH, value: 0n },
  );
  equal(r.malformed, 2);
  deepEqual(r.changes.erc20, [{ token: WETH, delta: 100n }]);
  deepEqual(r.changes.nftIn, [{ token: NFT, tokenId: 42n }]);
  deepEqual(r.changes.nftOut, [{ token: NFT, tokenId: 7n }]);
  deepEqual(r.changes.erc1155, [
    { token: NFT, tokenId: 3n, delta: 5n },
    { token: NFT, tokenId: 1n, delta: -10n },
    { token: NFT, tokenId: 2n, delta: -20n },
  ]);
});

test('a deploy that eth_simulateV1 cannot build (anvil: missing "to") falls back to eth_call', async () => {
  // Response text and code observed from anvil for a creation call.
  const node = new FakeNode()
    .on(
      'eth_simulateV1',
      new UpstreamRpcError(
        -32602,
        `Invalid transaction request: Failed to build transaction: eip1559 transaction can't be built due to missing keys: ["to"]`,
      ),
    )
    .on('eth_call', new UpstreamRpcError(3, 'execution reverted', '0x'));
  const sim = ran(await simulateTransaction(tx({ to: null, data: '0x60006000fd' }), PORTAL, node));
  equal(sim.status, 'reverted');
  equal(sim.method, 'eth_call');
  equal(sim.revertReason, 'execution reverted');
  deepEqual(sim.notes, [
    'simulation: eth_call only (node cannot simulate a contract creation with eth_simulateV1)',
  ]);
  const call = node.calls[0]!.params[0] as { blockStateCalls: { calls: object[] }[] };
  equal('to' in (call.blockStateCalls[0]!.calls[0] as object), false);
  // The same -32602 for a normal call is NOT a fallback trigger.
  const n2 = new FakeNode().on('eth_simulateV1', new UpstreamRpcError(-32602, 'bad params'));
  equal((await simulateTransaction(tx(), PORTAL, n2)).status, 'unavailable');
});

test('oversized quantities from the node never reach the formatters', async () => {
  const huge = '0x' + 'f'.repeat(100_000);
  const start = Date.now();
  const sim = ran(
    await simulateTransaction(
      tx(),
      PORTAL,
      new FakeNode().on('eth_simulateV1', simResult({ gasUsed: huge })),
    ),
  );
  equal(sim.gasUsed, null);
  // Fallback path: an oversized eth_estimateGas is "unavailable", not a number.
  const fb = ran(
    await simulateTransaction(tx(), PORTAL, new FakeNode().on('eth_estimateGas', huge)),
  );
  equal(fb.gasUsed, null);
  ok(fb.notes.includes('gas estimate unavailable'), fb.notes.join('|'));
  ok(Date.now() - start < 500, `${Date.now() - start} ms`);
});

test('a known revert is never downgraded to unavailable by malformed secondary fields', async () => {
  for (const call of [
    { status: '0x0', logs: 5 },
    { status: '0x0', logs: 'x', gasUsed: 'nope', returnData: 12 },
    { status: '0x0', gasUsed: '0x' + 'f'.repeat(100), error: 'not-an-object' },
  ]) {
    const sim = await simulateTransaction(
      tx(),
      PORTAL,
      new FakeNode().on('eth_simulateV1', [{ calls: [call] }]),
    );
    equal(sim.status, 'reverted', JSON.stringify(call));
  }
  const s = ran(
    await simulateTransaction(
      tx(),
      PORTAL,
      new FakeNode().on('eth_simulateV1', [{ calls: [{ status: '0x0', logs: 5, gasUsed: 'x' }] }]),
    ),
  );
  deepEqual(s.notes, ['gasUsed not understood', 'logs not understood']);
  equal(s.transfers, null);
  equal(s.changes, null);
  // ok + malformed logs: still ok, balance changes unknown.
  const okSim = ran(
    await simulateTransaction(
      tx(),
      PORTAL,
      new FakeNode().on('eth_simulateV1', [{ calls: [{ status: '0x1', logs: {} }] }]),
    ),
  );
  equal(okSim.status, 'ok');
  equal(okSim.changes, null);
  // Only a missing/unparseable status is unavailable.
  equal(
    (
      await simulateTransaction(
        tx(),
        PORTAL,
        new FakeNode().on('eth_simulateV1', [{ calls: [{ logs: [] }] }]),
      )
    ).status,
    'unavailable',
  );
});

test('fallback: a malformed eth_call result is unavailable, never ok', async () => {
  for (const bad of [null, 5, '0x1', 'deadbeef', { result: '0x' }]) {
    const node = new FakeNode().on('eth_call', () => bad).on('eth_estimateGas', '0x5208');
    deepEqual(await simulateTransaction(tx(), PORTAL, node), {
      status: 'unavailable',
      reason: 'malformed eth_call result',
    });
  }
});

test('fallback: eth_estimateGas reverting makes the simulation reverted', async () => {
  const node = new FakeNode()
    .on('eth_call', '0x')
    .on('eth_estimateGas', new UpstreamRpcError(3, 'execution reverted', ERROR_STF));
  const sim = ran(await simulateTransaction(tx(), PORTAL, node));
  equal(sim.status, 'reverted');
  equal(sim.method, 'eth_call');
  equal(sim.revertReason, 'Error("STF")');
  // Any other estimate failure only loses the gas figure.
  const n2 = new FakeNode()
    .on('eth_call', '0x00')
    .on('eth_estimateGas', new UpstreamRpcError(-32000, 'rate limited'));
  const s2 = ran(await simulateTransaction(tx(), PORTAL, n2));
  equal(s2.status, 'ok');
  ok(s2.notes.includes('gas estimate unavailable'));
});

function simCall(node: FakeNode, i = 0): Record<string, unknown> {
  const p = node.calls.filter((c) => c.method === 'eth_simulateV1')[i]!.params[0] as {
    blockStateCalls: { calls: Record<string, unknown>[] }[];
  };
  return p.blockStateCalls[0]!.calls[0]!;
}

test('the simulated call carries nonce, fees, gas and access list exactly as signed', async () => {
  const node = new FakeNode().on('eth_simulateV1', simResult({}));
  const al = [{ address: USDC, storageKeys: ['0x' + '01'.padStart(64, '0')] }] as never;
  await simulateTransaction(tx({ nonce: 7n, accessList: al, gasLimit: 50_000n }), PORTAL, node);
  const c = simCall(node);
  equal(c['nonce'], '0x7');
  equal(c['gas'], '0xc350');
  equal(c['maxFeePerGas'], '0x6fc23ac00');
  equal(c['maxPriorityFeePerGas'], '0x3b9aca00');
  deepEqual(c['accessList'], [{ address: USDC, storageKeys: ['0x' + '01'.padStart(64, '0')] }]);
  equal('gasPrice' in c, false);

  const legacy = new FakeNode().on('eth_estimateGas', '0x5208').on('eth_call', '0x');
  await simulateTransaction(
    {
      type: 'legacy',
      chainId: 1n,
      nonce: 3n,
      gasPrice: 5n,
      gasLimit: 21_000n,
      to: SPENDER as `0x${string}`,
      value: 1n,
      data: '0x',
    },
    PORTAL,
    legacy,
  );
  // Same parameters reach the eth_call/eth_estimateGas fallback.
  for (const m of ['eth_simulateV1', 'eth_call', 'eth_estimateGas']) {
    const c2 = legacy.calls.find((x) => x.method === m)!;
    const obj = (
      m === 'eth_simulateV1'
        ? (c2.params[0] as { blockStateCalls: { calls: Record<string, unknown>[] }[] })
            .blockStateCalls[0]!.calls[0]!
        : c2.params[0]
    ) as Record<string, unknown>;
    equal(obj['gasPrice'], '0x5', m);
    equal(obj['nonce'], '0x3', m);
    equal(obj['gas'], '0x5208', m);
    equal('maxFeePerGas' in obj, false, m);
    equal('accessList' in obj, false, m);
  }
});

test('gasLimit below 21000 is unavailable without asking the node', async () => {
  const node = new FakeNode().on('eth_simulateV1', simResult({}));
  deepEqual(await simulateTransaction(tx({ gasLimit: 0n }), PORTAL, node), {
    status: 'unavailable',
    reason: 'gasLimit 0 cannot be simulated or sent',
  });
  const s = await simulateTransaction(tx({ gasLimit: 20_999n }), PORTAL, node);
  equal(s.status, 'unavailable');
  ok((s as { reason: string }).reason.includes('below the 21000 intrinsic minimum'));
  deepEqual(node.calls, []);
});

test('insufficient funds with fee fields: one retry without them, noted', async () => {
  // anvil's behaviour for an unfunded sender once fee fields are present.
  const node = new FakeNode().on('eth_simulateV1', (params: readonly unknown[]) => {
    const c = (params[0] as { blockStateCalls: { calls: Record<string, unknown>[] }[] })
      .blockStateCalls[0]!.calls[0]!;
    return 'maxFeePerGas' in c
      ? new UpstreamRpcError(-32003, 'Insufficient funds for gas * price + value')
      : simResult({});
  });
  const sim = ran(await simulateTransaction(tx(), PORTAL, node));
  equal(sim.status, 'ok');
  deepEqual(sim.notes, [
    'simulation: fee fields (maxFeePerGas, maxPriorityFeePerGas) dropped — the node required the sender to fund gas × price; the contract saw tx.gasprice = 0',
  ]);
  const retried = simCall(node, 1);
  equal(retried['nonce'], '0x0');
  equal(retried['gas'], '0x30d40');
  // If even the value can't be covered, the error stands (no second retry).
  const broke = new FakeNode().on(
    'eth_simulateV1',
    new UpstreamRpcError(-32003, 'Insufficient funds for gas * price + value'),
  );
  const s2 = await simulateTransaction(tx(), PORTAL, broke);
  equal(s2.status, 'unavailable');
  equal(broke.calls.filter((c) => c.method === 'eth_simulateV1').length, 2);
});
