import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { AbiRegistry, buildTxPreview } from '../../src/preview/index.js';
import { assessTokens, canonicalToken } from '../../src/preview/trust.js';
import {
  FakeNode,
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
const ATTACKER = '0x6666666666666666666666666666666666666666';
const FAKE = [
  '0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1',
  '0xa2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2',
  '0xa3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3',
];

const credit = (token: string, amount: bigint) => ({
  address: token,
  topics: [TOPIC.Transfer, t(ATTACKER), t(PORTAL)],
  data: '0x' + w(amount),
});
const debit = (token: string, amount: bigint) => ({
  address: token,
  topics: [TOPIC.Transfer, t(PORTAL), t(ATTACKER)],
  data: '0x' + w(amount),
});

test('repro: fake "USDC" credits cannot hide a real USDC drain behind a WETH-looking deposit()', async () => {
  const node = new FakeNode()
    .on(
      'eth_simulateV1',
      simResult({
        logs: [
          credit(FAKE[0]!, 1_000_000n),
          credit(FAKE[1]!, 1_000_000n),
          credit(FAKE[2]!, 1_000_000n),
          debit(USDC, 1_000_000_000_000n), // the genuine transferFrom drain
        ],
      }),
    )
    .token(USDC, 'USDC', 6);
  for (const f of FAKE) node.token(f, 'USDC', 6);
  const p = await buildTxPreview({
    tx: tx({ to: ATTACKER as `0x${string}`, data: '0xd0e30db0' }),
    from: PORTAL,
    registry: EMPTY,
    simulator: node,
  });
  // The debit is listed first and in full; the call is not called a "wrap".
  ok(
    p.headline.startsWith(
      'deposit() on 0x6666…6666 | sim ok -1,000,000 USDC +1 "USDC"? (0xa1a1…a1a1)',
    ),
    p.headline,
  );
  ok(!p.headline.includes('wrap'), p.headline);
  ok(p.headline.includes('⚠'), p.headline);
  for (const f of FAKE) {
    ok(
      p.warnings.includes(
        `token at ${f.slice(0, 6)}…${f.slice(-4)} calls itself USDC but is not the known USDC on chain 1`,
      ),
      p.warnings.join('\n'),
    );
  }
  ok(
    p.warnings.includes(
      'selector matches WETH deposit() but the contract did not behave like WETH',
    ),
  );
  ok(p.warnings.includes('inflows from unverified tokens — check the debit'));
  ok(p.warnings.some((x) => x.startsWith('4 different tokens call themselves USDC')));
  // The real USDC keeps its plain name everywhere.
  ok(
    p.text.includes('balance changes for 0x2278…931c: -1,000,000 USDC, +1 "USDC"? (0xa1a1…a1a1)'),
    p.text,
  );
});

test('debits are never truncated; credits give way with "+N more in"', async () => {
  const debitTokens = Array.from({ length: 8 }, (_, i) => '0x' + (i + 1).toString(16).repeat(40));
  const creditTokens = Array.from(
    { length: 12 },
    (_, i) => '0x' + 'c'.repeat(38) + i.toString(16).padStart(2, '0'),
  );
  const node = new FakeNode().on(
    'eth_simulateV1',
    simResult({
      logs: [
        ...creditTokens.map((c) => credit(c, 5n)),
        ...debitTokens.map((d) => debit(d, 7n)),
        {
          address: USDC,
          topics: [TOPIC.Approval, t(PORTAL), t(SPENDER)],
          data: '0x' + 'f'.repeat(64),
        },
      ],
    }),
  );
  const p = await buildTxPreview({
    tx: tx({ to: ROUTER, data: ('0x12345678' + '00'.repeat(32)) as `0x${string}` }),
    from: PORTAL,
    registry: EMPTY,
    simulator: node,
  });
  for (const d of debitTokens) ok(p.headline.includes(`-7 of ${d.slice(0, 6)}…${d.slice(-4)}`), d);
  ok(p.headline.includes('grants 0xa0b8…eb48 → 0x1111…1111 UNLIMITED'), p.headline);
  ok(/\+\d+ more in/.test(p.headline), p.headline);
  // Every debit precedes every credit.
  const lastDebit = p.headline.lastIndexOf('-7 of');
  const firstCredit = p.headline.indexOf('+5 of');
  ok(firstCredit === -1 || firstCredit > lastDebit, p.headline);
  ok(p.headline.includes('⚠'), p.headline);
});

test('assessTokens: canonical names pass, impersonators and collisions are quoted', () => {
  const real = assessTokens({ [USDC]: { symbol: 'USDC', decimals: 6 } }, 1n);
  deepEqual(real.warnings, []);
  equal(real.meta[USDC]!.symbol, 'USDC');
  equal(real.unverified.size, 0);

  // Mainnet USDC's address is not USDC on Base.
  const base = assessTokens({ [USDC]: { symbol: 'USDC', decimals: 6 } }, 8453n);
  equal(base.meta[USDC]!.symbol, '"USDC"? (0xa0b8…eb48)');
  deepEqual(base.warnings, [
    'token at 0xa0b8…eb48 calls itself USDC but is not the known USDC on chain 8453',
  ]);

  // Unknown chain: a well-known name can't be verified, so it is quoted.
  equal(
    assessTokens({ [WETH]: { symbol: 'weth' } }, 999n).meta[WETH]!.symbol,
    '"weth"? (0xc02a…6cc2)',
  );
  // "ETH" is native — no ERC-20 is ever the real one.
  ok(assessTokens({ [FAKE[0]!]: { symbol: 'ETH' } }, 1n).unverified.has(FAKE[0]!));

  // Two unknown-name tokens sharing a symbol: both quoted.
  const col = assessTokens({ [FAKE[0]!]: { symbol: 'PEPE' }, [FAKE[1]!]: { symbol: 'PEPE' } }, 1n);
  equal(col.meta[FAKE[0]!]!.symbol, '"PEPE"? (0xa1a1…a1a1)');
  equal(col.meta[FAKE[1]!]!.symbol, '"PEPE"? (0xa2a2…a2a2)');
  deepEqual(col.warnings, ['2 different tokens call themselves PEPE: 0xa1a1…a1a1, 0xa2a2…a2a2']);
  // A missing symbol is unverified but not renamed.
  const nosym = assessTokens({ [FAKE[0]!]: { decimals: 18 } }, 1n);
  ok(nosym.unverified.has(FAKE[0]!));
  equal(nosym.meta[FAKE[0]!]!.symbol, undefined);

  equal(canonicalToken(11155111n, 'usdc'), '0x1c7d4b196cb0c7b01d743fbc6116a902379c7238');
});

test('a real WETH deposit keeps "wrap"; withdraw without a Withdrawal does not keep "withdraw"', async () => {
  const node = new FakeNode()
    .on(
      'eth_simulateV1',
      simResult({
        logs: [{ address: WETH, topics: [TOPIC.Deposit, t(PORTAL)], data: '0x' + w(10n ** 17n) }],
      }),
    )
    .token(WETH, 'WETH', 18);
  const ok1 = await buildTxPreview({
    tx: tx({ to: WETH, value: 10n ** 17n, data: '0xd0e30db0' }),
    from: PORTAL,
    registry: EMPTY,
    simulator: node,
  });
  ok(ok1.headline.startsWith('wrap 0.1 ETH | sim ok -0.1 ETH +0.1 WETH'), ok1.headline);
  deepEqual(ok1.warnings, []);

  const fakeWd = await buildTxPreview({
    tx: tx({ to: ATTACKER as `0x${string}`, data: `0x2e1a7d4d${w(5)}` }),
    from: PORTAL,
    registry: EMPTY,
    simulator: new FakeNode().on('eth_simulateV1', simResult({})),
  });
  ok(fakeWd.headline.startsWith('withdraw(amount=5) on 0x6666…6666'), fakeWd.headline);
  ok(
    fakeWd.warnings.includes(
      'selector matches WETH withdraw(uint256) but the contract did not behave like WETH',
    ),
  );
});

test('a "swap" with no output to the portal and a "transfer" that moves nothing lose their verbs', async () => {
  const swapData =
    '0x414bf389' + w(USDC) + w(WETH) + w(500) + w(PORTAL) + w(1) + w(1_000_000n) + w(1) + w(0);
  const swap = await buildTxPreview({
    tx: tx({ to: ROUTER, data: swapData as `0x${string}` }),
    from: PORTAL,
    registry: EMPTY,
    simulator: new FakeNode().on('eth_simulateV1', simResult({ logs: [debit(USDC, 1_000_000n)] })),
  });
  ok(swap.headline.startsWith('exactInputSingle(params=('), swap.headline);
  ok(
    swap.warnings.includes(
      'selector matches a Uniswap exactInputSingle but no swap output reached the portal',
    ),
  );

  const xfer = await buildTxPreview({
    tx: tx({ to: ATTACKER as `0x${string}`, data: `0xa9059cbb${w(SPENDER)}${w(1)}` }),
    from: PORTAL,
    registry: EMPTY,
    simulator: new FakeNode().on('eth_simulateV1', simResult({})),
  });
  ok(xfer.headline.startsWith('transfer(to=0x1111…1111, amount=1) on 0x6666…6666'), xfer.headline);
  ok(xfer.warnings.some((x) => x.startsWith('selector matches ERC-20 transfer()')));

  // Without logs (no simulation) nothing can be contradicted: verbs stay.
  const nosim = await buildTxPreview({
    tx: tx({ to: ATTACKER as `0x${string}`, data: `0xa9059cbb${w(SPENDER)}${w(1)}` }),
    from: PORTAL,
    registry: EMPTY,
  });
  ok(nosim.headline.startsWith('transfer 1 of'), nosim.headline);
});
