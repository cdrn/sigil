import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { functionSelector } from '../../src/eth/index.js';
import {
  AbiRegistry,
  decodeCalldata,
  decodeV3Path,
  KNOWN_FUNCTIONS,
  type TokenMetaLookup,
} from '../../src/preview/index.js';
import { MAX, NFT, PORTAL, ROUTER, SPENDER, USDC, w, WETH } from './_fixtures.js';

const EMPTY = AbiRegistry.empty();
const hex = (s: string): Buffer => Buffer.from(s.replace(/^0x/, ''), 'hex');
const META: TokenMetaLookup = (a) =>
  a === USDC
    ? { symbol: 'USDC', decimals: 6 }
    : a === WETH
      ? { symbol: 'WETH', decimals: 18 }
      : undefined;

test('KNOWN_FUNCTIONS: every built-in has a distinct, correct selector', () => {
  const expected: Record<string, string> = {
    '0xa9059cbb': 'transfer(address,uint256)',
    '0x095ea7b3': 'approve(address,uint256)',
    '0x23b872dd': 'transferFrom(address,address,uint256)',
    '0x39509351': 'increaseAllowance(address,uint256)',
    '0xa457c2d7': 'decreaseAllowance(address,uint256)',
    '0xa22cb465': 'setApprovalForAll(address,bool)',
    '0x42842e0e': 'safeTransferFrom(address,address,uint256)',
    '0xb88d4fde': 'safeTransferFrom(address,address,uint256,bytes)',
    '0xf242432a': 'safeTransferFrom(address,address,uint256,uint256,bytes)',
    '0x2eb2c2d6': 'safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)',
    '0xd0e30db0': 'deposit()',
    '0x2e1a7d4d': 'withdraw(uint256)',
    '0x87517c45': 'approve(address,address,uint160,uint48)',
    '0x38ed1739': 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)',
    '0x7ff36ab5': 'swapExactETHForTokens(uint256,address[],address,uint256)',
    '0x18cbafe5': 'swapExactTokensForETH(uint256,uint256,address[],address,uint256)',
    '0x8803dbee': 'swapTokensForExactTokens(uint256,uint256,address[],address,uint256)',
    '0x414bf389':
      'exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))',
    '0x04e45aaf': 'exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))',
    '0xc04b8d59': 'exactInput((bytes,address,uint256,uint256,uint256))',
    '0xdb3e2198':
      'exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))',
    '0x3593564c': 'execute(bytes,bytes[],uint256)',
    '0xac9650d8': 'multicall(bytes[])',
    '0x5ae401dc': 'multicall(uint256,bytes[])',
  };
  equal(KNOWN_FUNCTIONS.size, Object.keys(expected).length);
  for (const [sel, sig] of Object.entries(expected)) {
    equal(KNOWN_FUNCTIONS.get(sel)?.signature, sig, sel);
  }
});

test('empty calldata, deploy, too-short and unknown selectors', () => {
  const plain = decodeCalldata(new Uint8Array(0), EMPTY, undefined, { to: USDC });
  equal(plain.source, 'empty');
  equal(plain.text, 'plain ETH transfer');
  equal(plain.selector, null);

  const deploy = decodeCalldata(hex('6080604052'), EMPTY, undefined, { to: null });
  equal(deploy.source, 'deploy');
  equal(deploy.text, 'contract creation, 5-byte initcode');

  const short = decodeCalldata(hex('abcd'), EMPTY);
  equal(short.source, 'unknown');
  ok(short.warnings[0]!.includes('too short'));

  const unknown = decodeCalldata(hex('12345678' + w(1)), EMPTY);
  equal(unknown.source, 'unknown');
  equal(unknown.selector, '0x12345678');
  equal(unknown.text, 'unknown function 0x12345678 (36 bytes calldata)');
  deepEqual(unknown.warnings, ['unknown selector 0x12345678 — calldata not decoded']);
});

test('ERC-20 transfer: raw without metadata, units with it', () => {
  const data = hex('a9059cbb' + w(SPENDER) + w(1_000_500_000n));
  const raw = decodeCalldata(data, EMPTY, undefined, { to: USDC });
  equal(raw.source, 'builtin');
  equal(raw.text, 'transfer(to=0x1111…1111, amount=1000500000)');
  equal(raw.short, 'transfer 1000500000 of 0xa0b8…eb48 → 0x1111…1111');
  deepEqual(raw.args, [
    { name: 'to', type: 'address', value: SPENDER },
    { name: 'amount', type: 'uint256', value: '1000500000' },
  ]);
  deepEqual(raw.tokens, [USDC]);

  const nice = decodeCalldata(data, EMPTY, META, { to: USDC });
  equal(nice.text, 'transfer(to=0x1111…1111, amount=1,000.5 USDC)');
  equal(nice.short, 'transfer 1,000.5 USDC → 0x1111…1111');
});

test('approve: max uint and ≥ 2^255 are UNLIMITED; zero spender warns', () => {
  const max = decodeCalldata(hex('095ea7b3' + w(SPENDER) + MAX), EMPTY, META, { to: USDC });
  equal(max.text, 'approve(spender=0x1111…1111, amount=UNLIMITED)');
  equal(max.short, 'approve UNLIMITED USDC → 0x1111…1111');
  deepEqual(max.warnings, ['UNLIMITED approval']);

  const big = decodeCalldata(hex('095ea7b3' + w(SPENDER) + w(1n << 255n)), EMPTY, META, {
    to: USDC,
  });
  deepEqual(big.warnings, ['UNLIMITED approval']);

  const bounded = decodeCalldata(hex('095ea7b3' + w(SPENDER) + w(5_000_000n)), EMPTY, META, {
    to: USDC,
  });
  equal(bounded.short, 'approve 5 USDC → 0x1111…1111');
  deepEqual(bounded.warnings, []);

  const zero = decodeCalldata(hex('095ea7b3' + w(0) + w(1)), EMPTY, undefined, { to: USDC });
  deepEqual(zero.warnings, ['approve to the zero address']);
  const burn = decodeCalldata(hex('a9059cbb' + w(0) + w(1)), EMPTY, undefined, { to: USDC });
  deepEqual(burn.warnings, ['transfer to the zero address']);
});

test('increaseAllowance unlimited warns; decreaseAllowance does not', () => {
  const inc = decodeCalldata(hex('39509351' + w(SPENDER) + MAX), EMPTY, META, { to: USDC });
  deepEqual(inc.warnings, ['UNLIMITED approval']);
  const dec = decodeCalldata(hex('a457c2d7' + w(SPENDER) + w(1)), EMPTY, META, { to: USDC });
  deepEqual(dec.warnings, []);
  ok(dec.short!.startsWith('lower allowance'));
});

test('setApprovalForAll(true) warns, (false) is a revoke', () => {
  const on = decodeCalldata(hex('a22cb465' + w(SPENDER) + w(1)), EMPTY, undefined, { to: NFT });
  equal(on.short, 'approve ALL of 0xbc4c…f13d → 0x1111…1111');
  deepEqual(on.warnings, [
    'setApprovalForAll: 0x1111…1111 gets control of EVERY token in 0xbc4c…f13d',
  ]);
  const off = decodeCalldata(hex('a22cb465' + w(SPENDER) + w(0)), EMPTY, undefined, { to: NFT });
  deepEqual(off.warnings, []);
  equal(off.short, 'revoke 0x1111…1111 on 0xbc4c…f13d');
});

test('ERC-721 safeTransferFrom (both overloads) and ERC-1155 transfers', () => {
  const a = decodeCalldata(hex('42842e0e' + w(PORTAL) + w(SPENDER) + w(42)), EMPTY, undefined, {
    to: NFT,
  });
  equal(a.short, 'send NFT 0xbc4c…f13d #42 → 0x1111…1111');
  const b = decodeCalldata(
    hex('b88d4fde' + w(PORTAL) + w(SPENDER) + w(42) + w(0x80) + w(0)),
    EMPTY,
    undefined,
    { to: NFT },
  );
  equal(b.short, a.short);
  const single = decodeCalldata(
    hex('f242432a' + w(PORTAL) + w(SPENDER) + w(7) + w(5) + w(0xa0) + w(0)),
    EMPTY,
    undefined,
    { to: NFT },
  );
  equal(single.short, 'send 5 × id 7 of 0xbc4c…f13d → 0x1111…1111');
  const batch = decodeCalldata(
    hex(
      '2eb2c2d6' +
        w(PORTAL) +
        w(SPENDER) +
        w(0xa0) +
        w(0x100) +
        w(0x160) +
        w(2) +
        w(1) +
        w(2) +
        w(2) +
        w(10) +
        w(20) +
        w(0),
    ),
    EMPTY,
    undefined,
    { to: NFT },
  );
  equal(batch.short, 'send 2 token ids of 0xbc4c…f13d → 0x1111…1111');
});

test('WETH deposit/withdraw', () => {
  const dep = decodeCalldata(hex('d0e30db0'), EMPTY, undefined, { to: WETH, value: 10n ** 17n });
  equal(dep.text, 'deposit() — wrap 0.1 ETH');
  const wd = decodeCalldata(hex('2e1a7d4d' + w(10n ** 17n)), EMPTY, META, { to: WETH });
  equal(wd.short, 'withdraw 0.1 WETH');
});

test('Permit2 approve: uint160 max is UNLIMITED and the token comes from the args', () => {
  const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';
  const d = decodeCalldata(
    hex('87517c45' + w(USDC) + w(SPENDER) + w((1n << 160n) - 1n) + w(1_700_000_000)),
    EMPTY,
    META,
    { to: PERMIT2 },
  );
  equal(
    d.text,
    'Permit2 approve(token=USDC, spender=0x1111…1111, amount=UNLIMITED, expiration=2023-11-14T22:13:20Z)',
  );
  equal(d.short, 'Permit2: approve UNLIMITED USDC → 0x1111…1111');
  deepEqual(d.warnings, ['UNLIMITED approval']);
  deepEqual(d.tokens, [USDC]);
});

test('Uniswap V2 swaps: units, recipient and slippage warnings', () => {
  // swapExactTokensForTokens(1000 USDC, 0 min, [USDC, WETH], to=SPENDER, deadline)
  const data = hex(
    '38ed1739' +
      w(1_000_000_000n) +
      w(0) +
      w(0xa0) +
      w(SPENDER) +
      w(1_700_000_000) +
      w(2) +
      w(USDC) +
      w(WETH),
  );
  const d = decodeCalldata(data, EMPTY, META, { to: ROUTER, from: PORTAL });
  equal(d.short, 'swap 1,000 USDC → ≥0 WETH');
  deepEqual(d.warnings, [
    'swap output goes to 0x1111…1111, not the portal',
    'swap has no slippage protection (minimum output 0)',
  ]);
  deepEqual(d.tokens, [USDC, WETH]);
  ok(d.text.includes('path=USDC→WETH'));

  const eth = decodeCalldata(
    hex('7ff36ab5' + w(1_000_000_000n) + w(0x80) + w(PORTAL) + w(1) + w(2) + w(WETH) + w(USDC)),
    EMPTY,
    META,
    { to: ROUTER, from: PORTAL, value: 10n ** 18n },
  );
  equal(eth.short, 'swap 1 ETH → ≥1,000 USDC');
  deepEqual(eth.warnings, []);
});

test('Uniswap V3 exactInputSingle / exactInput / exactOutputSingle', () => {
  const single = decodeCalldata(
    hex(
      '414bf389' +
        w(USDC) +
        w(WETH) +
        w(500) +
        w(PORTAL) +
        w(1_700_000_000) +
        w(1_000_000_000n) +
        w(5n * 10n ** 17n) +
        w(0),
    ),
    EMPTY,
    META,
    { to: ROUTER, from: PORTAL },
  );
  equal(single.short, 'swap 1,000 USDC → ≥0.5 WETH');
  deepEqual(single.warnings, []);

  const path = USDC.slice(2) + '0001f4' + WETH.slice(2);
  const multi = decodeCalldata(
    hex(
      'c04b8d59' +
        w(0x20) +
        w(0xa0) +
        w(PORTAL) +
        w(1) +
        w(1_000_000_000n) +
        w(1) +
        w(43) +
        path.padEnd(128, '0'),
    ),
    EMPTY,
    META,
    { to: ROUTER, from: PORTAL },
  );
  equal(multi.short, 'swap 1,000 USDC → ≥0.000000000000000001 WETH');
  ok(multi.text.startsWith('exactInput(path=USDC→WETH'));

  const out = decodeCalldata(
    hex(
      'db3e2198' +
        w(USDC) +
        w(WETH) +
        w(500) +
        w(PORTAL) +
        w(1) +
        w(10n ** 18n) +
        w(3_000_000_000n) +
        w(0),
    ),
    EMPTY,
    META,
    { to: ROUTER, from: PORTAL },
  );
  equal(out.short, 'swap ≤3,000 USDC → 1 WETH');
});

test('decodeV3Path: valid and malformed', () => {
  deepEqual(decodeV3Path('0x' + USDC.slice(2) + '000bb8' + WETH.slice(2)), [USDC, WETH]);
  equal(decodeV3Path('0x1234'), null);
});

test('Universal Router execute names the command count', () => {
  const d = decodeCalldata(
    hex('3593564c' + w(0x60) + w(0xa0) + w(1_700_000_000) + w(2) + '0b00'.padEnd(64, '0') + w(0)),
    EMPTY,
    undefined,
    { to: ROUTER },
  );
  equal(d.short, 'Universal Router: 2 commands');
  ok(d.text.includes('0x0b00'));
});

test('multicall decodes inner calls one level deep and prefixes their warnings', () => {
  const inner1 = 'a9059cbb' + w(SPENDER) + w(5_000_000n);
  const inner2 = '095ea7b3' + w(SPENDER) + MAX;
  const len1 = inner1.length / 2;
  const len2 = inner2.length / 2;
  const pad = (h: string): string => h.padEnd(Math.ceil(h.length / 64) * 64, '0');
  const data = hex(
    'ac9650d8' +
      w(0x20) +
      w(2) +
      w(0x40) +
      w(0x40 + 32 + pad(inner1).length / 2) +
      w(len1) +
      pad(inner1) +
      w(len2) +
      pad(inner2),
  );
  const d = decodeCalldata(data, EMPTY, META, { to: USDC });
  equal(d.short, 'multicall: transfer 5 USDC → 0x1111…1111 + approve UNLIMITED USDC → 0x1111…1111');
  deepEqual(d.warnings, ['multicall[1]: UNLIMITED approval']);
  ok(d.text.startsWith('multicall(2 calls: transfer('));

  // A multicall nested inside a multicall is not decoded further.
  const nested = 'ac9650d8' + w(0x20) + w(0);
  const outer = hex('ac9650d8' + w(0x20) + w(1) + w(0x20) + w(nested.length / 2) + pad(nested));
  const o = decodeCalldata(outer, EMPTY, META, { to: USDC });
  equal(o.text, 'multicall(1 call: multicall(0 calls: ))');
});

test('calldata that does not match its selector warns instead of throwing', () => {
  const d = decodeCalldata(hex('a9059cbb' + w(SPENDER)), EMPTY, undefined, { to: USDC });
  equal(d.source, 'builtin');
  equal(d.text, 'transfer(…) — calldata does not match transfer(address,uint256)');
  ok(d.warnings[0]!.startsWith('calldata does not decode as transfer(address,uint256)'));
});

test('user ABI: decodes unknown selectors with argument names; renames built-in args', () => {
  const registry = AbiRegistry.fromSources([
    {
      name: 'Vault.json',
      text: JSON.stringify([
        {
          type: 'function',
          name: 'setFee',
          inputs: [
            { name: 'feeBps', type: 'uint16' },
            { name: 'note', type: 'string' },
          ],
        },
        {
          type: 'function',
          name: 'transfer',
          inputs: [
            { name: 'recipient', type: 'address' },
            { name: 'wad', type: 'uint256' },
          ],
        },
      ]),
    },
  ]);
  const sel = functionSelector('setFee(uint16,string)');
  const note = Buffer.from('hi').toString('hex').padEnd(64, '0');
  const d = decodeCalldata(hex(sel + w(30) + w(0x40) + w(2) + note), registry, undefined, {
    to: SPENDER,
  });
  equal(d.source, 'abi');
  equal(d.signature, 'setFee(uint16,string)');
  equal(d.text, 'setFee(feeBps=30, note="hi")');
  deepEqual(d.warnings, []);

  // Same selector as the built-in transfer: built-in sentence, user's names.
  const t = decodeCalldata(hex('a9059cbb' + w(SPENDER) + w(1)), registry, undefined, { to: USDC });
  equal(t.source, 'builtin');
  ok(t.text.startsWith('transfer(to='));
  deepEqual(
    t.args!.map((a) => a.name),
    ['recipient', 'wad'],
  );
});

test('generic rendering truncates long bytes and caps the call line', () => {
  const registry = AbiRegistry.fromSources([
    {
      name: 'Blob.json',
      text: JSON.stringify([{ name: 'put', inputs: [{ name: 'blob', type: 'bytes' }] }]),
    },
  ]);
  const body = 'ab'.repeat(100);
  const d = decodeCalldata(
    hex(functionSelector('put(bytes)') + w(0x20) + w(100) + body.padEnd(256, '0')),
    registry,
  );
  equal(d.args![0]!.value, `0x${'ab'.repeat(32)}…(100 bytes)`);
  ok(d.text.length <= 400);
});
