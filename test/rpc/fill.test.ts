import { test } from 'node:test';
import { deepEqual, equal, ok, rejects } from 'node:assert/strict';
import { fillTransaction, FillParamsError, UpstreamRpcError, type JsonRpcUpstream } from '../../src/rpc/index.js';

const FROM = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf';
const DEST = '0x000000000000000000000000000000000000dead';
const GWEI = '0x3b9aca00'; // 1 gwei

/** Scripted upstream: canned response (or Error) per method, calls recorded. */
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
  calledMethods(): string[] {
    return this.calls.map((c) => c.method);
  }
}

function londonUpstream(): FakeUpstream {
  const up = new FakeUpstream();
  up.responses.set('eth_getTransactionCount', '0x5');
  up.responses.set('eth_estimateGas', '0x5208'); // 21000
  up.responses.set('eth_getBlockByNumber', { baseFeePerGas: GWEI });
  up.responses.set('eth_maxPriorityFeePerGas', GWEI);
  up.responses.set('eth_gasPrice', '0x77359400'); // 2 gwei
  return up;
}

function ctx(up: JsonRpcUpstream) {
  return { portalAddress: FROM, chainId: 1n, upstream: up };
}

// ---------------------------------------------------------------------------
// happy paths
// ---------------------------------------------------------------------------

test('fill: minimal tx gets nonce, gas ×1.2, and EIP-1559 fees from upstream', async () => {
  const up = londonUpstream();
  const tx = await fillTransaction({ from: FROM, to: DEST }, ctx(up));
  deepEqual(tx, {
    type: 'eip1559',
    chainId: '1',
    nonce: '5',
    gasLimit: '25200',              // 21000 × 1.2
    to: DEST,
    value: '0',
    data: '0x',
    maxPriorityFeePerGas: '1000000000',
    maxFeePerGas: '3000000000',     // 2 × 1 gwei base + 1 gwei tip
  });
});

test('fill: caller-provided nonce/gas/fees are respected — zero upstream calls', async () => {
  const up = new FakeUpstream(); // nothing scripted: any call would throw
  const tx = await fillTransaction({
    from: FROM, to: DEST,
    nonce: '0x2a', gas: '0x30d40',
    maxFeePerGas: '0x77359400', maxPriorityFeePerGas: GWEI,
    value: '0x64', data: '0xa9059cbb',
  }, ctx(up));
  equal(tx['nonce'], '42');
  equal(tx['gasLimit'], '200000');
  equal(tx['maxFeePerGas'], '2000000000');
  equal(tx['maxPriorityFeePerGas'], '1000000000');
  equal(tx['value'], '100');
  equal(tx['data'], '0xa9059cbb');
  deepEqual(up.calls, []);
});

test('fill: gasPrice → legacy tx', async () => {
  const up = londonUpstream();
  const tx = await fillTransaction(
    { from: FROM, to: DEST, gasPrice: GWEI, nonce: '0x0', gas: '0x5208' },
    ctx(up),
  );
  equal(tx['type'], 'legacy');
  equal(tx['gasPrice'], '1000000000');
  equal(tx['maxFeePerGas'], undefined);
});

test('fill: pre-London chain (no baseFeePerGas) falls back to legacy via eth_gasPrice', async () => {
  const up = londonUpstream();
  up.responses.set('eth_getBlockByNumber', { number: '0x1' }); // no baseFeePerGas
  const tx = await fillTransaction({ from: FROM, to: DEST, nonce: '0x0', gas: '0x5208' }, ctx(up));
  equal(tx['type'], 'legacy');
  equal(tx['gasPrice'], '2000000000');
});

test('fill: tip falls back to 1 gwei when eth_maxPriorityFeePerGas is unsupported', async () => {
  const up = londonUpstream();
  up.responses.set(
    'eth_maxPriorityFeePerGas',
    new UpstreamRpcError(-32601, 'the method does not exist'),
  );
  const tx = await fillTransaction({ from: FROM, to: DEST, nonce: '0x0', gas: '0x5208' }, ctx(up));
  equal(tx['maxPriorityFeePerGas'], '1000000000');
});

test('fill: fetched tip is clamped to a caller-provided maxFeePerGas', async () => {
  const up = londonUpstream();
  up.responses.set('eth_maxPriorityFeePerGas', '0x77359400'); // 2 gwei tip...
  const tx = await fillTransaction({
    from: FROM, to: DEST, nonce: '0x0', gas: '0x5208',
    maxFeePerGas: GWEI, // ...but cap is 1 gwei
  }, ctx(up));
  equal(tx['maxPriorityFeePerGas'], '1000000000');
  equal(tx['maxFeePerGas'], '1000000000');
});

test('fill: omitted/null `to` becomes contract creation (to: null)', async () => {
  const up = londonUpstream();
  const initcode = '0x6080604052600080fd';
  const omitted = await fillTransaction({ from: FROM, data: initcode }, ctx(up));
  equal(omitted['to'], null);
  equal(omitted['data'], initcode);
  const explicit = await fillTransaction({ from: FROM, to: null, data: initcode }, ctx(up));
  equal(explicit['to'], null);
  // The gas estimate for a creation tx must not carry a `to` field.
  const estimate = up.calls.find((c) => c.method === 'eth_estimateGas')!;
  equal((estimate.params[0] as Record<string, unknown>)['to'], undefined);
});

test('fill: `input` is accepted as the data alias; both set must agree', async () => {
  const up = londonUpstream();
  const viaInput = await fillTransaction({ from: FROM, to: DEST, input: '0xbeef' }, ctx(up));
  equal(viaInput['data'], '0xbeef');
  const both = await fillTransaction(
    { from: FROM, to: DEST, data: '0xBEEF', input: '0xbeef' },
    ctx(up),
  );
  equal(both['data'], '0xBEEF');
  await rejects(
    () => fillTransaction({ from: FROM, to: DEST, data: '0xbeef', input: '0xdead' }, ctx(up)),
    /disagree/,
  );
});

// ---------------------------------------------------------------------------
// rejections
// ---------------------------------------------------------------------------

test('fill: missing or non-portal `from` is rejected', async () => {
  const up = londonUpstream();
  await rejects(() => fillTransaction({ to: DEST }, ctx(up)), /from is required/);
  await rejects(
    () => fillTransaction({ from: DEST, to: DEST }, ctx(up)),
    (err: Error) => err instanceof FillParamsError && /unknown account/.test(err.message),
  );
});

test('fill: `from` match is case-insensitive', async () => {
  const up = londonUpstream();
  const tx = await fillTransaction({ from: FROM.toUpperCase().replace('0X', '0x'), to: DEST }, ctx(up));
  equal(tx['type'], 'eip1559');
});

test('fill: tx.chainId that disagrees with the upstream chain is rejected', async () => {
  const up = londonUpstream();
  await rejects(
    () => fillTransaction({ from: FROM, to: DEST, chainId: '0x89' }, ctx(up)),
    /does not match upstream chain/,
  );
  // Matching chainId is fine.
  const tx = await fillTransaction({ from: FROM, to: DEST, chainId: '0x1' }, ctx(up));
  equal(tx['chainId'], '1');
});

test('fill: mixing gasPrice with 1559 fee fields is rejected', async () => {
  const up = londonUpstream();
  await rejects(
    () => fillTransaction({ from: FROM, to: DEST, gasPrice: GWEI, maxFeePerGas: GWEI }, ctx(up)),
    /mixes gasPrice/,
  );
});

test('fill: caller maxFeePerGas below caller tip is rejected', async () => {
  const up = londonUpstream();
  await rejects(
    () => fillTransaction({
      from: FROM, to: DEST, nonce: '0x0', gas: '0x5208',
      maxFeePerGas: GWEI, maxPriorityFeePerGas: '0x77359400',
    }, ctx(up)),
    /less than maxPriorityFeePerGas/,
  );
});

test('fill: malformed quantities and addresses are rejected', async () => {
  const up = londonUpstream();
  await rejects(() => fillTransaction({ from: FROM, to: 'dead' }, ctx(up)), /tx\.to/);
  await rejects(
    () => fillTransaction({ from: FROM, to: DEST, value: 'lots' }, ctx(up)),
    /tx\.value/,
  );
  await rejects(
    () => fillTransaction({ from: FROM, to: DEST, nonce: -1 }, ctx(up)),
    /tx\.nonce/,
  );
  await rejects(
    () => fillTransaction({ from: FROM, to: DEST, data: 'beef' }, ctx(up)),
    /tx\.data/,
  );
});

test('fill: malformed upstream quantity names the source method', async () => {
  const up = londonUpstream();
  up.responses.set('eth_getTransactionCount', 'not-a-quantity');
  await rejects(
    () => fillTransaction({ from: FROM, to: DEST }, ctx(up)),
    /upstream eth_getTransactionCount/,
  );
});

test('fill: value flows into the gas estimate params as hex', async () => {
  const up = londonUpstream();
  await fillTransaction({ from: FROM, to: DEST, value: '0x64' }, ctx(up));
  const estimate = up.calls.find((c) => c.method === 'eth_estimateGas')!;
  const params = estimate.params[0] as Record<string, unknown>;
  equal(params['value'], '0x64');
  equal(params['from'], FROM);
  equal(params['to'], DEST);
});

test('fill: nonce is fetched with the "pending" block tag', async () => {
  const up = londonUpstream();
  ok((await fillTransaction({ from: FROM, to: DEST }, ctx(up)))['nonce'] === '5');
  const call = up.calls.find((c) => c.method === 'eth_getTransactionCount')!;
  deepEqual(call.params, [FROM, 'pending']);
});
