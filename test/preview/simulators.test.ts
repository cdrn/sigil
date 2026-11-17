import { test } from 'node:test';
import { deepEqual, equal } from 'node:assert/strict';
import type { JsonRpcUpstream } from '../../src/rpc/index.js';
import { SimulatorResolver } from '../../src/preview/index.js';

class Node implements JsonRpcUpstream {
  calls = 0;
  constructor(
    readonly url: string,
    readonly chain: () => unknown,
  ) {}
  async call(method: string): Promise<unknown> {
    this.calls++;
    if (method !== 'eth_chainId') throw new Error('unexpected');
    const v = this.chain();
    if (v instanceof Error) throw v;
    return v;
  }
}

function factory(chain: () => unknown = () => '0x1'): {
  made: Node[];
  make: (url: string) => Node;
} {
  const made: Node[] = [];
  return {
    made,
    make: (url) => {
      const n = new Node(url, chain);
      made.push(n);
      return n;
    },
  };
}

test('explicit [simulate.rpc] chains get one cached upstream each; others get none', async () => {
  const f = factory();
  const r = new SimulatorResolver({
    rpcByChain: new Map([
      [11155111n, 'https://sepolia.example'],
      [1n, 'https://eth.example'],
    ]),
    makeUpstream: f.make,
  });
  deepEqual(r.configuredChains, [1n, 11155111n]);
  equal(r.hasProxyFallback, false);
  const a = await r.simulatorFor(1n);
  const b = await r.simulatorFor(1n);
  equal(a, b);
  equal((a as Node).url, 'https://eth.example');
  equal(await r.simulatorFor(10n), undefined);
  equal(f.made.length, 1); // lazy: sepolia not created until used
});

test('[rpc] upstream serves its own chain, resolved once via eth_chainId', async () => {
  const f = factory(() => '0xaa36a7'); // 11155111
  const r = new SimulatorResolver({
    rpcByChain: new Map(),
    proxyUpstream: 'https://proxy.example',
    makeUpstream: f.make,
  });
  equal(r.hasProxyFallback, true);
  const [x, y] = await Promise.all([r.simulatorFor(11155111n), r.simulatorFor(11155111n)]);
  equal((x as Node).url, 'https://proxy.example');
  equal(x, y);
  equal(await r.simulatorFor(1n), undefined); // a different chain is not served
  equal(f.made.length, 1);
  equal(f.made[0]!.calls, 1);
});

test('an explicit entry wins over the [rpc] upstream for the same chain', async () => {
  const f = factory(() => '0x1');
  const r = new SimulatorResolver({
    rpcByChain: new Map([[1n, 'https://explicit.example']]),
    proxyUpstream: 'https://proxy.example',
    makeUpstream: f.make,
  });
  equal(((await r.simulatorFor(1n)) as Node).url, 'https://explicit.example');
});

test('a failed eth_chainId means no simulator, retried only after a cool-down', async () => {
  let answer: unknown = new Error('connection refused');
  let now = 1_000_000;
  const f = factory(() => answer);
  const r = new SimulatorResolver({
    rpcByChain: new Map(),
    proxyUpstream: 'https://proxy.example',
    makeUpstream: f.make,
    now: () => now,
  });
  equal(await r.simulatorFor(1n), undefined);
  equal(await r.simulatorFor(1n), undefined); // within cool-down: not retried
  equal(f.made[0]!.calls, 1);
  answer = 'garbage';
  now += 61_000;
  equal(await r.simulatorFor(1n), undefined); // malformed answer is a failure too
  equal(f.made[0]!.calls, 2);
  answer = '0x1';
  now += 61_000;
  equal(((await r.simulatorFor(1n)) as Node).url, 'https://proxy.example');
  equal(f.made[0]!.calls, 3);
});
