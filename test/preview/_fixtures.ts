import type { Eip1559Tx } from '../../src/eth/index.js';
import { UpstreamRpcError, type JsonRpcUpstream } from '../../src/rpc/index.js';

/** One left-padded 32-byte word (no 0x). Addresses may be passed with 0x. */
export function w(v: string | number | bigint): string {
  const h = typeof v === 'string' ? v.replace(/^0x/, '') : v.toString(16);
  return h.padStart(64, '0');
}

/** ABI-encode a single `string` return value. */
export function encString(s: string): string {
  const h = Buffer.from(s, 'utf8').toString('hex');
  const padded = h.padEnd(Math.max(64, Math.ceil(h.length / 64) * 64), '0');
  return '0x' + w(0x20) + w(h.length / 2) + padded;
}

export const MAX = 'f'.repeat(64);

export const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
export const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2';
export const MKR = '0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2';
export const ROUTER = '0xe592427a0aece92de3edee1f18e0157c05861564';
export const POOL = '0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640';
export const PORTAL = '0x2278aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa931c';
export const SPENDER = '0x1111111111111111111111111111111111111111';
export const NFT = '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d';

export const TOPIC = {
  Transfer: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
  Approval: '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
  ApprovalForAll: '0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31',
  TransferSingle: '0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62',
  TransferBatch: '0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb',
  Deposit: '0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c',
  Withdrawal: '0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65',
};

export const t = (addr: string): string => '0x' + w(addr);

export function tx(over: Partial<Eip1559Tx> = {}): Eip1559Tx {
  return {
    type: 'eip1559',
    chainId: 1n,
    nonce: 0n,
    maxPriorityFeePerGas: 1_000_000_000n,
    maxFeePerGas: 30_000_000_000n,
    gasLimit: 200_000n,
    to: USDC,
    value: 0n,
    data: '0x',
    ...over,
  };
}

type Handler = (params: readonly unknown[]) => unknown;

/**
 * Scripted JSON-RPC node. Handlers per method; eth_call is further routed by
 * `${to}:${data}` so token metadata can be scripted per token. Anything
 * unscripted answers like a node that lacks the method.
 */
export class FakeNode implements JsonRpcUpstream {
  calls: { method: string; params: unknown[] }[] = [];
  handlers = new Map<string, Handler>();
  ethCalls = new Map<string, unknown>();

  on(method: string, h: Handler | unknown): this {
    this.handlers.set(method, typeof h === 'function' ? (h as Handler) : () => h);
    return this;
  }

  token(addr: string, symbol: string | undefined, decimals: number | undefined): this {
    this.ethCalls.set(
      `${addr}:0x95d89b41`,
      symbol === undefined ? new UpstreamRpcError(3, 'execution reverted') : encString(symbol),
    );
    this.ethCalls.set(
      `${addr}:0x313ce567`,
      decimals === undefined ? new UpstreamRpcError(3, 'execution reverted') : '0x' + w(decimals),
    );
    return this;
  }

  async call(method: string, params: readonly unknown[]): Promise<unknown> {
    this.calls.push({ method, params: [...params] });
    if (method === 'eth_call' && !this.handlers.has('eth_call')) {
      const p = params[0] as { to?: string; data?: string };
      const key = `${p.to}:${p.data}`;
      if (this.ethCalls.has(key)) {
        const r = this.ethCalls.get(key);
        if (r instanceof Error) throw r;
        return r;
      }
      return '0x';
    }
    const h = this.handlers.get(method);
    if (!h)
      throw new UpstreamRpcError(-32601, `the method ${method} does not exist/is not available`);
    const r = h(params);
    if (r instanceof Error) throw r;
    return r;
  }
}

export function simResult(call: Record<string, unknown>): unknown {
  return [
    {
      number: '0x1',
      calls: [{ status: '0x1', gasUsed: '0x5208', returnData: '0x', logs: [], ...call }],
    },
  ];
}
