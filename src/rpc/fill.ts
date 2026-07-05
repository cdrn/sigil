import { UpstreamRpcError, type JsonRpcUpstream } from './upstream.js';

/**
 * Turn an eth_sendTransaction/eth_signTransaction params object (JSON-RPC
 * hex quantities, missing fields allowed) into the fully-specified tx shape
 * sigil's daemon dispatch expects (decimal-string quantities, every field
 * present). Missing nonce/gas/fees are filled from the upstream node.
 *
 * This runs BEFORE policy — it only shapes the request; every security
 * decision (chain allowlist, destination allowlist, value cap, contract
 * creation, confirm) happens inside the daemon sign path the result is
 * dispatched to.
 */

const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const QTY_RE = /^0x[0-9a-fA-F]+$/;
const DATA_RE = /^0x[0-9a-fA-F]*$/;

/** Invalid client input. The proxy maps this to JSON-RPC -32602. */
export class FillParamsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FillParamsError';
  }
}

export interface FillContext {
  /** The portal's EVM address, lowercase. `from` must match it. */
  portalAddress: string;
  /** Chain ID reported by the upstream node (eth_chainId). */
  chainId: bigint;
  upstream: JsonRpcUpstream;
}

/** The daemon `tx` param shape (decimal strings; see daemon/methods.ts asTx). */
export type FilledTx = Record<string, unknown>;

/** Fallback priority fee when the node doesn't serve eth_maxPriorityFeePerGas. */
const DEFAULT_TIP_WEI = 1_000_000_000n; // 1 gwei

/** Headroom multiplier applied to eth_estimateGas (×1.2). Estimates are the
 *  simulated minimum; state moving between estimate and inclusion makes the
 *  exact value flaky, and unused gas is refunded. */
const GAS_HEADROOM_NUM = 12n;
const GAS_HEADROOM_DEN = 10n;

export async function fillTransaction(
  raw: Record<string, unknown>,
  fill: FillContext,
): Promise<FilledTx> {
  // --- from: required, must be the portal's own address -------------------
  const from = raw['from'];
  if (typeof from !== 'string' || !ADDR_RE.test(from)) {
    throw new FillParamsError('tx.from is required and must be a 0x address');
  }
  if (from.toLowerCase() !== fill.portalAddress) {
    throw new FillParamsError(
      `unknown account ${from} — this endpoint signs only for ${fill.portalAddress}`,
    );
  }

  // --- chainId: optional, but must match the upstream if given ------------
  if (raw['chainId'] !== undefined) {
    const chainId = qty(raw['chainId'], 'chainId');
    if (chainId !== fill.chainId) {
      throw new FillParamsError(
        `tx.chainId ${chainId} does not match upstream chain ${fill.chainId}`,
      );
    }
  }

  // --- to: absent/null = contract creation --------------------------------
  const toRaw = raw['to'];
  let to: string | null;
  if (toRaw === undefined || toRaw === null) {
    to = null;
  } else if (typeof toRaw === 'string' && ADDR_RE.test(toRaw)) {
    to = toRaw;
  } else {
    throw new FillParamsError('tx.to must be a 0x address, null, or omitted');
  }

  // --- data / input: spec-standard alias pair -----------------------------
  const data = pickData(raw);

  const value = raw['value'] === undefined ? 0n : qty(raw['value'], 'value');

  // --- nonce ---------------------------------------------------------------
  const nonce = raw['nonce'] !== undefined
    ? qty(raw['nonce'], 'nonce')
    : qtyResult(
        await fill.upstream.call('eth_getTransactionCount', [from, 'pending']),
        'eth_getTransactionCount',
      );

  // --- gas limit ------------------------------------------------------------
  let gasLimit: bigint;
  if (raw['gas'] !== undefined) {
    gasLimit = qty(raw['gas'], 'gas');
  } else {
    const estimateParams: Record<string, unknown> = {
      from,
      data,
      value: toQtyHex(value),
      ...(to !== null ? { to } : {}),
    };
    const estimated = qtyResult(
      await fill.upstream.call('eth_estimateGas', [estimateParams]),
      'eth_estimateGas',
    );
    gasLimit = (estimated * GAS_HEADROOM_NUM) / GAS_HEADROOM_DEN;
  }

  const common = {
    chainId: fill.chainId.toString(),
    nonce: nonce.toString(),
    gasLimit: gasLimit.toString(),
    to,
    value: value.toString(),
    data,
  };

  // --- fees -----------------------------------------------------------------
  const hasGasPrice = raw['gasPrice'] !== undefined;
  const hasMaxFee = raw['maxFeePerGas'] !== undefined;
  const hasTip = raw['maxPriorityFeePerGas'] !== undefined;
  if (hasGasPrice && (hasMaxFee || hasTip)) {
    throw new FillParamsError('tx mixes gasPrice with maxFeePerGas/maxPriorityFeePerGas');
  }

  if (hasGasPrice) {
    return { ...common, type: 'legacy', gasPrice: qty(raw['gasPrice'], 'gasPrice').toString() };
  }

  // EIP-1559 by default; fall back to legacy on a pre-London chain (no
  // baseFeePerGas in the latest block).
  let maxFeePerGas = hasMaxFee ? qty(raw['maxFeePerGas'], 'maxFeePerGas') : undefined;
  let tip = hasTip ? qty(raw['maxPriorityFeePerGas'], 'maxPriorityFeePerGas') : undefined;

  if (maxFeePerGas === undefined || tip === undefined) {
    const baseFee = await fetchBaseFee(fill.upstream);
    if (baseFee === undefined) {
      // Pre-London chain: no 1559 fields exist to fill; sign legacy instead.
      const gasPrice = qtyResult(await fill.upstream.call('eth_gasPrice', []), 'eth_gasPrice');
      return { ...common, type: 'legacy', gasPrice: gasPrice.toString() };
    }
    if (tip === undefined) {
      tip = await fetchTip(fill.upstream);
      // A filled tip must never exceed a caller-provided fee cap.
      if (maxFeePerGas !== undefined && tip > maxFeePerGas) tip = maxFeePerGas;
    }
    if (maxFeePerGas === undefined) {
      // 2× base fee absorbs six consecutive max-increase blocks before the
      // cap binds — the standard wallet heuristic.
      maxFeePerGas = baseFee * 2n + tip;
    }
  }
  if (maxFeePerGas < tip) {
    throw new FillParamsError('tx.maxFeePerGas is less than maxPriorityFeePerGas');
  }

  return {
    ...common,
    type: 'eip1559',
    maxFeePerGas: maxFeePerGas.toString(),
    maxPriorityFeePerGas: tip.toString(),
  };
}

/** Extract calldata, honouring the data/input alias pair: either alone is
 *  fine, both must agree (viem and recent forge send both). */
function pickData(raw: Record<string, unknown>): string {
  const data = raw['data'];
  const input = raw['input'];
  const check = (v: unknown, name: string): string => {
    if (typeof v !== 'string' || !DATA_RE.test(v)) {
      throw new FillParamsError(`tx.${name} must be 0x-prefixed hex`);
    }
    return v;
  };
  if (data !== undefined && input !== undefined) {
    const d = check(data, 'data');
    const i = check(input, 'input');
    if (d.toLowerCase() !== i.toLowerCase()) {
      throw new FillParamsError('tx.data and tx.input are both set and disagree');
    }
    return d;
  }
  if (data !== undefined) return check(data, 'data');
  if (input !== undefined) return check(input, 'input');
  return '0x';
}

async function fetchBaseFee(upstream: JsonRpcUpstream): Promise<bigint | undefined> {
  const block = await upstream.call('eth_getBlockByNumber', ['latest', false]);
  if (typeof block !== 'object' || block === null) {
    throw new FillParamsError('upstream eth_getBlockByNumber returned no block');
  }
  const baseFee = (block as Record<string, unknown>)['baseFeePerGas'];
  if (baseFee === undefined || baseFee === null) return undefined;
  return qtyResult(baseFee, 'baseFeePerGas');
}

async function fetchTip(upstream: JsonRpcUpstream): Promise<bigint> {
  try {
    return qtyResult(
      await upstream.call('eth_maxPriorityFeePerGas', []),
      'eth_maxPriorityFeePerGas',
    );
  } catch (err) {
    // Method not on every node; a sane constant beats failing the sign.
    if (err instanceof UpstreamRpcError) return DEFAULT_TIP_WEI;
    throw err;
  }
}

/** Parse a client-supplied JSON-RPC quantity (0x hex string, or a plain
 *  number some loose clients send). */
function qty(v: unknown, name: string): bigint {
  if (typeof v === 'string') {
    if (!QTY_RE.test(v)) {
      throw new FillParamsError(`tx.${name} must be a 0x-prefixed hex quantity`);
    }
    return BigInt(v);
  }
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) {
    return BigInt(v);
  }
  throw new FillParamsError(`tx.${name} must be a 0x-prefixed hex quantity`);
}

/** Parse a quantity out of an upstream RESPONSE — failures here are the
 *  node's fault, not the client's, so the error names the source method. */
function qtyResult(v: unknown, source: string): bigint {
  if (typeof v !== 'string' || !QTY_RE.test(v)) {
    throw new FillParamsError(`upstream ${source} returned a malformed quantity`);
  }
  return BigInt(v);
}

function toQtyHex(v: bigint): string {
  return '0x' + v.toString(16);
}
