import { AbiDecodeError, decodeAbiParameters } from '../eth/abi.js';
import type { SignableTx } from '../eth/index.js';
import { type JsonRpcUpstream, UpstreamRpcError } from '../rpc/upstream.js';
import { EVENT_TOPICS } from './known.js';
import type { TokenMeta } from './types.js';
import { hexQuantity, MAX_QTY_HEX_DIGITS, sanitizeSymbol, ZERO_ADDRESS } from './units.js';

/**
 * Dry-run a transaction on the user's configured RPC node and summarize
 * what it would do to the portal: status, gas, revert reason, native and
 * token balance deltas, approvals granted.
 *
 * Primary primitive: eth_simulateV1 (one call; geth, reth, anvil and the
 * big hosted providers serve it) with `traceTransfers`, which also reports
 * native ETH movements as synthetic ERC-20-style Transfer logs. Nodes that
 * don't serve it get an eth_call + eth_estimateGas fallback: status and gas
 * only, balance changes unknown.
 *
 * Never throws. Any transport failure, timeout or malformed node response
 * becomes `{ status: 'unavailable', reason }` — the caller decides whether
 * that matters (policy `require_simulation`) or is just a warning.
 *
 * Trust: the node is the user's own choice and the tx would be broadcast
 * there anyway, but its answer is not authenticated. Logs are whatever the
 * simulated contracts chose to emit — a scam token can emit a Transfer it
 * never performed, and call itself "USDC". The result is a strong hint for
 * a human, not a proof.
 */

export const DEFAULT_SIM_TIMEOUT_MS = 15_000;
/** Most tokens whose symbol()/decimals() we look up per simulation. */
const MAX_META_TOKENS = 10;
/** Transfers kept for the long-form listing. */
const MAX_TRANSFERS = 32;
/** Intrinsic gas of the cheapest possible transaction. */
const MIN_GAS = 21_000n;

/**
 * Addresses traceTransfers uses for synthetic native-ETH Transfer logs.
 * geth emits them from ERC-7528's 0xEeee…EEeE, reth (seen on v2.11 against
 * Sepolia) from 0xffff…fffe, and some implementations and docs use the zero
 * address. All are treated as native ETH — none can host a real token
 * contract emitting events (the two high addresses are precompile-range
 * reserved; the zero address has no code).
 */
const NATIVE_SENTINELS: ReadonlySet<string> = new Set([
  ZERO_ADDRESS,
  '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  '0xfffffffffffffffffffffffffffffffffffffffe',
]);

/**
 * A call that reverts with no data while having burned (almost) all of its
 * gas limit ran out of gas: EIP-150 keeps 1/64 for the caller, so a true
 * out-of-gas lands just under the limit rather than exactly on it. A
 * real revert with no reason string stops well short. Seen live: a USDC
 * approve on Sepolia needs ~140k gas; with gas_limit 100000 reth reported
 * status 0x0, data 0x, gasUsed 98844 — a bare "execution reverted" that
 * would send the human chasing a contract bug instead of a gas limit.
 */
const OOG_NUM = 95n;
const OOG_DEN = 100n;
export function outOfGasReason(gasUsed: bigint | null, gasLimit: bigint): string | null {
  if (gasUsed === null || gasLimit <= 0n) return null;
  if (gasUsed * OOG_DEN < gasLimit * OOG_NUM) return null;
  return `likely out of gas (used ${gasUsed} of the ${gasLimit} gas limit — raise gasLimit)`;
}

export interface SimTransfer {
  standard: 'native' | 'erc20' | 'erc721' | 'erc1155';
  /** Token contract (lowercase); null for native ETH. */
  token: string | null;
  from: string;
  to: string;
  /** Wei / token units / 1 for an ERC-721. */
  amount: bigint;
  tokenId?: bigint;
}

export interface WrapEvent {
  token: string;
  who: string;
  kind: 'deposit' | 'withdrawal';
  amount: bigint;
}

export interface SimApproval {
  standard: 'erc20' | 'erc721' | 'operator';
  token: string;
  spender: string;
  /** ERC-20 allowance. 0 = revoke. */
  amount?: bigint;
  /** ERC-721 single-token approval. */
  tokenId?: bigint;
  /** ApprovalForAll: true grants, false revokes. */
  approved?: boolean;
}

export interface BalanceChanges {
  /** Net native wei for the portal, excluding gas. */
  native: bigint;
  erc20: { token: string; delta: bigint }[];
  nftIn: { token: string; tokenId: bigint }[];
  nftOut: { token: string; tokenId: bigint }[];
  erc1155: { token: string; tokenId: bigint; delta: bigint }[];
}

export type Simulation =
  | {
      status: 'ok' | 'reverted';
      method: 'eth_simulateV1' | 'eth_call';
      gasUsed: bigint | null;
      revertReason?: string;
      /** null = unknown (eth_call fallback has no logs). */
      transfers: SimTransfer[] | null;
      /** Transfers beyond MAX_TRANSFERS that were not listed. */
      transfersOmitted: number;
      changes: BalanceChanges | null;
      approvals: SimApproval[] | null;
      /**
       * WETH9-style Deposit/Withdrawal events (all of them, never truncated):
       * the evidence that a `deposit()`/`withdraw()` really wrapped/unwrapped.
       */
      wraps: WrapEvent[] | null;
      /**
       * False when the node only accepted the call without the signed fee
       * fields (the contract saw tx.gasprice = 0): it simulated a different
       * transaction, so require_simulation does not accept it.
       */
      faithful: boolean;
      notes: string[];
      /** symbol/decimals per lowercase token address, where readable. */
      tokenMeta: Readonly<Record<string, TokenMeta>>;
    }
  | { status: 'unavailable'; reason: string };

export interface SimulateOpts {
  /** Per-RPC-call timeout; the whole simulation is bounded at 2×. */
  timeoutMs?: number;
  /** Extra token addresses to fetch metadata for (e.g. the `to` of an approve). */
  extraTokens?: readonly string[];
}

export async function simulateTransaction(
  tx: SignableTx,
  from: string,
  upstream: JsonRpcUpstream,
  opts: SimulateOpts = {},
): Promise<Simulation> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_SIM_TIMEOUT_MS;
  // A gas limit below the intrinsic 21000 can never be included; and with
  // 0 the node would substitute its own limit, simulating a different tx
  // than the one being signed. Unavailable, so require_simulation denies.
  const gas = BigInt(tx.gasLimit);
  if (gas < MIN_GAS) {
    return {
      status: 'unavailable',
      reason:
        gas === 0n
          ? 'gasLimit 0 cannot be simulated or sent'
          : `gasLimit ${gas} is below the 21000 intrinsic minimum and cannot be simulated or sent`,
    };
  }
  const running = run(tx, from.toLowerCase(), upstream, timeoutMs, opts.extraTokens ?? []);
  running.catch(() => {
    /* settled below or abandoned after the overall timeout */
  });
  try {
    return await withTimeout(
      running,
      timeoutMs * 2,
      `simulation timed out after ${timeoutMs * 2} ms`,
    );
  } catch (err) {
    return { status: 'unavailable', reason: errText(err) };
  }
}

async function run(
  tx: SignableTx,
  from: string,
  upstream: JsonRpcUpstream,
  timeoutMs: number,
  extraTokens: readonly string[],
): Promise<Simulation> {
  const call = (method: string, params: unknown[]): Promise<unknown> =>
    withTimeout(
      upstream.call(method, params),
      timeoutMs,
      `${method} timed out after ${timeoutMs} ms`,
    );

  const to = tx.to === null ? null : tx.to.toLowerCase();
  const value = BigInt(tx.value);
  const dataHex =
    typeof tx.data === 'string' ? tx.data.toLowerCase() : '0x' + tx.data.toString('hex');
  const gas = BigInt(tx.gasLimit);
  // Simulate exactly the parameters that will be signed. A contract can
  // branch on tx.gasprice, gasleft() or the nonce, so a call built from
  // from/to/value/data alone is a different transaction.
  const base: Record<string, unknown> = {
    from,
    ...(to !== null ? { to } : {}),
    value: qtyHex(value),
    data: dataHex,
    gas: qtyHex(gas),
    nonce: qtyHex(BigInt(tx.nonce)),
    ...(tx.type === 'eip1559'
      ? {
          accessList: (tx.accessList ?? []).map((a) => ({
            address: a.address.toLowerCase(),
            storageKeys: a.storageKeys.map((k) => k.toLowerCase()),
          })),
        }
      : {}),
  };
  const feeFields: Record<string, string> =
    tx.type === 'eip1559'
      ? {
          maxFeePerGas: qtyHex(BigInt(tx.maxFeePerGas)),
          maxPriorityFeePerGas: qtyHex(BigInt(tx.maxPriorityFeePerGas)),
        }
      : { gasPrice: qtyHex(BigInt(tx.gasPrice)) };
  const full = { ...base, ...feeFields };
  let callObj: Record<string, unknown> = full;

  const notes: string[] = [];
  let faithful = true;
  /**
   * Some nodes (anvil, verified) enforce balance ≥ gas × price + value even
   * with validation:false once fee fields are present; others (reth) don't.
   * When the node refuses for insufficient funds, retry ONCE without the
   * fee fields and say so — the simulation then saw tx.gasprice = 0. If the
   * retry is refused too, the sender can't even cover the value: that error
   * stands.
   */
  const viaNode = async (
    method: string,
    params: (obj: Record<string, unknown>) => unknown[],
  ): Promise<unknown> => {
    try {
      return await call(method, params(callObj));
    } catch (e) {
      if (callObj !== full || !isInsufficientFunds(e)) throw e;
      callObj = base;
      faithful = false;
      notes.push(
        `simulation: fee fields (${Object.keys(feeFields).join(', ')}) dropped — the node ` +
          `required the sender to fund gas × price; the contract saw tx.gasprice = 0`,
      );
      return await call(method, params(callObj));
    }
  };

  let method: 'eth_simulateV1' | 'eth_call' = 'eth_simulateV1';
  let status: 'ok' | 'reverted' | undefined;
  let gasUsed: bigint | null = null;
  let revertReason: string | undefined;
  let logs: RawLog[] | null = null;

  try {
    const res = await viaNode('eth_simulateV1', (obj) => [
      { blockStateCalls: [{ calls: [obj] }], traceTransfers: true, validation: false },
      'latest',
    ]);
    const parsed = parseSimulateV1(res);
    status = parsed.ok ? 'ok' : 'reverted';
    gasUsed = parsed.gasUsed;
    logs = parsed.logs;
    notes.push(...parsed.notes);
    if (!parsed.ok) {
      revertReason = parsed.revertReason;
      if (parsed.bareRevert) revertReason = outOfGasReason(gasUsed, gas) ?? revertReason;
    }
  } catch (err) {
    // Some nodes serve eth_simulateV1 but can't build a creation call with
    // it (anvil rejects a missing `to`); eth_call handles deploys fine.
    const deployRejected =
      to === null && err instanceof UpstreamRpcError && !isRevert(err) && err.code === -32602;
    if (err instanceof UpstreamRpcError && (isUnsupported(err) || deployRejected)) {
      method = 'eth_call';
      notes.push(
        deployRejected
          ? 'simulation: eth_call only (node cannot simulate a contract creation with eth_simulateV1)'
          : 'simulation: eth_call only (node lacks eth_simulateV1)',
      );
      // Only a well-formed answer counts as success: an eth_call result is
      // return data (hex bytes); null, a number or odd-length hex means we
      // don't know what happened.
      let callOk = false;
      try {
        const ret = await viaNode('eth_call', (obj) => [obj, 'latest']);
        if (typeof ret !== 'string' || !RETURN_DATA_RE.test(ret)) {
          throw new Error('malformed eth_call result', { cause: err });
        }
        callOk = true;
      } catch (e) {
        if (!(e instanceof UpstreamRpcError) || !isRevert(e)) throw e;
        status = 'reverted';
        revertReason = revertFromRpcError(e);
      }
      if (callOk) {
        status = 'ok';
        // eth_estimateGas re-executes the call; if it reverts there, the tx
        // reverts — that is a result, not a missing gas figure.
        try {
          gasUsed = parseQty(await viaNode('eth_estimateGas', (obj) => [obj]), 'eth_estimateGas');
        } catch (e) {
          if (e instanceof UpstreamRpcError && isRevert(e)) {
            status = 'reverted';
            revertReason = revertFromRpcError(e);
          } else {
            notes.push('gas estimate unavailable');
          }
        }
      }
    } else if (err instanceof UpstreamRpcError && isRevert(err)) {
      // Some nodes surface a revert of the (only) call as a top-level error.
      status = 'reverted';
      revertReason = revertFromRpcError(err);
      logs = [];
    } else {
      throw err;
    }
  }

  let transfers: SimTransfer[] | null = null;
  let approvals: SimApproval[] | null = null;
  let wraps: WrapEvent[] | null = null;
  let changes: BalanceChanges | null = null;
  let omitted = 0;
  if (logs !== null) {
    const analysis = analyzeLogs(logs, from, { to, value });
    if (analysis.malformed > 0) {
      notes.push(`${analysis.malformed} log${analysis.malformed === 1 ? '' : 's'} not understood`);
    }
    omitted = Math.max(0, analysis.transfers.length - MAX_TRANSFERS);
    transfers = analysis.transfers.slice(0, MAX_TRANSFERS);
    approvals = analysis.approvals;
    wraps = analysis.wraps;
    changes = analysis.changes;
  }

  // Token metadata: every ERC-20 touched, plus what the decoder asked for.
  const wanted: string[] = [];
  const want = (t: string | null): void => {
    if (t === null || NATIVE_SENTINELS.has(t) || wanted.includes(t)) return;
    if (wanted.length < MAX_META_TOKENS) wanted.push(t);
  };
  for (const t of extraTokens) want(t.toLowerCase());
  for (const c of changes?.erc20 ?? []) want(c.token);
  for (const t of transfers ?? []) if (t.standard === 'erc20') want(t.token);
  for (const ap of approvals ?? []) if (ap.standard === 'erc20') want(ap.token);
  const metaEntries = await Promise.all(
    wanted.map(async (t) => [t, await fetchTokenMeta(t, call)] as const),
  );
  const tokenMeta: Record<string, TokenMeta> = {};
  for (const [t, m] of metaEntries) {
    if (m.symbol !== undefined || m.decimals !== undefined) tokenMeta[t] = m;
  }

  if (status === undefined) throw new Error('internal: simulation status unset');
  return {
    status,
    method,
    gasUsed,
    ...(revertReason !== undefined ? { revertReason } : {}),
    transfers,
    transfersOmitted: omitted,
    changes,
    approvals,
    wraps,
    faithful,
    notes,
    tokenMeta,
  };
}

// ---------------------------------------------------------------------------
// eth_simulateV1 response
// ---------------------------------------------------------------------------

export interface RawLog {
  address: string;
  topics: string[];
  data: string;
}

class SimShapeError extends Error {
  constructor(message: string) {
    super(`eth_simulateV1 returned an unexpected shape: ${message}`);
    this.name = 'SimShapeError';
  }
}

/**
 * Status is read first and is the only field whose absence makes the
 * result unusable. Once the node has said "reverted", nothing else in the
 * response may downgrade that to "unavailable" — a malformed `logs` or
 * `gasUsed` next to a known revert would otherwise slip a reverting tx past
 * sign_on_revert = false. Malformed secondary fields become notes, with
 * logs null (balance changes unknown).
 */
function parseSimulateV1(res: unknown): {
  ok: boolean;
  gasUsed: bigint | null;
  revertReason?: string;
  /** Reverted with no revert data at all (out-of-gas looks like this). */
  bareRevert?: boolean;
  logs: RawLog[] | null;
  notes: string[];
} {
  if (!Array.isArray(res) || res.length === 0) throw new SimShapeError('no blocks');
  const block = res[0] as Record<string, unknown>;
  const calls = isObj(block) ? block['calls'] : undefined;
  if (!Array.isArray(calls) || calls.length === 0 || !isObj(calls[0])) {
    throw new SimShapeError('no call results');
  }
  const c = calls[0];
  const st = c['status'];
  if (st !== '0x1' && st !== '0x0' && st !== '0x01' && st !== '0x00') {
    throw new SimShapeError(`status ${JSON.stringify(st)}`);
  }
  const ok = st === '0x1' || st === '0x01';
  const notes: string[] = [];
  const gasUsed = hexQuantity(c['gasUsed']);
  if (gasUsed === null && c['gasUsed'] !== undefined) notes.push('gasUsed not understood');
  const rawLogs = c['logs'] ?? [];
  let logs: RawLog[] | null = null;
  if (Array.isArray(rawLogs)) {
    logs = rawLogs.filter(isObj).map((l) => ({
      address: typeof l['address'] === 'string' ? l['address'].toLowerCase() : '',
      topics: Array.isArray(l['topics'])
        ? l['topics'].map((t) => (typeof t === 'string' ? t.toLowerCase() : ''))
        : [],
      data: typeof l['data'] === 'string' ? l['data'].toLowerCase() : '',
    }));
  } else {
    notes.push('logs not understood');
  }
  if (ok) return { ok, gasUsed, logs, notes };
  const err = isObj(c['error']) ? c['error'] : undefined;
  const errData = typeof err?.['data'] === 'string' ? err['data'] : undefined;
  const ret = typeof c['returnData'] === 'string' ? c['returnData'] : undefined;
  const bytes = errData ?? ret;
  let revertReason: string;
  let bareRevert = false;
  if (bytes !== undefined && bytes !== '0x' && HEX_RE.test(bytes)) {
    revertReason = decodeRevert(bytes);
  } else {
    bareRevert = true;
    revertReason =
      typeof err?.['message'] === 'string'
        ? cleanMessage(err['message'])
        : 'execution reverted (no reason)';
  }
  return { ok, gasUsed, revertReason, bareRevert, logs, notes };
}

// ---------------------------------------------------------------------------
// Revert decoding
// ---------------------------------------------------------------------------

const PANIC_CODES: Readonly<Record<string, string>> = {
  '0': 'generic compiler panic',
  '1': 'assertion failed',
  '17': 'arithmetic overflow/underflow',
  '18': 'division or modulo by zero',
  '33': 'invalid enum value',
  '34': 'invalid storage byte array encoding',
  '49': 'pop on empty array',
  '50': 'array index out of bounds',
  '65': 'out of memory / allocation too large',
  '81': 'call to an uninitialized internal function',
};

/**
 * Human text for revert data. Error(string) and Panic(uint256) are decoded;
 * anything else is named by its selector. The reason string is chosen by
 * the reverting contract — JSON-quoted and truncated so it can't break the
 * layout of a push notification or impersonate sigil's own lines.
 */
export function decodeRevert(hex: string): string {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (body.length === 0) return 'execution reverted (no reason)';
  if (body.length < 8 || body.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(body)) {
    return `malformed revert data (${Math.floor(body.length / 2)} bytes)`;
  }
  const sel = body.slice(0, 8).toLowerCase();
  const args = Buffer.from(body.slice(8), 'hex');
  if (sel === '08c379a0') {
    try {
      const [msg] = decodeAbiParameters(['string'], args) as [string];
      const clipped = msg.length > 160 ? msg.slice(0, 160) + '…' : msg;
      return `Error(${JSON.stringify(clipped)})`;
    } catch (err) {
      if (!(err instanceof AbiDecodeError)) throw err;
    }
  } else if (sel === '4e487b71') {
    try {
      const [code] = decodeAbiParameters(['uint256'], args) as [bigint];
      const name = PANIC_CODES[code.toString()];
      return `Panic(0x${code.toString(16)}${name ? `: ${name}` : ''})`;
    } catch (err) {
      if (!(err instanceof AbiDecodeError)) throw err;
    }
  }
  return `custom error 0x${sel} (${body.length / 2} bytes)`;
}

function revertFromRpcError(e: UpstreamRpcError): string {
  if (typeof e.data === 'string' && e.data !== '0x' && HEX_RE.test(e.data)) {
    return decodeRevert(e.data);
  }
  return cleanMessage(e.message);
}

/** Node error messages are short and node-authored, but may embed a revert string. */
function cleanMessage(m: string): string {
  const t = Array.from(m, (ch) => (ch.charCodeAt(0) < 0x20 || ch === '\u007f' ? ' ' : ch))
    .join('')
    .trim();
  return t.length > 160 ? t.slice(0, 160) + '…' : t;
}

/**
 * Exactly anvil's refusal (-32003 "Insufficient funds for gas * price +
 * value"). Both the code and the message must match: the fee-stripped
 * retry simulates a different tx, so it must not be reachable through any
 * other error a node (or something in front of it) can produce.
 */
function isInsufficientFunds(e: unknown): boolean {
  return (
    e instanceof UpstreamRpcError &&
    e.code === -32003 &&
    !isRevert(e) &&
    /insufficient funds/i.test(e.message)
  );
}

function isRevert(e: UpstreamRpcError): boolean {
  return e.code === 3 || /revert/i.test(e.message);
}

/** The node doesn't serve the method (vs. the call failing). */
function isUnsupported(e: UpstreamRpcError): boolean {
  if (isRevert(e)) return false;
  return e.code === -32601 || /not supported|does not exist/i.test(e.message);
}

// ---------------------------------------------------------------------------
// Log analysis
// ---------------------------------------------------------------------------

const HEX_RE = /^0x[0-9a-fA-F]*$/;
/** Return data: whole bytes of hex. */
const RETURN_DATA_RE = /^0x(?:[0-9a-fA-F]{2})*$/;
const TOPIC_RE = /^0x[0-9a-f]{64}$/;
const ADDR_RE = /^0x[0-9a-f]{40}$/;

/**
 * Pure: classify logs into transfers and approvals, and net them for the
 * portal. `value` and `to` let the caller's own native send be accounted
 * for when the node didn't trace the top-level transfer (see below).
 */
export function analyzeLogs(
  logs: readonly RawLog[],
  portal: string,
  tx: { to: string | null; value: bigint },
): {
  transfers: SimTransfer[];
  approvals: SimApproval[];
  wraps: WrapEvent[];
  changes: BalanceChanges;
  malformed: number;
} {
  const transfers: SimTransfer[] = [];
  const approvals: SimApproval[] = [];
  const wraps: WrapEvent[] = [];
  let malformed = 0;
  for (const log of logs) {
    try {
      classify(log, portal, transfers, approvals, wraps);
    } catch {
      malformed++;
    }
  }

  let native = 0n;
  let tracedOut = 0n;
  const erc20 = new Map<string, bigint>();
  const nftIn: { token: string; tokenId: bigint }[] = [];
  const nftOut: { token: string; tokenId: bigint }[] = [];
  const erc1155 = new Map<string, { token: string; tokenId: bigint; delta: bigint }>();
  for (const t of transfers) {
    const sign = (t.to === portal ? 1n : 0n) - (t.from === portal ? 1n : 0n);
    if (t.standard === 'native' && t.from === portal) tracedOut += t.amount;
    if (sign === 0n) continue;
    switch (t.standard) {
      case 'native':
        native += sign * t.amount;
        break;
      case 'erc20':
        erc20.set(t.token!, (erc20.get(t.token!) ?? 0n) + sign * t.amount);
        break;
      case 'erc721':
        (sign > 0n ? nftIn : nftOut).push({ token: t.token!, tokenId: t.tokenId! });
        break;
      case 'erc1155': {
        const key = `${t.token}:${t.tokenId}`;
        const cur = erc1155.get(key) ?? { token: t.token!, tokenId: t.tokenId!, delta: 0n };
        cur.delta += sign * t.amount;
        erc1155.set(key, cur);
        break;
      }
    }
  }
  // traceTransfers normally includes the top-level value transfer; if the
  // node traced none of the portal's outflow, account for tx.value here.
  // Gas is deliberately excluded — it depends on inclusion-time fees.
  if (tx.value > 0n && tracedOut < tx.value && tx.to !== portal) {
    native -= tx.value - tracedOut;
  }
  return {
    transfers,
    approvals,
    wraps,
    changes: {
      native,
      erc20: [...erc20].filter(([, d]) => d !== 0n).map(([token, delta]) => ({ token, delta })),
      nftIn,
      nftOut,
      erc1155: [...erc1155.values()].filter((e) => e.delta !== 0n),
    },
    malformed,
  };
}

function classify(
  log: RawLog,
  portal: string,
  transfers: SimTransfer[],
  approvals: SimApproval[],
  wraps: WrapEvent[],
): void {
  if (!ADDR_RE.test(log.address) || !HEX_RE.test(log.data)) throw new Error('bad log');
  for (const t of log.topics) if (!TOPIC_RE.test(t)) throw new Error('bad topic');
  const [topic0] = log.topics;
  if (topic0 === undefined) return; // anonymous event: not ours
  const n = log.topics.length;
  const data = Buffer.from(log.data.slice(2), 'hex');
  const token = log.address;
  switch (topic0) {
    case EVENT_TOPICS.Transfer: {
      if (n === 3) {
        const [amount] = decodeAbiParameters(['uint256'], data) as [bigint];
        const native = NATIVE_SENTINELS.has(token);
        transfers.push({
          standard: native ? 'native' : 'erc20',
          token: native ? null : token,
          from: topicAddr(log.topics[1]!),
          to: topicAddr(log.topics[2]!),
          amount,
        });
        return;
      }
      if (n === 4) {
        transfers.push({
          standard: 'erc721',
          token,
          from: topicAddr(log.topics[1]!),
          to: topicAddr(log.topics[2]!),
          amount: 1n,
          tokenId: BigInt(log.topics[3]!),
        });
        return;
      }
      throw new Error('Transfer arity');
    }
    case EVENT_TOPICS.Approval: {
      const owner = topicAddr(log.topics[1] ?? '');
      if (n === 3) {
        const [amount] = decodeAbiParameters(['uint256'], data) as [bigint];
        if (owner === portal) {
          approvals.push({ standard: 'erc20', token, spender: topicAddr(log.topics[2]!), amount });
        }
        return;
      }
      if (n === 4) {
        if (owner === portal) {
          approvals.push({
            standard: 'erc721',
            token,
            spender: topicAddr(log.topics[2]!),
            tokenId: BigInt(log.topics[3]!),
          });
        }
        return;
      }
      throw new Error('Approval arity');
    }
    case EVENT_TOPICS.ApprovalForAll: {
      if (n !== 3) throw new Error('ApprovalForAll arity');
      const [approved] = decodeAbiParameters(['bool'], data) as [boolean];
      if (topicAddr(log.topics[1]!) === portal) {
        approvals.push({
          standard: 'operator',
          token,
          spender: topicAddr(log.topics[2]!),
          approved,
        });
      }
      return;
    }
    case EVENT_TOPICS.TransferSingle: {
      if (n !== 4) throw new Error('TransferSingle arity');
      const [id, amount] = decodeAbiParameters(['uint256', 'uint256'], data) as [bigint, bigint];
      transfers.push({
        standard: 'erc1155',
        token,
        from: topicAddr(log.topics[2]!),
        to: topicAddr(log.topics[3]!),
        amount,
        tokenId: id,
      });
      return;
    }
    case EVENT_TOPICS.TransferBatch: {
      if (n !== 4) throw new Error('TransferBatch arity');
      const [ids, amounts] = decodeAbiParameters(['uint256[]', 'uint256[]'], data) as [
        bigint[],
        bigint[],
      ];
      if (ids.length !== amounts.length) throw new Error('TransferBatch length mismatch');
      ids.forEach((id, i) =>
        transfers.push({
          standard: 'erc1155',
          token,
          from: topicAddr(log.topics[2]!),
          to: topicAddr(log.topics[3]!),
          amount: amounts[i]!,
          tokenId: id,
        }),
      );
      return;
    }
    case EVENT_TOPICS.Deposit:
    case EVENT_TOPICS.Withdrawal: {
      if (n !== 2) throw new Error('Deposit/Withdrawal arity');
      const [wad] = decodeAbiParameters(['uint256'], data) as [bigint];
      const who = topicAddr(log.topics[1]!);
      // WETH9 mints/burns without a Transfer event; model it as one.
      const deposit = topic0 === EVENT_TOPICS.Deposit;
      wraps.push({ token, who, kind: deposit ? 'deposit' : 'withdrawal', amount: wad });
      transfers.push({
        standard: 'erc20',
        token,
        from: deposit ? ZERO_ADDRESS : who,
        to: deposit ? who : ZERO_ADDRESS,
        amount: wad,
      });
      return;
    }
    default:
      return; // some other event — not part of the balance picture
  }
}

function topicAddr(topic: string): string {
  if (!TOPIC_RE.test(topic)) throw new Error('bad topic');
  return '0x' + topic.slice(26);
}

// ---------------------------------------------------------------------------
// Token metadata
// ---------------------------------------------------------------------------

const SYMBOL_SELECTOR = '0x95d89b41';
const DECIMALS_SELECTOR = '0x313ce567';

/**
 * symbol() + decimals() via eth_call. Tolerates bytes32 symbols (MKR-era
 * tokens), reverts, EOAs and garbage: whatever fails is simply absent.
 */
export async function fetchTokenMeta(
  token: string,
  call: (method: string, params: unknown[]) => Promise<unknown>,
): Promise<TokenMeta> {
  const [sym, dec] = await Promise.allSettled([
    call('eth_call', [{ to: token, data: SYMBOL_SELECTOR }, 'latest']),
    call('eth_call', [{ to: token, data: DECIMALS_SELECTOR }, 'latest']),
  ]);
  const meta: TokenMeta = {};
  if (sym.status === 'fulfilled') {
    const s = parseSymbol(sym.value);
    if (s !== undefined) meta.symbol = s;
  }
  if (dec.status === 'fulfilled') {
    const d = parseDecimals(dec.value);
    if (d !== undefined) meta.decimals = d;
  }
  return meta;
}

export function parseSymbol(ret: unknown): string | undefined {
  if (typeof ret !== 'string' || !HEX_RE.test(ret) || ret.length % 2 !== 0) return undefined;
  const bytes = Buffer.from(ret.slice(2), 'hex');
  if (bytes.length > 32) {
    try {
      const [s] = decodeAbiParameters(['string'], bytes) as [string];
      return sanitizeSymbol(s);
    } catch {
      return undefined;
    }
  }
  if (bytes.length === 32) {
    // bytes32 symbol: ASCII, right-padded with zeros.
    const end = bytes.indexOf(0);
    return sanitizeSymbol(bytes.subarray(0, end === -1 ? 32 : end).toString('latin1'));
  }
  return undefined;
}

export function parseDecimals(ret: unknown): number | undefined {
  if (typeof ret !== 'string' || !HEX_RE.test(ret) || ret.length % 2 !== 0) return undefined;
  const bytes = Buffer.from(ret.slice(2), 'hex');
  if (bytes.length < 32) return undefined;
  try {
    const [d] = decodeAbiParameters(['uint256'], bytes) as [bigint];
    return d <= 36n ? Number(d) : undefined;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function qtyHex(v: bigint): string {
  return '0x' + v.toString(16);
}

/** A node quantity, or throw: malformed or wider than uint256 (oversized). */
function parseQty(v: unknown, what: string): bigint {
  const q = hexQuantity(v);
  if (q === null) {
    const oversized = typeof v === 'string' && v.length > MAX_QTY_HEX_DIGITS + 2;
    throw new Error(`${what} is ${oversized ? 'an oversized quantity' : 'not a hex quantity'}`);
  }
  return q;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function errText(err: unknown): string {
  if (err instanceof UpstreamRpcError)
    return `node error ${err.code}: ${cleanMessage(err.message)}`;
  return cleanMessage((err as Error).message ?? String(err));
}

/** Race a promise against a timer; the timer never keeps the process alive. */
export function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const t = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
    timer.unref?.();
  });
  return Promise.race([p, t]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}
