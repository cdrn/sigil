import type { SignableTx } from '../eth/index.js';
import type { JsonRpcUpstream } from '../rpc/upstream.js';
import { AbiRegistry } from './abi-dir.js';
import { decodeCalldata } from './decode.js';
import { type PreviewSimulation, renderHeadline, renderText, simulationSummary } from './format.js';
import { operatorWarning } from './known.js';
import { simulateTransaction } from './simulate.js';
import { type DecodedCall, NO_META, type TokenMetaLookup } from './types.js';
import { assessTokens, checkBehaviour, rawCallText } from './trust.js';
import { clean, isUnlimited, shortAddr } from './units.js';

/**
 * "Show me what I'm signing": decode an EVM transaction to English and, when
 * an RPC node is configured for its chain, dry-run it. The result feeds
 * three readers — the human (confirm push headline), the agent (returned
 * text) and the audit log — and two opt-in policy gates (deny on revert,
 * require simulation) that the sign path applies.
 */

export interface TxPreview {
  decoded: DecodedCall;
  simulation: PreviewSimulation;
  warnings: string[];
  /** Multi-line, for the agent and the audit log. */
  text: string;
  /** One line, for the confirm push. */
  headline: string;
}

export interface BuildTxPreviewInput {
  tx: SignableTx;
  /** The signing portal's address. */
  from: string;
  registry: AbiRegistry;
  /** RPC node for this tx's chain; undefined = no simulation (skipped). */
  simulator?: JsonRpcUpstream;
  /** Why there is no simulator, when the caller knows better than the default. */
  skippedReason?: string;
  timeoutMs?: number;
}

export async function buildTxPreview(input: BuildTxPreviewInput): Promise<TxPreview> {
  const { tx, registry } = input;
  const from = input.from.toLowerCase();
  const to = tx.to === null ? null : tx.to.toLowerCase();
  const value = BigInt(tx.value);
  const chainId = BigInt(tx.chainId);
  const data =
    typeof tx.data === 'string' ? Buffer.from(tx.data.slice(2), 'hex') : Buffer.from(tx.data);
  const ctx = { to, value, from };

  // First pass with no metadata: learns which tokens the call names, so the
  // simulator can fetch their symbol/decimals alongside the ones it touches.
  const pre = decodeCalldata(data, registry, NO_META, ctx);

  let simulation: PreviewSimulation;
  if (input.simulator === undefined) {
    simulation = {
      status: 'skipped',
      reason: input.skippedReason ?? `no simulation RPC configured for chain ${chainId}`,
    };
  } else {
    simulation = await simulateTransaction(tx, from, input.simulator, {
      ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
      extraTokens: pre.tokens ?? [],
    });
  }

  // Contract-reported symbols are vetted before anything renders them.
  const trust = assessTokens(
    simulation.status === 'ok' || simulation.status === 'reverted' ? simulation.tokenMeta : {},
    chainId,
  );
  const metaTable = trust.meta;
  const meta: TokenMetaLookup = (addr) =>
    Object.prototype.hasOwnProperty.call(metaTable, addr) ? metaTable[addr] : undefined;
  let decoded = Object.keys(metaTable).length > 0 ? decodeCalldata(data, registry, meta, ctx) : pre;

  // A friendly verb is only kept when the contract behaved like it.
  const verdict = checkBehaviour(decoded, simulation, { from, to, chainId }, meta);
  const trustWarnings: string[] = [];
  if (verdict && !verdict.matches && verdict.rewrite !== false) {
    const raw = rawCallText(decoded);
    const { short: _dropped, ...rest } = decoded;
    decoded = { ...rest, text: raw, short: `${raw} on ${shortAddr(to ?? '')}` };
  }
  if (verdict && !verdict.matches) {
    if (verdict.warning) trustWarnings.push(verdict.warning);
    trustWarnings.push(...(verdict.more ?? []));
  }
  if (simulation.status === 'ok' && simulation.changes) {
    const c = simulation.changes;
    const debit =
      c.native < 0n ||
      c.erc20.some((e) => e.delta < 0n) ||
      c.nftOut.length > 0 ||
      c.erc1155.some((e) => e.delta < 0n);
    const shadyInflow = c.erc20.some(
      (e) => e.delta > 0n && (trust.unverified.has(e.token) || !metaTable[e.token]?.symbol),
    );
    if (debit && shadyInflow)
      trustWarnings.push('inflows from unverified tokens — check the debit');
  }

  // Most actionable first: behaviour mismatch and unverified inflows, then
  // the per-token impersonation details.
  trustWarnings.push(...trust.warnings);
  const warnings = collectWarnings(decoded, simulation, { from, to, value }, trustWarnings);
  const render = {
    decoded,
    simulation,
    warnings,
    from,
    to,
    value,
    chainId,
    meta,
    footer: registry.loadWarnings,
  };
  return {
    decoded,
    simulation,
    warnings,
    text: renderText(render),
    headline: renderHeadline(render),
  };
}

/** The simulation ran without the signed fee fields (see simulate.ts). */
export const UNFAITHFUL_WARNING =
  'simulated without fee fields (node refused: insufficient funds) — the contract saw tx.gasprice = 0';

function collectWarnings(
  decoded: DecodedCall,
  sim: PreviewSimulation,
  tx: { from: string; to: string | null; value: bigint },
  trustWarnings: readonly string[],
): string[] {
  // Impersonation / behaviour warnings first: they explain everything else.
  const out: string[] = [...trustWarnings, ...decoded.warnings];
  if ((sim.status === 'ok' || sim.status === 'reverted') && !sim.faithful) {
    out.push(UNFAITHFUL_WARNING);
  }
  if (sim.status === 'reverted') out.push(`simulation reverted: ${sim.revertReason ?? 'unknown'}`);
  if (sim.status === 'unavailable') out.push(`simulation unavailable: ${sim.reason}`);
  if (decoded.source === 'unknown' && tx.value > 0n) {
    out.push('calldata to unknown function with ETH value');
  }
  if (tx.to !== null && tx.to === tx.from) out.push("destination is the portal's own address");
  if (sim.status === 'ok') {
    for (const a of sim.approvals ?? []) {
      if (a.standard === 'erc20' && a.amount !== undefined && isUnlimited(a.amount)) {
        out.push('UNLIMITED approval');
      }
      if (a.standard === 'operator' && a.approved) out.push(operatorWarning(a.spender, a.token));
    }
  }
  return [...new Set(out.map(clean))];
}

/**
 * Stand-in when building the preview itself failed (a bug, not a node
 * problem — those are already 'unavailable'). Presentation fails open but
 * loud: the sign path proceeds with this warning unless the policy demands
 * a simulation, in which case the 'unavailable' status denies (fail closed).
 */
export function previewFailure(message: string): TxPreview {
  const reason = `preview failed: ${message}`;
  const decoded: DecodedCall = {
    selector: null,
    text: reason,
    warnings: [reason],
    source: 'unknown',
  };
  return {
    decoded,
    simulation: { status: 'unavailable', reason },
    warnings: [reason],
    text: `call: ${reason}\nwarnings:\n  - ${reason}`,
    headline: `⚠ ${reason}`.slice(0, 220),
  };
}

/** The compact form written into the audit entry. */
export function auditPreview(p: TxPreview): {
  text: string;
  decoded: string;
  simulation: string;
  warnings: string[];
} {
  return {
    text: p.text,
    decoded: clean(p.decoded.text),
    simulation: clean(simulationSummary(p.simulation)),
    warnings: p.warnings,
  };
}

/** Deep-convert bigints to decimal strings so the value can be JSON-serialized. */
export function jsonSafe(v: unknown): unknown {
  if (typeof v === 'bigint') return v.toString();
  if (Array.isArray(v)) return v.map(jsonSafe);
  if (typeof v === 'object' && v !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = jsonSafe(x);
    return out;
  }
  return v;
}

export { AbiRegistry, type AbiFunction, type AbiInput } from './abi-dir.js';
export { SimulatorResolver, type SimulatorResolverOpts } from './simulators.js';
export { decodeCalldata, type DecodeCtx } from './decode.js';
export {
  simulateTransaction,
  analyzeLogs,
  decodeRevert,
  fetchTokenMeta,
  parseSymbol,
  parseDecimals,
  DEFAULT_SIM_TIMEOUT_MS,
  type Simulation,
  type SimTransfer,
  type SimApproval,
  type BalanceChanges,
  type RawLog,
  type SimulateOpts,
} from './simulate.js';
export {
  renderText,
  renderHeadline,
  simulationSummary,
  HEADLINE_MAX,
  type PreviewSimulation,
} from './format.js';
export { KNOWN_FUNCTIONS, EVENT_TOPICS, decodeV3Path, type KnownFunction } from './known.js';
export type { DecodedCall, DecodedArg, TokenMeta, TokenMetaLookup } from './types.js';
export { formatUnits, shortAddr, sanitizeSymbol } from './units.js';
