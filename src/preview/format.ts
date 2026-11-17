import type { SimApproval, SimTransfer, Simulation } from './simulate.js';
import type { DecodedCall, TokenMetaLookup } from './types.js';
import {
  formatEth,
  groupThousands,
  headAmount,
  isUnlimited,
  shortAddr,
  tokenLabel,
} from './units.js';

/**
 * Rendering for the transaction preview. Pure: given the same decode and
 * simulation it produces byte-identical text, so tests can pin it and the
 * audit log records exactly what the human and the agent were shown.
 *
 * Two shapes:
 *   - `renderText`: multi-line, for the agent and the audit log.
 *   - `renderHeadline`: one line, ` | `-separated, ≤ ~220 chars, for the
 *     phone push where the first glance has to carry the decision.
 */

export type PreviewSimulation = Simulation | { status: 'skipped'; reason: string };

export interface RenderInput {
  decoded: DecodedCall;
  simulation: PreviewSimulation;
  warnings: readonly string[];
  /** Lowercase portal address. */
  from: string;
  /** Lowercase destination, null for a deploy. */
  to: string | null;
  value: bigint;
  chainId: bigint;
  meta: TokenMetaLookup;
  /** Extra trailing lines (e.g. `abi: skipped foo.json: invalid JSON`). */
  footer?: readonly string[];
}

export const HEADLINE_MAX = 220;

export function renderText(r: RenderInput): string {
  const lines: string[] = [];
  lines.push(`call: ${callLine(r)}`);
  lines.push(`value: ${formatEth(r.value)}   chain: ${r.chainId}`);
  lines.push(`simulation: ${simulationSummary(r.simulation)}`);
  const sim = r.simulation;
  if (sim.status === 'ok' || sim.status === 'reverted') {
    for (const note of sim.notes) lines.push(`  note: ${note}`);
    if (sim.status === 'ok') {
      if (sim.approvals && sim.approvals.length > 0) {
        lines.push(`  approvals: ${sim.approvals.map((a) => approvalText(a, r.meta)).join('; ')}`);
      }
      if (sim.changes) {
        const deltas = deltaTexts(sim, r.meta);
        lines.push(
          `  balance changes for ${shortAddr(r.from)}: ${deltas.length ? deltas.join(', ') : 'none'}`,
        );
      } else {
        lines.push(`  balance changes: unknown (no event logs from this node)`);
      }
      if (sim.transfers && sim.transfers.length > 0) {
        const more = sim.transfersOmitted > 0 ? `, ${sim.transfersOmitted} more not shown` : '';
        lines.push(`  transfers (${sim.transfers.length}${more}):`);
        for (const t of sim.transfers) lines.push(`    ${transferText(t, r.meta)}`);
      }
    }
  }
  if (r.warnings.length > 0) {
    lines.push('warnings:');
    for (const w of r.warnings) lines.push(`  - ${w}`);
  }
  for (const f of r.footer ?? []) lines.push(f);
  return lines.join('\n');
}

export function renderHeadline(r: RenderInput): string {
  const parts: string[] = [headlineCall(r)];
  const sim = r.simulation;
  switch (sim.status) {
    case 'ok': {
      const deltas = sim.changes ? deltaTexts(sim, r.meta) : [];
      const shown = deltas.slice(0, 3).join(' ');
      const tail = deltas.length > 3 ? ` +${deltas.length - 3} more` : '';
      parts.push(`sim ok${shown ? ` ${shown}${tail}` : ''}`);
      break;
    }
    case 'reverted':
      parts.push(`sim REVERTED: ${sim.revertReason ?? 'unknown reason'}`);
      break;
    case 'unavailable':
      parts.push('sim unavailable');
      break;
    case 'skipped':
      parts.push('no sim');
      break;
  }
  if (r.warnings.length > 0) {
    const more = r.warnings.length > 1 ? ` (+${r.warnings.length - 1} more)` : '';
    parts.push(`⚠ ${r.warnings[0]}${more}`);
  }
  const line = parts.join(' | ');
  return line.length > HEADLINE_MAX ? line.slice(0, HEADLINE_MAX - 1) + '…' : line;
}

/** One-line simulation status, also what the audit entry records. */
export function simulationSummary(sim: PreviewSimulation): string {
  switch (sim.status) {
    case 'ok':
    case 'reverted': {
      const gas = sim.gasUsed !== null ? `, ${groupThousands(sim.gasUsed)} gas` : '';
      const via = sim.method === 'eth_call' ? ' (eth_call)' : '';
      return sim.status === 'ok'
        ? `ok${gas}${via}`
        : `REVERTED — ${sim.revertReason ?? 'unknown reason'}${via}`;
    }
    case 'unavailable':
      return `unavailable — ${sim.reason}`;
    case 'skipped':
      return `skipped — ${sim.reason}`;
  }
}

function callLine(r: RenderInput): string {
  const d = r.decoded;
  if (d.source === 'deploy') return d.text;
  if (r.to === null) return d.text;
  if (d.source === 'empty') return `plain ETH transfer to ${shortAddr(r.to)}`;
  const sym = r.meta(r.to)?.symbol;
  return `${d.text} on ${shortAddr(r.to)}${sym ? ` (${sym})` : ''}`;
}

function headlineCall(r: RenderInput): string {
  const d = r.decoded;
  if (d.source === 'empty' && r.to !== null) {
    return `send ${formatEth(r.value)} → ${shortAddr(r.to)}`;
  }
  let s =
    d.short ?? (r.to !== null && d.source !== 'deploy' ? `${d.text} → ${shortAddr(r.to)}` : d.text);
  const eth = formatEth(r.value);
  if (r.value > 0n && !s.includes(eth)) s += `, value ${eth}`;
  return s;
}

function signed(delta: bigint, render: (abs: bigint) => string): string {
  return `${delta < 0n ? '-' : '+'}${render(delta < 0n ? -delta : delta)}`;
}

function deltaTexts(
  sim: Extract<Simulation, { status: 'ok' | 'reverted' }>,
  meta: TokenMetaLookup,
): string[] {
  const c = sim.changes;
  if (!c) return [];
  const out: string[] = [];
  if (c.native !== 0n) out.push(signed(c.native, formatEth));
  for (const e of c.erc20) out.push(signed(e.delta, (v) => headAmount(v, e.token, meta)));
  for (const n of c.nftIn) out.push(`+NFT ${shortAddr(n.token)} #${n.tokenId}`);
  for (const n of c.nftOut) out.push(`-NFT ${shortAddr(n.token)} #${n.tokenId}`);
  for (const e of c.erc1155) {
    out.push(signed(e.delta, (v) => `${v} × id ${e.tokenId} of ${shortAddr(e.token)}`));
  }
  return out;
}

function approvalText(a: SimApproval, meta: TokenMetaLookup): string {
  switch (a.standard) {
    case 'erc20': {
      const amt = a.amount ?? 0n;
      const label = tokenLabel(a.token, meta);
      if (amt === 0n) return `${label} → ${shortAddr(a.spender)} revoked`;
      if (isUnlimited(amt)) return `${label} → ${shortAddr(a.spender)} UNLIMITED`;
      return `${label} → ${shortAddr(a.spender)} ${headAmount(amt, a.token, meta)}`;
    }
    case 'erc721':
      return `NFT ${shortAddr(a.token)} #${a.tokenId} → ${shortAddr(a.spender)}`;
    case 'operator':
      return a.approved
        ? `ALL of ${shortAddr(a.token)} → ${shortAddr(a.spender)}`
        : `ALL of ${shortAddr(a.token)} → ${shortAddr(a.spender)} revoked`;
  }
}

function transferText(t: SimTransfer, meta: TokenMetaLookup): string {
  const route = `${shortAddr(t.from)} → ${shortAddr(t.to)}`;
  switch (t.standard) {
    case 'native':
      return `${formatEth(t.amount)} ${route}`;
    case 'erc20':
      return `${headAmount(t.amount, t.token!, meta)} ${route}`;
    case 'erc721':
      return `NFT ${shortAddr(t.token!)} #${t.tokenId} ${route}`;
    case 'erc1155':
      return `${t.amount} × id ${t.tokenId} of ${shortAddr(t.token!)} ${route}`;
  }
}
