import type { SimApproval, SimTransfer, Simulation } from './simulate.js';
import type { DecodedCall, TokenMetaLookup } from './types.js';
import {
  clean,
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
  // The one place lines are joined: nothing inside a line may start a new one.
  return lines.map(clean).join('\n');
}

/** Debits beyond this many are summarized (loudly) rather than listed. */
const MAX_HEADLINE_DEBITS = 40;
/** The call description's share of the headline; the rest is for effects. */
const HEADLINE_CALL_MAX = 90;

/**
 * The phone headline. What leaves the portal is the decision, so the
 * simulation part lists every debit — native and token outflows, NFTs out,
 * approvals granted — BEFORE any credit, and debits are never cut to fit:
 * a run of attacker-emitted "+1 USDC" credits must not push a real drain
 * off the screen. Only the call description (clipped), the credits
 * (`+N more in`) and the warnings (down to `⚠ N warnings`) give way to
 * HEADLINE_MAX; a headline is longer than that only when the debits are.
 */
export function renderHeadline(r: RenderInput): string {
  const call = clip(headlineCall(r), HEADLINE_CALL_MAX);
  const sim = r.simulation;
  let simPart: string;
  let credits: string[] = [];
  switch (sim.status) {
    case 'ok': {
      const f = flows(sim, r.meta);
      const debits =
        f.debits.length > MAX_HEADLINE_DEBITS
          ? [
              ...f.debits.slice(0, MAX_HEADLINE_DEBITS),
              `!! ${f.debits.length - MAX_HEADLINE_DEBITS} MORE DEBITS — read the preview`,
            ]
          : f.debits;
      simPart = ['sim ok', ...debits].join(' ');
      credits = f.credits;
      break;
    }
    case 'reverted':
      simPart = `sim REVERTED: ${clip(sim.revertReason ?? 'unknown reason', 80)}`;
      break;
    case 'unavailable':
      simPart = 'sim unavailable';
      break;
    case 'skipped':
      simPart = 'no sim';
      break;
  }

  let line = `${call} | ${simPart}`;
  const n = r.warnings.length;
  const minWarn = n > 0 ? ` | ⚠ ${n} warning${n === 1 ? '' : 's'}` : '';
  // Credits: as many as fit while leaving room for at least the warning count.
  for (let i = 0; i < credits.length; i++) {
    const rest = credits.length - i - 1;
    const tail = rest > 0 ? ` +${rest} more in` : '';
    if (line.length + 1 + credits[i]!.length + tail.length + minWarn.length > HEADLINE_MAX) {
      line += ` +${credits.length - i} more in`;
      break;
    }
    line += ` ${credits[i]}`;
  }
  if (n > 0) {
    const more = n > 1 ? ` (+${n - 1} more)` : '';
    const full = ` | ⚠ ${r.warnings[0]}${more}`;
    const room = HEADLINE_MAX - line.length;
    if (full.length <= room) line += full;
    else if (room > minWarn.length + 12)
      line += clip(` | ⚠ ${r.warnings[0]}`, room - more.length) + more;
    else line += minWarn;
  }
  return clean(line);
}

function clip(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
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

/**
 * Split the portal's balance changes into debits (incl. approvals it
 * grants) and credits, debits first in a stable order.
 */
function flows(
  sim: Extract<Simulation, { status: 'ok' | 'reverted' }>,
  meta: TokenMetaLookup,
  withApprovals = true,
): { debits: string[]; credits: string[] } {
  const debits: string[] = [];
  const credits: string[] = [];
  const c = sim.changes;
  if (c) {
    if (c.native < 0n) debits.push(signed(c.native, formatEth));
    if (c.native > 0n) credits.push(signed(c.native, formatEth));
    for (const e of c.erc20) {
      (e.delta < 0n ? debits : credits).push(signed(e.delta, (v) => headAmount(v, e.token, meta)));
    }
    for (const nft of c.nftOut) debits.push(`-NFT ${shortAddr(nft.token)} #${nft.tokenId}`);
    for (const nft of c.nftIn) credits.push(`+NFT ${shortAddr(nft.token)} #${nft.tokenId}`);
    for (const e of c.erc1155) {
      (e.delta < 0n ? debits : credits).push(
        signed(e.delta, (v) => `${v} × id ${e.tokenId} of ${shortAddr(e.token)}`),
      );
    }
  }
  for (const a of withApprovals ? (sim.approvals ?? []) : []) {
    const revoke =
      (a.standard === 'erc20' && (a.amount ?? 0n) === 0n) ||
      (a.standard === 'operator' && !a.approved);
    if (!revoke) debits.push(`grants ${approvalText(a, meta)}`);
  }
  return { debits, credits };
}

/** Balance changes for the long-form text: debits first, then credits. */
function deltaTexts(
  sim: Extract<Simulation, { status: 'ok' | 'reverted' }>,
  meta: TokenMetaLookup,
): string[] {
  const f = flows(sim, meta, false);
  return [...f.debits, ...f.credits];
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
