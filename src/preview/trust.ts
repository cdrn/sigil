import type { PreviewSimulation } from './format.js';
import { type DecodedCall, NO_META, type TokenMeta, type TokenMetaLookup } from './types.js';
import { formatEth, headAmount, shortAddr } from './units.js';

/**
 * Everything a simulated contract says about itself — its symbol(), the
 * events it emits — is chosen by whoever deployed it. This module decides
 * how much of that the preview may repeat in sigil's own voice:
 *
 *   - Token symbols that collide within one simulation, or that claim a
 *     well-known name (USDC, USDT, DAI, WETH, WBTC, ETH) at an address that
 *     is not that token on this chain, are rendered quoted with their
 *     address — `"USDC"? (0x1234…abcd)` — and warned about.
 *   - Friendly verbs from the built-in descriptions ("wrap", "unwrap",
 *     "swap", "transfer") are only kept when the simulation shows the
 *     contract behaving like that; otherwise the raw signature is shown.
 *   - A debit alongside credits from unverified tokens is flagged: fake
 *     inflows are the classic way to make a drain look like a trade.
 */

/** Names worth impersonating. Exact (case-insensitive) symbol match. */
const WELL_KNOWN = ['USDC', 'USDT', 'DAI', 'WETH', 'WBTC', 'ETH'] as const;

/**
 * Canonical token addresses per chain (lowercase). Deliberately tiny: it
 * only has to answer "is this the real one?" for the names above. A name
 * with no entry for a chain is never canonical there — anything claiming
 * it is quoted. ETH is native and never an ERC-20.
 */
const CANONICAL: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  '1': {
    USDC: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
    USDT: '0xdac17f958d2ee523a2206206994597c13d831ec7',
    DAI: '0x6b175474e89094c44da98b954eedeac495271d0f',
    WETH: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
    WBTC: '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599',
  },
  '8453': {
    USDC: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    USDT: '0xfde4c96c8593536e31f229ea8f37b2ada2699bb2',
    DAI: '0x50c5725949a6f0c72e6c4a641f24049a917db0cb',
    WETH: '0x4200000000000000000000000000000000000006',
  },
  '42161': {
    USDC: '0xaf88d065e77c8cc2239327c5edb3a432268e5831',
    USDT: '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9',
    DAI: '0xda10009cbd5d07dd0cecc66161fc93d7c9000da1',
    WETH: '0x82af49447d8a07e3bd95bd0d56f35241523fbab1',
    WBTC: '0x2f2a2543b76a4166549f7aab2e75bef0aefc5b0f',
  },
  '10': {
    USDC: '0x0b2c639c533813f4aa9d7837caf62653d097ff85',
    USDT: '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58',
    DAI: '0xda10009cbd5d07dd0cecc66161fc93d7c9000da1',
    WETH: '0x4200000000000000000000000000000000000006',
    WBTC: '0x68f180fcce6836688e9084f035309e29bf0a2095',
  },
  '11155111': {
    USDC: '0x1c7d4b196cb0c7b01d743fbc6116a902379c7238',
    WETH: '0xfff9976782d46cc05630d1f6ebab18b2324d6b14',
  },
  '84532': {
    USDC: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
    WETH: '0x4200000000000000000000000000000000000006',
  },
};

/** The canonical address of a well-known token on a chain, if sigil knows it. */
export function canonicalToken(chainId: bigint, symbol: string): string | undefined {
  return CANONICAL[chainId.toString()]?.[symbol.toUpperCase()];
}

export interface TokenTrust {
  /** Metadata to render with: suspect symbols replaced by `"SYM"? (0x…)`. */
  meta: Record<string, TokenMeta>;
  /** Tokens whose symbol is missing, colliding or impersonating. */
  unverified: Set<string>;
  warnings: string[];
}

export function assessTokens(
  raw: Readonly<Record<string, TokenMeta>>,
  chainId: bigint,
): TokenTrust {
  const meta: Record<string, TokenMeta> = {};
  const unverified = new Set<string>();
  const warnings: string[] = [];
  const bySymbol = new Map<string, string[]>();
  for (const [addr, m] of Object.entries(raw)) {
    meta[addr] = { ...m };
    if (m.symbol === undefined) {
      unverified.add(addr);
      continue;
    }
    const key = m.symbol.toUpperCase();
    bySymbol.set(key, [...(bySymbol.get(key) ?? []), addr]);
  }
  const quote = (addr: string, sym: string): void => {
    unverified.add(addr);
    meta[addr] = { ...meta[addr], symbol: `"${sym}"? (${shortAddr(addr)})` };
  };
  for (const [key, addrs] of bySymbol) {
    const sym = raw[addrs[0]!]!.symbol!;
    const canonical = canonicalToken(chainId, key);
    const wellKnown = (WELL_KNOWN as readonly string[]).includes(key);
    for (const addr of addrs) {
      if (wellKnown && addr !== canonical) {
        quote(addr, raw[addr]!.symbol!);
        warnings.push(
          `token at ${shortAddr(addr)} calls itself ${key} but is not the known ${key} on chain ${chainId}`,
        );
      }
    }
    if (addrs.length > 1) {
      // Colliding names: the canonical one (if present) keeps its name.
      for (const addr of addrs) if (addr !== canonical) quote(addr, raw[addr]!.symbol!);
      warnings.push(
        `${addrs.length} different tokens call themselves ${sym}: ${addrs.map(shortAddr).join(', ')}`,
      );
    }
  }
  return { meta, unverified, warnings: [...new Set(warnings)] };
}

// --- behaviour checks -------------------------------------------------------

const DEPOSIT = '0xd0e30db0';
const WITHDRAW = '0x2e1a7d4d';
const TRANSFER = '0xa9059cbb';
const SWAPS = new Set([
  '0x38ed1739',
  '0x7ff36ab5',
  '0x18cbafe5',
  '0x8803dbee',
  '0x414bf389',
  '0x04e45aaf',
  '0xc04b8d59',
  '0xdb3e2198',
]);

export interface BehaviourVerdict {
  /** false = the simulation contradicts the friendly description. */
  matches: boolean;
  warning?: string;
}

/**
 * Does the simulation show `to` doing what the built-in description says?
 * Returns null when it can't be judged (no simulation, no logs, not a call
 * we have a check for). Only a successful eth_simulateV1 run with logs can
 * contradict a description.
 */
export function checkBehaviour(
  decoded: DecodedCall,
  sim: PreviewSimulation,
  tx: { from: string; to: string | null },
  meta: TokenMetaLookup = NO_META,
): BehaviourVerdict | null {
  if (decoded.source !== 'builtin' || decoded.selector === null || tx.to === null) return null;
  if (sim.status !== 'ok' || sim.changes === null || sim.wraps === null) return null;
  const to = tx.to;
  const sel = decoded.selector;
  if (sel === DEPOSIT || sel === WITHDRAW) {
    const kind = sel === DEPOSIT ? 'deposit' : 'withdrawal';
    const ok = sim.wraps.some((w) => w.token === to && w.kind === kind && w.who === tx.from);
    return ok
      ? { matches: true }
      : {
          matches: false,
          warning: `selector matches WETH ${sel === DEPOSIT ? 'deposit()' : 'withdraw(uint256)'} but the contract did not behave like WETH`,
        };
  }
  if (sel === TRANSFER) {
    const ok = sim.changes.erc20.some((e) => e.token === to && e.delta < 0n);
    return ok
      ? { matches: true }
      : {
          matches: false,
          warning:
            'selector matches ERC-20 transfer() but the contract moved none of its own token out of the portal',
        };
  }
  if (SWAPS.has(sel)) {
    const out = decoded.swapOut;
    if (!out) {
      return { matches: false, warning: 'swap output is not the declared token' };
    }
    const min = BigInt(out.min);
    // Router sentinels: address(1) = msg.sender (the portal), address(2) =
    // the router itself (a multicall continues with the funds).
    const recipient =
      out.recipient === SENTINEL_SENDER
        ? tx.from
        : out.recipient === SENTINEL_THIS
          ? to
          : out.recipient;
    const got = received(sim, recipient, out.token, tx.from);
    const label = (v: bigint): string =>
      out.token === null ? formatEth(v) : headAmount(v, out.token, meta);
    if (got > 0n && got >= min) return { matches: true };
    if (got === 0n && otherInflow(sim, recipient, out.token, tx.from)) {
      return { matches: false, warning: 'swap output is not the declared token' };
    }
    return {
      matches: false,
      warning: `swap output below the declared minimum (got ${label(got)}, declared ≥ ${label(min)})`,
    };
  }
  return null;
}

const SENTINEL_SENDER = '0x0000000000000000000000000000000000000001';
const SENTINEL_THIS = '0x0000000000000000000000000000000000000002';

type RanSim = Extract<PreviewSimulation, { status: 'ok' | 'reverted' }>;

/**
 * How much of `token` (null = native) the recipient gained. For the portal
 * this is its net balance change; for anyone else, the sum of listed
 * transfers to them (the listing is capped, so this can under-count — the
 * check then fails loudly rather than vouching).
 */
function received(sim: RanSim, recipient: string, token: string | null, portal: string): bigint {
  if (recipient === portal && sim.changes) {
    if (token === null) return sim.changes.native > 0n ? sim.changes.native : 0n;
    const d = sim.changes.erc20.find((e) => e.token === token)?.delta ?? 0n;
    return d > 0n ? d : 0n;
  }
  let sum = 0n;
  for (const t of sim.transfers ?? []) {
    if (t.to !== recipient) continue;
    if (token === null ? t.standard === 'native' : t.standard === 'erc20' && t.token === token) {
      sum += t.amount;
    }
  }
  return sum;
}

/** Did the recipient receive something other than the declared token? */
function otherInflow(
  sim: RanSim,
  recipient: string,
  token: string | null,
  portal: string,
): boolean {
  if (recipient === portal && sim.changes) {
    return (
      (token !== null && sim.changes.native > 0n) ||
      sim.changes.erc20.some((e) => e.delta > 0n && e.token !== token)
    );
  }
  return (sim.transfers ?? []).some(
    (t) =>
      t.to === recipient &&
      (t.standard === 'native' ? token !== null : t.standard === 'erc20' && t.token !== token),
  );
}

/** The plain-signature rendering used when the friendly one isn't earned. */
export function rawCallText(decoded: DecodedCall): string {
  const args = (decoded.args ?? []).map(
    (a) => `${a.name}=${a.type === 'address' ? shortAddr(a.value) : a.value}`,
  );
  return `${decoded.name ?? decoded.selector}(${args.join(', ')})`;
}
