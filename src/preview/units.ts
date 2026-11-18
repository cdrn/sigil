import type { TokenMeta, TokenMetaLookup } from './types.js';

/**
 * Small pure formatters shared by the decoder, the simulator and the preview
 * renderer. Kept separate from format.ts so known.ts can use them without
 * importing the renderer (and the renderer's simulation types).
 */

export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
export const MAX_UINT256 = (1n << 256n) - 1n;
/** At or above this, an allowance is "unlimited" for every practical purpose. */
export const UNLIMITED_THRESHOLD = 1n << 255n;

/** `0x1111…1111` — enough to eyeball against the address you expected. */
export function shortAddr(addr: string): string {
  const a = addr.toLowerCase();
  return a.length === 42 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

/**
 * Anything at or above 10^80 is not a real amount (uint256 tops out at
 * ~1.2e77). Formatting refuses it before calling BigInt.toString, whose
 * cost grows super-linearly with the digit count — a node or contract
 * must not be able to stall the event loop with a 100k-digit "gasUsed".
 */
const FORMAT_CAP = 10n ** 80n;
const HUGE = '≥1e80 (not a real amount)';

/** Longest hex quantity accepted from a node: uint256, 64 hex digits. */
export const MAX_QTY_HEX_DIGITS = 64;
const QTY_RE = /^0x[0-9a-fA-F]{1,64}$/;

/**
 * Parse a JSON-RPC hex quantity from a node, or null if it is malformed or
 * wider than uint256. Bounded regex, so the check itself is linear.
 */
export function hexQuantity(v: unknown): bigint | null {
  if (typeof v !== 'string' || !QTY_RE.test(v)) return null;
  return BigInt(v);
}

/** 1234567 → "1,234,567". Linear: built with a loop, no regex. */
export function groupThousands(n: bigint): string {
  const neg = n < 0n;
  const abs = neg ? -n : n;
  if (abs >= FORMAT_CAP) return (neg ? '-' : '') + HUGE;
  const s = abs.toString();
  let out = '';
  for (let i = 0; i < s.length; i++) {
    if (i > 0 && (s.length - i) % 3 === 0) out += ',';
    out += s[i];
  }
  return neg ? `-${out}` : out;
}

function trimTrailingZeros(s: string): string {
  let end = s.length;
  while (end > 0 && s[end - 1] === '0') end--;
  return s.slice(0, end);
}

/**
 * Exact fixed-point rendering with thousands separators and trailing zeros
 * trimmed: (1000500000n, 6) → "1,000.5". Exact rather than rounded — a
 * signing prompt is the wrong place to approximate.
 */
export function formatUnits(amount: bigint, decimals: number): string {
  const neg = amount < 0n;
  const abs = neg ? -amount : amount;
  if (abs >= FORMAT_CAP) return (neg ? '-' : '') + HUGE;
  if (decimals === 0) return (neg ? '-' : '') + groupThousands(abs);
  const scale = 10n ** BigInt(decimals);
  const whole = abs / scale;
  const frac = trimTrailingZeros((abs % scale).toString().padStart(decimals, '0'));
  return (neg ? '-' : '') + groupThousands(whole) + (frac === '' ? '' : `.${frac}`);
}

export function formatEth(wei: bigint): string {
  return `${formatUnits(wei, 18)} ETH`;
}

/** True when an allowance amount is the max of its type or ≥ 2^255. */
export function isUnlimited(amount: bigint, bits = 256): boolean {
  return amount >= UNLIMITED_THRESHOLD || amount === (1n << BigInt(bits)) - 1n;
}

/** The token's symbol if known, else its short address. */
export function tokenLabel(token: string, meta: TokenMetaLookup): string {
  return meta(token.toLowerCase())?.symbol ?? shortAddr(token);
}

/**
 * Amount for a call argument: `UNLIMITED` for allowance-style maxima (when
 * `bits` is given), `1,000.5 USDC` when decimals are known, else the raw
 * integer.
 */
export function argAmount(
  amount: bigint,
  token: string | null,
  meta: TokenMetaLookup,
  opts: { allowanceBits?: number } = {},
): string {
  if (opts.allowanceBits !== undefined && isUnlimited(amount, opts.allowanceBits)) {
    return 'UNLIMITED';
  }
  const m: TokenMeta | undefined = token ? meta(token.toLowerCase()) : undefined;
  if (m?.decimals !== undefined && token) {
    return `${formatUnits(amount, m.decimals)} ${tokenLabel(token, meta)}`;
  }
  return amount.toString();
}

/**
 * Amount for a headline: always names the token. `1,000.5 USDC`,
 * `UNLIMITED USDC`, or `5 of 0xa0b8…eb48` when decimals are unknown.
 */
export function headAmount(
  amount: bigint,
  token: string,
  meta: TokenMetaLookup,
  opts: { allowanceBits?: number } = {},
): string {
  const label = tokenLabel(token, meta);
  if (opts.allowanceBits !== undefined && isUnlimited(amount, opts.allowanceBits)) {
    return `UNLIMITED ${label}`;
  }
  const m = meta(token.toLowerCase());
  if (m?.decimals !== undefined) return `${formatUnits(amount, m.decimals)} ${label}`;
  return `${amount} of ${label}`;
}

/** Unix seconds → ISO-8601, or the raw number when out of a sane range. */
export function formatTimestamp(secs: bigint): string {
  if (secs <= 0n || secs > 253_402_300_799n) return secs.toString(); // > year 9999
  return new Date(Number(secs) * 1000).toISOString().replace('.000Z', 'Z');
}

/** Bytes as 0x hex, truncated to 32 bytes with a length suffix. */
export function truncHex(hex: string): string {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (body.length <= 64) return '0x' + body;
  return `0x${body.slice(0, 64)}…(${body.length / 2} bytes)`;
}

/**
 * Render an ABI-decoded value for display. `short` shortens addresses
 * (call-line text); the structured args keep them in full.
 */
export function renderValue(type: string, v: unknown, short = false, depth = 0): string {
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'string') {
    if (type === 'address') return short ? shortAddr(v) : v;
    if (type === 'string') return JSON.stringify(v.length > 120 ? v.slice(0, 120) + '…' : v);
    return truncHex(v); // bytes / bytesN
  }
  if (Array.isArray(v)) {
    const inner = innerTypes(type, v.length);
    const MAX = 16;
    const parts = v
      .slice(0, MAX)
      .map((x, i) => (depth > 4 ? '…' : renderValue(inner[i] ?? '', x, short, depth + 1)));
    if (v.length > MAX) parts.push(`…+${v.length - MAX} more`);
    return type.startsWith('(') && !type.endsWith(']')
      ? `(${parts.join(', ')})`
      : `[${parts.join(', ')}]`;
  }
  return String(v);
}

/** Element types of an array type, or component types of a tuple type. */
function innerTypes(type: string, n: number): string[] {
  const arr = /^(.*)\[\d*\]$/.exec(type);
  if (arr) return new Array<string>(n).fill(arr[1]!);
  if (type.startsWith('(') && type.endsWith(')')) return splitTopLevel(type.slice(1, -1));
  return [];
}

/** Split "a,(b,c),d[]" at top-level commas. */
export function splitTopLevel(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      out.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur !== '') out.push(cur);
  return out;
}

/**
 * Strip characters that could break or forge lines in what a human reads:
 * C0/C1 controls (incl. \n, \r, \t), DEL, U+2028/2029 line/paragraph
 * separators and the bidi overrides/isolates. Applied at the render
 * boundary to every line of preview text, the headline and the warnings —
 * defence in depth behind the per-source checks (identifier-only ABI names,
 * quoted revert strings, allowlisted symbols).
 */
export function clean(s: string): string {
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    const bad =
      c < 0x20 ||
      (c >= 0x7f && c <= 0x9f) ||
      c === 0x2028 ||
      c === 0x2029 ||
      (c >= 0x202a && c <= 0x202e) ||
      (c >= 0x2066 && c <= 0x2069) ||
      c === 0x200e ||
      c === 0x200f;
    out += bad ? ' ' : ch;
  }
  return out;
}

/**
 * Sanitize a token symbol read from a contract. The symbol is chosen by
 * whoever deployed the token, and it lands on the user's phone and in the
 * agent's context: allow a conservative printable set and a short length,
 * or nothing (callers then fall back to the address).
 */
export function sanitizeSymbol(s: string): string | undefined {
  if (s.length > 64) return undefined;
  let end = s.length;
  while (end > 0 && s[end - 1] === '\0') end--;
  const t = s.slice(0, end).trim();
  if (!/^[A-Za-z0-9.$_+-]{1,16}$/.test(t)) return undefined;
  return t;
}
