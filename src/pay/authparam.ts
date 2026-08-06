/**
 * RFC 9110 §11 challenge parsing, scoped to the "Payment" auth scheme.
 *
 * A 402 can carry several `WWW-Authenticate` headers, and each header can
 * carry several comma-separated challenges. Auth-param values may be tokens
 * or quoted-strings; commas both separate params within a challenge and
 * separate challenges within a header, so the grammar is only decidable by
 * lookahead: a bare token followed by `=` starts a new param, a bare token
 * NOT followed by `=` starts a new challenge (its scheme name).
 *
 * We deliberately parse only what MPP emits — `Payment` challenges whose
 * params are all `token=value` pairs — but tolerate and skip challenges of
 * other schemes sharing the header.
 */

export interface PaymentChallenge {
  /** Lowercased param names → unescaped values. */
  params: Record<string, string>;
}

const TOKEN_RE = /^[!#$%&'*+.^_`|~0-9a-zA-Z-]+$/;

interface Cursor {
  s: string;
  i: number;
}

function skipOws(c: Cursor): void {
  while (c.i < c.s.length && (c.s[c.i] === ' ' || c.s[c.i] === '\t')) c.i++;
}

function readToken(c: Cursor): string | null {
  const start = c.i;
  while (c.i < c.s.length && TOKEN_RE.test(c.s[c.i]!)) c.i++;
  return c.i > start ? c.s.slice(start, c.i) : null;
}

function readQuotedString(c: Cursor): string | null {
  if (c.s[c.i] !== '"') return null;
  c.i++;
  let out = '';
  while (c.i < c.s.length) {
    const ch = c.s[c.i]!;
    if (ch === '\\' && c.i + 1 < c.s.length) {
      out += c.s[c.i + 1]!;
      c.i += 2;
      continue;
    }
    if (ch === '"') {
      c.i++;
      return out;
    }
    out += ch;
    c.i++;
  }
  return null; // unterminated
}

/**
 * Parse every Payment challenge out of a list of WWW-Authenticate header
 * values. Malformed trailing input ends parsing of that header value rather
 * than throwing: a 402 with one good challenge and one garbled one should
 * still be payable.
 */
export function parsePaymentChallenges(headerValues: readonly string[]): PaymentChallenge[] {
  const out: PaymentChallenge[] = [];
  for (const value of headerValues) {
    const c: Cursor = { s: value, i: 0 };
    let current: PaymentChallenge | null = null;
    skipOws(c);
    while (c.i < c.s.length) {
      const token = readToken(c);
      if (token === null) break;
      skipOws(c);
      if (c.s[c.i] === '=') {
        // auth-param — belongs to the current challenge (if it's Payment).
        c.i++;
        skipOws(c);
        const v = c.s[c.i] === '"' ? readQuotedString(c) : readToken(c);
        if (v === null) break;
        if (current) current.params[token.toLowerCase()] = v;
      } else {
        // scheme name — starts a new challenge.
        if (token.toLowerCase() === 'payment') {
          current = { params: {} };
          out.push(current);
        } else {
          current = null;
        }
      }
      skipOws(c);
      if (c.s[c.i] === ',') {
        c.i++;
        skipOws(c);
      }
    }
  }
  return out;
}
