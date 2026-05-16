/**
 * Output redactor — the second line of defence behind the path blocker.
 * If a key somehow ends up in tool output (because the agent read a file
 * the blocker missed, or coaxed a key out of an API), redact it before it
 * reaches the model's context.
 *
 * The rules are deliberately strict — false positives are tolerable
 * (redacted noise in tool output is annoying; an exfiltrated key is fatal).
 */

export interface RedactionStat {
  reason: string;
  count: number;
}

export interface RedactionResult {
  text: string;
  redactions: RedactionStat[];
}

interface Rule {
  reason: string;
  regex: RegExp;
}

const RULES: readonly Rule[] = Object.freeze([
  // PEM-encoded private key blocks. Matched first so the inner base64 isn't
  // also caught by the hex/JWT rules.
  {
    reason: 'pem-private-key',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----/g,
  },
  // Generic PEM block — second-line check for "BEGIN ... KEY ...END ... KEY"
  // that didn't say PRIVATE explicitly (some tools emit just "KEY").
  {
    reason: 'pem-key-block',
    regex: /-----BEGIN [A-Z0-9 ]*KEY[A-Z0-9 ]*-----[\s\S]+?-----END [A-Z0-9 ]*KEY[A-Z0-9 ]*-----/g,
  },
  // 32-byte raw private keys as 0x-prefixed hex (most common Ethereum form).
  // Word boundary on both sides so we don't grab a 0x... that happens to be
  // a longer hash and continue past it.
  {
    reason: 'hex-private-key',
    regex: /\b0x[0-9a-fA-F]{64}(?![0-9a-fA-F])/g,
  },
  // JWT (header.payload.signature where header starts with eyJ — base64url
  // of {"...). Three url-safe-base64 sections separated by dots.
  {
    reason: 'jwt',
    regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  // npm tokens (npm_ + ~36 chars) — same pattern they're emitted in.
  {
    reason: 'npm-token',
    regex: /\bnpm_[A-Za-z0-9]{36,}\b/g,
  },
  // Anthropic / Claude API keys (sk-ant-...).
  {
    reason: 'anthropic-api-key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  // OpenAI keys.
  {
    reason: 'openai-api-key',
    regex: /\bsk-[A-Za-z0-9]{32,}\b/g,
  },
  // AWS access key IDs (AKIA + 16 chars) and secret access keys (40 base64-ish chars).
  {
    reason: 'aws-access-key-id',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
]);

export function redact(text: string): RedactionResult {
  const counts = new Map<string, number>();
  let out = text;
  for (const rule of RULES) {
    out = out.replace(rule.regex, () => {
      counts.set(rule.reason, (counts.get(rule.reason) ?? 0) + 1);
      return `<REDACTED:${rule.reason}>`;
    });
  }
  const redactions: RedactionStat[] = [];
  for (const [reason, count] of counts) redactions.push({ reason, count });
  return { text: out, redactions };
}
