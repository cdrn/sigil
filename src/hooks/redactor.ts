/**
 * Output redactor — the second line of defence behind the path blocker.
 * If a key somehow ends up in tool output (because the agent read a file
 * the blocker missed, or coaxed a key out of an API), redact it before it
 * reaches the model's context.
 *
 * This layer, not the path blocker, is what protects mixed-content files
 * like `.env`: we deliberately let the agent READ them (blocking every
 * `.env` would break ordinary work and give false assurance — secrets live
 * in many places), and instead strip the dangerous *values* out of the
 * output. So `cat .env` returns with PORT / DATABASE_URL intact and
 * PRIVATE_KEY / MNEMONIC redacted.
 *
 * The rules are deliberately strict — false positives are tolerable
 * (redacted noise in tool output is annoying; an exfiltrated key is fatal) —
 * except the mnemonic pass, which is checksum-validated precisely because a
 * loose "N words" rule would shred normal prose.
 */

import { redactMnemonics } from './bip39.js';

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
  /**
   * Replacement template when the rule redacts only part of the match (uses
   * `$1` etc. capture groups). When omitted, the entire match is replaced
   * with the `<REDACTED:reason>` placeholder.
   */
  replacement?: string;
}

const RULES: readonly Rule[] = Object.freeze([
  // PEM-encoded private key blocks. Matched first so the inner base64 isn't
  // also caught by the hex/JWT rules.
  {
    reason: 'pem-private-key',
    regex:
      /-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----/g,
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
  // Signing-secret assignments (`.env`, YAML, shell export). Redacts the
  // VALUE, keeps the name, so the agent still sees that the var exists. Scoped
  // to key/mnemonic/seed names — the crown jewels for a signing tool — rather
  // than every SECRET/TOKEN/PASSWORD, to stay off ordinary config the agent
  // legitimately needs while debugging. Anchored per-line (m flag).
  {
    reason: 'env-secret',
    regex:
      /^([ \t]*(?:export[ \t]+)?[A-Za-z0-9_]*(?:PRIVATE_?KEY|MNEMONIC|SEED_?PHRASE|SECRET_?KEY)[A-Za-z0-9_]*[ \t]*[=:][ \t]*)(?:"[^"]*"|'[^']*'|.+)$/gim,
    replacement: '$1<REDACTED:env-secret>',
  },
]);

export function redact(text: string): RedactionResult {
  const counts = new Map<string, number>();
  let out = text;

  // Checksum-validated seed phrases first: a mnemonic is plain lowercase
  // words, so running it before the shape rules avoids any interaction, and
  // its placeholder contains no wordlist words for later rules to touch.
  const mnemonic = redactMnemonics(out, '<REDACTED:mnemonic>');
  if (mnemonic.count > 0) {
    counts.set('mnemonic', mnemonic.count);
    out = mnemonic.text;
  }

  for (const rule of RULES) {
    out = out.replace(rule.regex, (...args) => {
      counts.set(rule.reason, (counts.get(rule.reason) ?? 0) + 1);
      if (rule.replacement === undefined) return `<REDACTED:${rule.reason}>`;
      // Expand $1..$9 in the replacement template from the capture groups.
      return rule.replacement.replace(/\$(\d)/g, (_m, d: string) => args[Number(d)] ?? '');
    });
  }
  const redactions: RedactionStat[] = [];
  for (const [reason, count] of counts) redactions.push({ reason, count });
  return { text: out, redactions };
}
