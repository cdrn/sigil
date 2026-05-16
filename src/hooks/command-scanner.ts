import { isBlockedPath, type BlockerOpts, type BlockDecision } from './path-blocker.js';

/**
 * Scan a bash command for attempts to read a blocked path. Best-effort:
 * a determined shell can always obfuscate, but we catch the obvious cases
 * that a confused agent (or basic prompt injection) would produce.
 *
 * Approach:
 *  1. Tokenize the command crudely on whitespace and shell metacharacters.
 *  2. Skip the first token of each statement (the program name itself).
 *  3. Check each remaining token against the path blocker.
 *  4. Also detect a few "always block" reader commands when they appear at
 *     a position that suggests they're targeting a key (e.g. `gpg
 *     --export-secret-keys`).
 */

const COMMAND_SEPARATORS = /[;&|]|\$\(|`/;

const ALWAYS_BLOCK_COMMAND_PATTERNS: readonly { regex: RegExp; reason: string }[] = Object.freeze([
  { regex: /\bgpg\b[^|;]*--export-secret-keys?/i, reason: 'gpg --export-secret-keys reads private GPG key material' },
  { regex: /\bssh-keygen\b[^|;]*-y\b/i, reason: 'ssh-keygen -y reads a private SSH key to derive the public key' },
  { regex: /\bopenssl\b[^|;]*(pkey|rsa|ec)\b[^|;]*-(in|noout)/i, reason: 'openssl key dump' },
]);

export function scanBashCommand(command: string, opts: BlockerOpts = {}): BlockDecision & { reason?: string } {
  // Check always-block patterns first; they're command-shape based.
  for (const { regex, reason } of ALWAYS_BLOCK_COMMAND_PATTERNS) {
    if (regex.test(command)) {
      return { blocked: true, reason };
    }
  }

  // Tokenize the command. Split on statement separators first so we treat
  // each statement's program name separately.
  const statements = command.split(COMMAND_SEPARATORS);
  for (const stmt of statements) {
    const tokens = tokenize(stmt);
    if (tokens.length === 0) continue;
    // Skip the first token (program name) — we don't want to block on a path
    // that happens to coincide with the script being executed. Args follow.
    for (let i = 1; i < tokens.length; i++) {
      const tok = stripShellQuoting(tokens[i]!);
      if (looksLikePath(tok)) {
        const decision = isBlockedPath(tok, opts);
        if (decision.blocked) {
          return {
            blocked: true,
            ...(decision.matchedPattern ? { matchedPattern: decision.matchedPattern } : {}),
            reason: `command argument "${tok}" matches blocked pattern ${decision.matchedPattern}`,
          };
        }
      }
    }
  }
  return { blocked: false };
}

/**
 * Very crude tokenization: split on whitespace but respect quoted strings.
 * Good enough for the obvious-read-attempt detection we're going for.
 */
function tokenize(s: string): string[] {
  const tokens: string[] = [];
  let cur = '';
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '\\' && i + 1 < s.length) {
      cur += c + s[i + 1];
      i++;
      continue;
    }
    if (c === "'" && !inDouble) {
      inSingle = !inSingle;
      cur += c;
      continue;
    }
    if (c === '"' && !inSingle) {
      inDouble = !inDouble;
      cur += c;
      continue;
    }
    if (/\s/.test(c) && !inSingle && !inDouble) {
      if (cur.length > 0) {
        tokens.push(cur);
        cur = '';
      }
      continue;
    }
    cur += c;
  }
  if (cur.length > 0) tokens.push(cur);
  return tokens;
}

function stripShellQuoting(tok: string): string {
  // Strip outer matching quotes; leave backslash escapes for the FS layer.
  if (tok.length >= 2) {
    const first = tok[0]!;
    const last = tok[tok.length - 1]!;
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return tok.slice(1, -1);
    }
  }
  return tok;
}

function looksLikePath(tok: string): boolean {
  // Flags don't look like paths.
  if (tok.startsWith('-')) return false;
  // Heuristic: contains a slash, OR starts with a dot (e.g. ".env"),
  // OR is a bare filename ending in a key-ish extension.
  if (tok.includes('/')) return true;
  if (tok.startsWith('.')) return true;
  if (/\.(pem|key|keystore|jks|p12)$/i.test(tok)) return true;
  return false;
}
