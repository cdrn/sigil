import { isBlockedPath, type BlockerOpts, type BlockDecision } from './path-blocker.js';

/**
 * Scan a bash command for attempts to read a blocked path. Best-effort:
 * a determined shell can always obfuscate, but we catch the obvious cases
 * that a confused agent (or basic prompt injection) would produce.
 *
 * Model: path-token checks only fire when the statement's program is on the
 * READER_COMMANDS allowlist below. That keeps the scanner from blocking
 * benign commands that *mention* a path token without reading it — e.g.
 * `git commit -F message.txt` (the file is recorded as a commit message,
 * not read into the shell) or `gh pr create --body-file body.md`. Statement
 * separators include `$(...)` and backticks, so `git commit -m "$(cat .env)"`
 * still trips on the inner `cat`.
 *
 * Separately, ALWAYS_BLOCK_COMMAND_PATTERNS fires unconditionally for
 * commands that are intrinsically dangerous regardless of classification
 * (`gpg --export-secret-keys`, `ssh-keygen -y`, `openssl pkey -in`).
 */

const COMMAND_SEPARATORS = /[;&|]|\$\(|`/;

const ALWAYS_BLOCK_COMMAND_PATTERNS: readonly { regex: RegExp; reason: string }[] = Object.freeze([
  {
    regex: /\bgpg\b[^|;]*--export-secret-keys?/i,
    reason: 'gpg --export-secret-keys reads private GPG key material',
  },
  {
    regex: /\bssh-keygen\b[^|;]*-y\b/i,
    reason: 'ssh-keygen -y reads a private SSH key to derive the public key',
  },
  { regex: /\bopenssl\b[^|;]*(pkey|rsa|ec)\b[^|;]*-(in|noout)/i, reason: 'openssl key dump' },
]);

/**
 * Programs whose arguments we treat as candidate path reads. Start
 * conservative (false negatives are worse than false positives for the
 * threat we care about) but exclude commands that take paths as *data* —
 * `git commit -F`, `gh pr create --body-file`, build tools, etc.
 *
 * `find` is included because `find ... -exec <reader>` is too easy a
 * bypass; treating it as a reader lets the path-token loop catch the
 * `-exec` target argument as well.
 */
const READER_COMMANDS: ReadonlySet<string> = new Set([
  // bulk file readers
  'cat',
  'bat',
  'tac',
  'nl',
  // paged / streamed readers
  'less',
  'more',
  'head',
  'tail',
  // editors (a deliberate open is a read)
  'vi',
  'vim',
  'view',
  'nvim',
  'nano',
  'emacs',
  'code',
  'subl',
  'open',
  // binary inspectors
  'xxd',
  'od',
  'hexdump',
  'strings',
  'file',
  // searchers that print matches from files
  'grep',
  'egrep',
  'fgrep',
  'rg',
  'ag',
  'ack',
  'sift',
  // stream filters that can take a path arg and print contents
  'tee',
  'tr',
  'sed',
  'awk',
  // compressed-content dumpers
  'zcat',
  'bzcat',
  'xzcat',
  'gunzip',
  // walks the tree; `-exec <reader>` is a trivial bypass otherwise
  'find',
]);

export function scanBashCommand(
  command: string,
  opts: BlockerOpts = {},
): BlockDecision & { reason?: string } {
  // 1. Always-block patterns — shape-based, fire regardless of classification.
  for (const { regex, reason } of ALWAYS_BLOCK_COMMAND_PATTERNS) {
    if (regex.test(command)) {
      return { blocked: true, reason };
    }
  }

  // 2. Per-statement path scan, gated on the program being a known reader.
  //    COMMAND_SEPARATORS splits on `$(` and backticks too, so a `cat` hidden
  //    inside a substitution surfaces as the first token of its own statement.
  const statements = command.split(COMMAND_SEPARATORS);
  for (const stmt of statements) {
    const tokens = tokenize(stmt);
    if (tokens.length === 0) continue;
    if (!isReaderCommand(tokens[0]!)) continue;
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
 * Match the program token against READER_COMMANDS. Strips any leading path
 * (`/usr/bin/cat` → `cat`) and any shell quoting, then case-folds for
 * platforms with case-insensitive filesystems.
 */
function isReaderCommand(programToken: string): boolean {
  const stripped = stripShellQuoting(programToken);
  const slash = stripped.lastIndexOf('/');
  const base = (slash === -1 ? stripped : stripped.slice(slash + 1)).toLowerCase();
  return READER_COMMANDS.has(base);
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
  if (/\.(key|keystore|jks|p12)$/i.test(tok)) return true;
  return false;
}
