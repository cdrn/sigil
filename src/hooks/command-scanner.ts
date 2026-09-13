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

// Newlines separate statements too (the original scanner missed this, so a
// read on the second line of a multi-line command was never seen).
const COMMAND_SEPARATORS = /[;&|\n]|\$\(|`/;

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

/**
 * Programs that execute what they are handed (as arguments or on stdin).
 * Text flowing into one of these is code, so it is never carved out.
 */
const INTERPRETERS: ReadonlySet<string> = new Set([
  'bash',
  'sh',
  'zsh',
  'dash',
  'ksh',
  'busybox',
  'eval',
  'source',
  '.',
  'exec',
  'command',
  'builtin',
  'env',
  'sudo',
  'doas',
  'nohup',
  'time',
  'nice',
  'ionice',
  'timeout',
  'xargs',
  'watch',
  'script',
  'node',
  'python',
  'python3',
  'perl',
  'ruby',
  'php',
  'deno',
  'bun',
  'osascript',
  'expect',
  'awk',
  'sed',
]);

/** A line of the command whose output could reach an interpreter or a file. */
const FLOWS_ONWARD = /[|>]|\$\(|`|<\(|>\(/;

/**
 * Blank out regions of the command that are provably inert — data the shell
 * never executes and no program in the command interprets — before the
 * conservative statement scan runs (#92). Everything else is left exactly
 * as it was, so whatever the scanner refused before, it still refuses; the
 * carve-outs only remove false positives, never add acceptances of code.
 *
 * Carved:
 *   1. The body of a heredoc with a *simply* quoted delimiter
 *      (`<<'WORD'` / `<<"WORD"`, WORD = identifier, nothing glued after the
 *      closing quote), when the opener statement's program (after any
 *      VAR=value prefixes) is not an interpreter and the opener line does
 *      not pipe, redirect, or substitute its output anywhere. A quoted
 *      delimiter means the shell performs no expansion in the body; the
 *      other conditions mean nothing else will execute it either. One
 *      exception to "no redirect": `> FILE` is allowed when every other
 *      mention of FILE in the command is an argument to git or gh (the
 *      commit-message / PR-body workflow) — those consume it as text.
 *   2. Message strings handed to git or gh (`-m`, `--message`, `--body`,
 *      `--title`, `--notes`, and their `=` forms) when the string contains
 *      no `$(` or backtick. git and gh store these; they never execute them.
 *
 * Replaced text keeps its newlines so no statement boundaries move.
 */
export function stripInertText(command: string): string {
  let out = carveQuotedHeredocs(command);
  out = carveMessageStrings(out);
  return out;
}

function blank(text: string): string {
  return text.replace(/[^\n]/g, ' ');
}

const HEREDOC_OPENER = /<<-?\s*(['"])([A-Za-z_][A-Za-z0-9_]*)\1(?=[\s;&|)<>]|$)/g;

function carveQuotedHeredocs(command: string): string {
  const lines = command.split('\n');
  const outLines = [...lines];
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li]!;
    HEREDOC_OPENER.lastIndex = 0;
    const m = HEREDOC_OPENER.exec(line);
    if (!m) continue;
    // Only the first heredoc on a line is handled; a second one, or any
    // unquoted one, leaves the line to the conservative scan.
    if (HEREDOC_OPENER.exec(line) || /<<-?\s*[^'"\s]/.test(line.replace(m[0], ''))) continue;
    const dash = m[0].startsWith('<<-');
    const delim = m[2]!;
    const program = openerProgram(line.slice(0, m.index));
    if (INTERPRETERS.has(program)) continue;
    const rest = line.slice(0, m.index) + line.slice(m.index + m[0].length);
    if (/[|]|\$\(|`|<\(|>\(/.test(rest)) continue;
    const redirect = /(?:^|\s)>{1,2}\s*(\S+)/.exec(rest);
    if (redirect) {
      const target = redirect[1]!;
      if (!onlyConsumedByGit(command, target, li)) continue;
    } else if (/[<>]/.test(rest.replace(/<<-?/, ''))) {
      continue;
    }
    // Find the terminator line.
    let end = -1;
    for (let j = li + 1; j < lines.length; j++) {
      const cmp = dash ? lines[j]!.replace(/^\t+/, '') : lines[j]!;
      if (cmp === delim) {
        end = j;
        break;
      }
    }
    if (end === -1) continue; // unterminated: leave it alone
    for (let j = li + 1; j < end; j++) outLines[j] = blank(lines[j]!);
    li = end;
  }
  return outLines.join('\n');
}

/** First program word of an opener statement, skipping VAR=value prefixes. */
function openerProgram(prefix: string): string {
  // The opener statement starts after the last separator on the line.
  const seg = prefix.split(/[;&|]|\$\(|`/).pop() ?? '';
  const words = seg.trim().split(/\s+/).filter(Boolean);
  for (const w of words) {
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
    const bare = w.replace(/^["']|["']$/g, '');
    const slash = bare.lastIndexOf('/');
    return (slash === -1 ? bare : bare.slice(slash + 1)).toLowerCase();
  }
  return '';
}

/**
 * True when every line other than `openerLine` that mentions `target` is a
 * git/gh statement (which reads it as text). Any other mention — `bash
 * target`, `source target`, `./target`, `chmod` — keeps the body unscanned
 * text from being carved.
 */
function onlyConsumedByGit(command: string, target: string, openerLine: number): boolean {
  const lines = command.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (i === openerLine || !lines[i]!.includes(target)) continue;
    for (const stmt of lines[i]!.split(/[;&|]|\$\(|`/)) {
      if (!stmt.includes(target)) continue;
      const prog = openerProgram(stmt + ' ');
      if (prog !== 'git' && prog !== 'gh') return false;
      if (FLOWS_ONWARD.test(stmt.replace(target, ''))) return false;
    }
  }
  return true;
}

const MESSAGE_FLAG =
  /(?:^|\s)(?:-m|--message|--body|--title|--notes|--body-file=-|-F\s*-)(?:\s+|=)('(?:[^'])*'|"(?:[^"\\]|\\.)*")/g;

function carveMessageStrings(command: string): string {
  return command
    .split('\n')
    .map((line) => {
      const prog = openerProgram(line.split(/[;&|]/)[0] + ' ');
      if (prog !== 'git' && prog !== 'gh') return line;
      return line.replace(MESSAGE_FLAG, (whole, str: string) => {
        if (/\$\(|`/.test(str)) return whole; // a substitution inside is code
        return (
          whole.slice(0, whole.length - str.length) +
          str[0] +
          blank(str.slice(1, -1)) +
          str[str.length - 1]
        );
      });
    })
    .join('\n');
}

/** Shells whose `-c` argument is a script. */
const SHELLS: ReadonlySet<string> = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'busybox']);
/** Wrappers that run their remaining arguments as a command. */
const WRAPPERS: ReadonlySet<string> = new Set([
  'sudo',
  'doas',
  'env',
  'command',
  'builtin',
  'exec',
  'nohup',
  'time',
  'nice',
  'ionice',
  'timeout',
  'watch',
  'xargs',
]);

/**
 * Strictly additive: for a statement that hands text to a shell (`sh -c
 * "…"`, `eval …`) or wraps another command (`sudo cat …`, `env X=1 cat …`),
 * surface that text as statements of its own so the reader check sees it.
 * Only the `-c` payload of a shell and the arguments of eval are treated as
 * scripts — other quoted arguments (positional parameters, printf formats)
 * are data and are left alone.
 */
function expandInterpreters(statements: readonly string[], depth = 0): string[] {
  if (depth > 4) return [...statements];
  const out: string[] = [];
  for (const stmt of statements) {
    out.push(stmt);
    const toks = tokenize(stmt);
    if (toks.length < 2) continue;
    const prog = programName(toks[0]!);
    let script: string | null = null;
    let rest: string[] | null = null;
    if (SHELLS.has(prog)) {
      const c = toks.findIndex((t, i) => i > 0 && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(t));
      if (c !== -1 && toks[c + 1]) script = stripShellQuoting(toks[c + 1]!);
    } else if (prog === 'eval') {
      script = toks.slice(1).map(stripShellQuoting).join(' ');
    } else if (WRAPPERS.has(prog)) {
      // Drop option flags, VAR=value assignments and bare numbers (timeout
      // durations, nice levels) to reach the wrapped command.
      rest = toks
        .slice(1)
        .filter(
          (t) =>
            !t.startsWith('-') && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t) && !/^\d+[smhd]?$/.test(t),
        );
    }
    if (script !== null) {
      out.push(...expandInterpreters(script.split(COMMAND_SEPARATORS), depth + 1));
    }
    if (rest && rest.length > 0) {
      out.push(...expandInterpreters([rest.join(' ')], depth + 1));
    }
  }
  return out;
}

const QUOTED_OR_WORD = String.raw`'[^']*'|"(?:[^"\\]|\\.)*"|\S+`;
const SHELL_C_RE = new RegExp(
  String.raw`(?:^|[;&|\n(\`]\s*)(?:\S*/)?(?:bash|sh|zsh|dash|ksh|busybox\s+sh)\s+(?:-\S+\s+)*?-[a-zA-Z]*c[a-zA-Z]*\s+(${QUOTED_OR_WORD})`,
  'g',
);
const EVAL_RE = new RegExp(
  String.raw`(?:^|[;&|\n(\`]\s*)eval\s+((?:${QUOTED_OR_WORD})(?:\s+(?:${QUOTED_OR_WORD}))*)`,
  'g',
);

/**
 * The scripts a command hands to a shell (`sh -c '…'`) or to eval, taken
 * from the raw text with quote-aware matching, each split into statements
 * (and expanded again, for nesting). Additive: these only add statements
 * for the reader check to look at.
 */
function interpreterPayloads(command: string, depth = 0): string[] {
  if (depth > 4) return [];
  const out: string[] = [];
  // matchAll clones the regex, so recursion below can't disturb this walk.
  for (const m of command.matchAll(SHELL_C_RE)) {
    const payload = stripShellQuoting(m[1]!);
    out.push(...payload.split(COMMAND_SEPARATORS), ...interpreterPayloads(payload, depth + 1));
  }
  for (const m of command.matchAll(EVAL_RE)) {
    const payload = tokenize(m[1]!).map(stripShellQuoting).join(' ');
    out.push(...payload.split(COMMAND_SEPARATORS), ...interpreterPayloads(payload, depth + 1));
  }
  return out;
}

function programName(tok: string): string {
  const bare = stripShellQuoting(tok);
  const slash = bare.lastIndexOf('/');
  return (slash === -1 ? bare : bare.slice(slash + 1)).toLowerCase();
}

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
  // Backslash-newline is removed by the shell before anything else (so
  // `ca\<nl>t` is `cat` and `a.key\<nl>.txt` is `a.key.txt`); do the same.
  const joined = stripInertText(command.replace(/\\\n/g, ''));
  // Payloads handed to a shell or eval are matched on the raw text first —
  // the naive split below would cut inside their quotes and hide them.
  const statements = expandInterpreters([
    ...joined.split(COMMAND_SEPARATORS),
    ...interpreterPayloads(joined),
  ]);
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
