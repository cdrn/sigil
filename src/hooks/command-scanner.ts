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

/**
 * Programs that execute their string arguments (or their stdin) as shell.
 * Text handed to one of these is code, however it was quoted, so it is
 * scanned as commands rather than treated as literal data.
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
]);

const MAX_DEPTH = 6;

/**
 * Split a shell command line into every statement that could run a
 * program, following Bash's own lexical rules closely enough that quoted
 * prose is never mistaken for code and code is never mistaken for prose:
 *
 *   - `;`, `&`, `|`, newlines separate statements outside quotes;
 *   - a `#` that starts a word begins a comment to end of line;
 *   - single quotes are literal through the next `'` (backslash does not
 *     escape inside them); double quotes are literal except that `$(…)`
 *     and backticks inside them execute and are parsed recursively with a
 *     fresh quote context; `((…))` and `$((…))` are arithmetic and opaque;
 *   - `<<<` is a here-string (data). `<<` / `<<-` opens a heredoc whose
 *     delimiter is the whole following word; the rest of the opener line is
 *     still command text; the body runs from the next line to the
 *     delimiter line (leading tabs stripped only for `<<-`; for an unquoted
 *     delimiter, backslash-newline joins body lines first). A quoted
 *     delimiter makes the body literal to the shell — but it is still code
 *     if the opener's program is an interpreter (`bash <<'EOF'`). An
 *     unquoted delimiter's body expands, so the substitutions inside it
 *     are surfaced as statements;
 *   - statements whose program is an interpreter (`bash -c '…'`, `eval …`,
 *     `sudo cat …`, `xargs cat`) have their arguments scanned as commands.
 *
 * The result is used only to classify: each statement's first token is
 * checked against the reader list and its path-like tokens against the
 * wardlist. Anything this parser cannot follow errs toward *more*
 * statements (a separator seen is a split made), never fewer.
 */
export function splitStatements(command: string, depth = 0): string[] {
  if (depth > MAX_DEPTH) return [command];
  const out: string[] = [];
  parseScript(command, 0, null, depth, out);
  return out;
}

interface Heredoc {
  delim: string;
  quoted: boolean;
  dash: boolean;
  /** First token of the opener statement, to tell `bash <<'EOF'` from `cat <<'EOF'`. */
  program: string;
}

/**
 * Parse statements from `src[i..]` until `stop` (a closing `)` for `$(`, a
 * backtick for `…`, or end of input). Appends statements to `out`; returns
 * the index just past the terminator.
 */
function parseScript(
  src: string,
  i: number,
  stop: ')' | '`' | null,
  depth: number,
  out: string[],
): number {
  const n = src.length;
  let cur = '';
  let parenDepth = 0;
  let pending: Heredoc[] = [];
  const flush = (): void => {
    if (cur.trim().length > 0) out.push(cur);
    cur = '';
  };
  const atWordStart = (): boolean => cur.length === 0 || /[\s;&|(]$/.test(cur);
  while (i < n) {
    const c = src[i]!;
    // Terminators for nested contexts.
    if (stop === '`' && c === '`') {
      flush();
      return i + 1;
    }
    if (stop === ')' && c === ')' && parenDepth === 0) {
      flush();
      return i + 1;
    }
    if (c === '\\' && i + 1 < n) {
      // Backslash-newline is a continuation of the same statement.
      cur += c + src[i + 1];
      i += 2;
      continue;
    }
    if (c === '#' && atWordStart()) {
      const eol = src.indexOf('\n', i);
      i = eol === -1 ? n : eol; // the newline itself is handled below
      continue;
    }
    if (c === "'") {
      const close = src.indexOf("'", i + 1);
      const seg = close === -1 ? src.slice(i) : src.slice(i, close + 1);
      cur += seg;
      i += seg.length;
      continue;
    }
    if (c === '"') {
      i = parseDoubleQuoted(src, i, depth, out, (t) => (cur += t));
      continue;
    }
    if (c === '$' && src.startsWith('$((', i)) {
      const close = findArithmeticEnd(src, i + 3);
      cur += src.slice(i, close);
      i = close;
      continue;
    }
    if (c === '(' && src.startsWith('((', i) && atWordStart()) {
      const close = findArithmeticEnd(src, i + 2);
      cur += src.slice(i, close);
      i = close;
      continue;
    }
    if (c === '$' && src[i + 1] === '(') {
      cur += ' ';
      i = parseScript(src, i + 2, ')', depth + 1, out);
      continue;
    }
    if (c === '`') {
      cur += ' ';
      i = parseScript(src, i + 1, '`', depth + 1, out);
      continue;
    }
    if (c === '(') {
      parenDepth++;
      flush();
      i++;
      continue;
    }
    if (c === ')') {
      if (parenDepth > 0) parenDepth--;
      flush();
      i++;
      continue;
    }
    if (c === '<' && src.startsWith('<<<', i)) {
      // Here-string: the operand is data, and `<<<` is not a heredoc opener.
      cur += '<<<';
      i += 3;
      continue;
    }
    if (c === '<' && src.startsWith('<<', i)) {
      // The delimiter is the whole following word; any quoting anywhere in
      // it (quotes or backslashes) makes the body literal, and the
      // terminator is the word with that quoting removed.
      const m = /^<<(-?)\s*((?:'[^']*'|"[^"]*"|\\.|[^\s;&|<>()'"\\])+)/.exec(src.slice(i));
      if (m) {
        const dash = m[1] === '-';
        const word = m[2]!;
        const quoted = /['"\\]/.test(word);
        const delim = word.replace(/'([^']*)'|"([^"]*)"|\\(.)/g, (_, a, b, c) => a ?? b ?? c);
        const program = firstToken(cur);
        pending.push({ delim, quoted, dash, program });
        cur += ' ';
        i += m[0].length;
        continue;
      }
    }
    if (c === '\n') {
      flush();
      i++;
      if (pending.length > 0) {
        i = consumeHeredocBodies(src, i, pending, depth, out);
        pending = [];
      }
      continue;
    }
    if (c === ';' || c === '&' || c === '|') {
      flush();
      i++;
      continue;
    }
    cur += c;
    i++;
  }
  flush();
  // Heredocs opened on the last line with no body: nothing to consume.
  return n;
}

/** Copy a double-quoted string into `emit`, surfacing substitutions as statements. */
function parseDoubleQuoted(
  src: string,
  i: number,
  depth: number,
  out: string[],
  emit: (text: string) => void,
): number {
  const n = src.length;
  emit('"');
  i++;
  while (i < n) {
    const c = src[i]!;
    if (c === '\\' && i + 1 < n) {
      emit(c + src[i + 1]);
      i += 2;
      continue;
    }
    if (c === '"') {
      emit('"');
      return i + 1;
    }
    if (c === '$' && src.startsWith('$((', i)) {
      const close = findArithmeticEnd(src, i + 3);
      emit(src.slice(i, close));
      i = close;
      continue;
    }
    if (c === '$' && src[i + 1] === '(') {
      emit(' ');
      i = parseScript(src, i + 2, ')', depth + 1, out);
      continue;
    }
    if (c === '`') {
      emit(' ');
      i = parseScript(src, i + 1, '`', depth + 1, out);
      continue;
    }
    emit(c);
    i++;
  }
  return n; // unterminated: the rest was literal
}

/** Index just past the `))` closing an arithmetic expression opened at `i`. */
function findArithmeticEnd(src: string, i: number): number {
  let depth = 1;
  while (i < src.length) {
    if (src.startsWith('((', i)) {
      depth++;
      i += 2;
      continue;
    }
    if (src.startsWith('))', i)) {
      depth--;
      i += 2;
      if (depth === 0) return i;
      continue;
    }
    i++;
  }
  return src.length;
}

/** Consume the bodies of every heredoc opened on the line that just ended. */
function consumeHeredocBodies(
  src: string,
  i: number,
  pending: readonly Heredoc[],
  depth: number,
  out: string[],
): number {
  const n = src.length;
  for (const h of pending) {
    const bodyLines: string[] = [];
    let carry = '';
    for (;;) {
      if (i >= n) break;
      const nl = src.indexOf('\n', i);
      let line = nl === -1 ? src.slice(i) : src.slice(i, nl);
      i = nl === -1 ? n : nl + 1;
      if (!h.quoted && line.endsWith('\\')) {
        // Backslash-newline joins lines in an expanding heredoc.
        carry += line.slice(0, -1);
        continue;
      }
      line = carry + line;
      carry = '';
      const cmp = h.dash ? line.replace(/^\t+/, '') : line;
      if (cmp === h.delim) break;
      bodyLines.push(line);
    }
    if (isInterpreter(h.program)) {
      // The body is a script for that program, however it was quoted.
      for (const s of splitStatements(bodyLines.join('\n'), depth + 1)) out.push(s);
    } else if (!h.quoted) {
      // Expanding body: only its substitutions run. Quotes are literal in a
      // heredoc, so scan the whole body (substitutions may span lines) for
      // `$(…)` and backticks alone.
      scanExpandingText(bodyLines.join('\n'), depth + 1, out);
    }
    // Quoted body for a non-interpreter: literal data, nothing to scan.
  }
  return i;
}

/** Surface the substitutions in text where quotes are literal (heredoc bodies). */
function scanExpandingText(text: string, depth: number, out: string[]): void {
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i]!;
    if (c === '\\' && i + 1 < n) {
      i += 2;
      continue;
    }
    if (c === '$' && text.startsWith('$((', i)) {
      i = findArithmeticEnd(text, i + 3);
      continue;
    }
    if (c === '$' && text[i + 1] === '(') {
      i = parseScript(text, i + 2, ')', depth, out);
      continue;
    }
    if (c === '`') {
      i = parseScript(text, i + 1, '`', depth, out);
      continue;
    }
    i++;
  }
}

function firstToken(stmt: string): string {
  const toks = tokenize(stmt);
  return toks.length > 0 ? stripShellQuoting(toks[0]!) : '';
}

function baseName(prog: string): string {
  const stripped = stripShellQuoting(prog);
  const slash = stripped.lastIndexOf('/');
  return (slash === -1 ? stripped : stripped.slice(slash + 1)).toLowerCase();
}

function isInterpreter(prog: string): boolean {
  return INTERPRETERS.has(baseName(prog));
}

/**
 * Expand statements whose program is an interpreter: its arguments are a
 * command in their own right (`sudo cat X`, `xargs cat`), and any quoted
 * argument is a script (`bash -c '…'`, `eval "…"`), scanned recursively.
 */
function expandInterpreters(statements: readonly string[], depth = 0): string[] {
  if (depth > MAX_DEPTH) return [...statements];
  const out: string[] = [];
  for (const stmt of statements) {
    out.push(stmt);
    const toks = tokenize(stmt);
    if (toks.length < 2 || !isInterpreter(toks[0]!)) continue;
    // The remaining tokens as a command of their own (skipping option flags
    // and VAR=value assignments that env/sudo accept).
    const rest = toks
      .slice(1)
      .filter((t) => !t.startsWith('-') && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t));
    if (rest.length > 0) out.push(...expandInterpreters([rest.join(' ')], depth + 1));
    // Each quoted argument is a script.
    for (const t of toks.slice(1)) {
      const inner = stripShellQuoting(t);
      if (inner !== t)
        out.push(...expandInterpreters(splitStatements(inner, depth + 1), depth + 1));
    }
  }
  return out;
}

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
  // block copier: `dd if=<file>` prints the file
  'dd',
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
  //    splitStatements surfaces `$(` and backtick bodies as their own
  //    statements, so a `cat` hidden inside a substitution is seen as the
  //    first token; quoted prose and heredoc bodies never are.
  const statements = expandInterpreters(splitStatements(command));
  for (const stmt of statements) {
    const tokens = tokenize(stmt);
    if (tokens.length === 0) continue;
    // `< file` (or `$(< file)`) reads the file with no program at all.
    const redirectRead = tokens[0] === '<' || tokens[0]!.startsWith('<');
    if (!redirectRead && !isReaderCommand(tokens[0]!)) continue;
    for (let i = redirectRead ? 0 : 1; i < tokens.length; i++) {
      const tok = stripShellQuoting(tokens[i]!).replace(/^<+/, '');
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
      if (s[i + 1] === '\n' && !inSingle) {
        // Line continuation: acts as whitespace between tokens.
        if (!inDouble && cur.length > 0) {
          tokens.push(cur);
          cur = '';
        }
        i++;
        continue;
      }
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
