// Tiny POSIX-style glob → regex translator. Just enough to support our
// blocklist patterns (~/.sigil/everything, *.key at any depth, etc.).
//
// Supported syntax:
//   double-star (globstar): match anything including path separators
//   single-star            : match anything except path separators
//   ?                      : match one char except separator
//   [abc], [a-z]           : char class (passed through to RegExp)
//   everything else        : literal
//
// `~` is expanded to the user's home directory before matching.
// Matches are case-sensitive; paths are normalised by collapsing repeated
// slashes and resolving `.` and `..` segments lexically.

import { homedir } from 'node:os';

export function expandTilde(path: string): string {
  if (path.startsWith('~/')) return homedir() + path.slice(1);
  if (path === '~') return homedir();
  return path;
}

function lexicalNormalize(path: string): string {
  // Collapse repeated slashes, resolve "." and ".." purely syntactically.
  // Leading "/" preserved.
  const isAbs = path.startsWith('/');
  const parts: string[] = [];
  for (const seg of path.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (parts.length > 0 && parts[parts.length - 1] !== '..') parts.pop();
      else if (!isAbs) parts.push('..');
      continue;
    }
    parts.push(seg);
  }
  return (isAbs ? '/' : '') + parts.join('/');
}

export function normalizePath(path: string): string {
  return lexicalNormalize(expandTilde(path));
}

/**
 * Convert a glob pattern to a RegExp. Anchored to the full string.
 */
export function globToRegex(glob: string): RegExp {
  const expanded = expandTilde(glob);
  let re = '^';
  let i = 0;
  while (i < expanded.length) {
    const c = expanded[i]!;
    if (c === '*') {
      if (expanded[i + 1] === '*') {
        // ** — match anything including slashes; consume optional trailing /
        re += '.*';
        i += 2;
        if (expanded[i] === '/') i++; // swallow `/` after ** so `a/**/b` matches `a/b`
      } else {
        re += '[^/]*';
        i++;
      }
    } else if (c === '?') {
      re += '[^/]';
      i++;
    } else if (c === '[') {
      // Pass character class through as-is; find matching ]
      const end = expanded.indexOf(']', i + 1);
      if (end === -1) {
        // No close — treat literally
        re += '\\[';
        i++;
      } else {
        re += expanded.slice(i, end + 1);
        i = end + 1;
      }
    } else if ('.+^$|()\\{}'.includes(c)) {
      re += '\\' + c;
      i++;
    } else {
      re += c;
      i++;
    }
  }
  re += '$';
  return new RegExp(re);
}

export function globMatch(path: string, pattern: string): boolean {
  return globToRegex(pattern).test(normalizePath(path));
}
