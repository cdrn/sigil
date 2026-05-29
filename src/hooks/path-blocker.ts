import { basename } from 'node:path';
import { globMatch, normalizePath } from './glob.js';

/**
 * Built-in patterns we always block. These are not user-configurable; they
 * represent paths where a key would conventionally live and that the agent
 * should never read.
 */
export const DEFAULT_PATH_PATTERNS: readonly string[] = Object.freeze([
  // sigil's own state
  '**/.sigil/**',
  // key-bearing file extensions (specific enough to have a low false-positive rate)
  '**/*.key',
  '**/*.keystore',
  '**/*.jks',
  '**/*.p12',
  // SSH private key conventions
  '**/.ssh/id_*',
  '**/.ssh/*_rsa',
  '**/.ssh/*_ed25519',
  '**/.ssh/*_ecdsa',
  // GPG / pass(1) storage
  '**/.gnupg/**',
  '**/.password-store/**',
]);

export interface BlockDecision {
  blocked: boolean;
  /** The pattern that matched, useful for surfacing in the error to the agent. */
  matchedPattern?: string;
}

export interface BlockerOpts {
  /** Extra glob patterns to block, in addition to the built-ins. */
  extraPatterns?: readonly string[];
}

/**
 * Decide whether to block a path read. Both the resolved absolute path AND
 * the raw user-supplied path are checked, because attackers (or confused
 * agents) may pass paths with `..` or symlinks that resolve to a blocked
 * location while looking innocent.
 *
 * Note: this does NOT resolve symlinks itself. Symlink resolution is best
 * left to the caller (who has filesystem access). For sigil's hook context,
 * the agent already has filesystem access and would do the symlink read
 * before our hook fires; the meaningful protection is preventing direct
 * reads through obvious paths.
 */
export function isBlockedPath(path: string, opts: BlockerOpts = {}): BlockDecision {
  const patterns = [...DEFAULT_PATH_PATTERNS, ...(opts.extraPatterns ?? [])];
  const normalized = normalizePath(path);
  const base = basename(normalized);

  for (const pattern of patterns) {
    if (globMatch(normalized, pattern)) {
      return { blocked: true, matchedPattern: pattern };
    }
    // Also test the basename so a pattern like `**/.env` catches relative `.env`.
    if (globMatch(base, pattern.replace(/^\*\*\//, ''))) {
      return { blocked: true, matchedPattern: pattern };
    }
  }
  return { blocked: false };
}
