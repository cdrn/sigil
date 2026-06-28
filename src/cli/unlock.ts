import {
  broadcast,
  isControlError,
  type SessionResult,
} from '../control/index.js';
import type { SigilPaths } from './paths.js';

export interface UnlockOpts {
  paths: SigilPaths;
  /** Buffer holding the passphrase. Caller is responsible for zeroizing it. */
  passphrase: Buffer;
  /** Optional connect timeout in ms (default 5000). */
  timeoutMs?: number;
}

/**
 * Push an unlock to every running sigil-mcp session. Encodes the passphrase as
 * base64 for transport; does NOT clear the caller's buffer (the caller owns
 * lifetime). Returns the per-session outcomes — aggregate them with
 * {@link formatResult}.
 */
export async function unlock(opts: UnlockOpts): Promise<SessionResult[]> {
  const passphraseB64 = opts.passphrase.toString('base64');
  return broadcast(opts.paths.controlDir, { method: 'unlock', passphraseB64 }, opts.timeoutMs);
}

export interface LockOpts {
  paths: SigilPaths;
  timeoutMs?: number;
}

export async function lock(opts: LockOpts): Promise<SessionResult[]> {
  return broadcast(opts.paths.controlDir, { method: 'lock' }, opts.timeoutMs);
}

/**
 * Aggregate per-session outcomes into a single human-readable line + exit code.
 *
 * Sessions that were reaped (stale sockets from dead processes) are ignored —
 * they don't count as reachable. If nothing was reachable, that's "not
 * running". A wrong passphrase fails uniformly (all sessions share the same
 * keyfiles), so any WRONG_PASSPHRASE short-circuits to exit 2. Otherwise we
 * report how many sessions ended up in the desired state, treating
 * ALREADY_UNLOCKED as a successful unlock.
 */
export function formatResult(action: 'unlock' | 'lock', sessions: SessionResult[]): {
  message: string;
  code: number;
} {
  // A session is "reachable" if it answered at all (success or server-side
  // error). Reaped / unreachable sockets don't count.
  const answered = sessions.filter((s) => s.response !== null);
  const unreachable = sessions.filter((s) => s.response === null);

  if (answered.length === 0) {
    // Nothing live to talk to. Distinguish "no sessions at all" from "every
    // session we found was unreachable" only in the message; both exit 1.
    if (sessions.length === 0) {
      return {
        message:
          `sigil-mcp is not running. Start a Claude Code session (which spawns it via your MCP config) and try again.`,
        code: 1,
      };
    }
    const detail = unreachable[0]?.clientError?.message ?? 'no response';
    return { message: `sigil ${action}: no reachable sessions (${detail})`, code: 1 };
  }

  if (action === 'unlock') {
    const wrong = answered.find(
      (s) => s.response && isControlError(s.response) && s.response.code === 'WRONG_PASSPHRASE',
    );
    if (wrong) return { message: `sigil unlock: wrong passphrase`, code: 2 };

    // Unlocked = freshly unlocked OR already unlocked. Anything else is a
    // per-session failure (e.g. KEYS_LOAD_FAILED) we surface but don't let
    // sink the whole command if other sessions succeeded.
    const unlocked: SessionResult[] = [];
    const failed: SessionResult[] = [];
    for (const s of answered) {
      const r = s.response!;
      if (!isControlError(r)) unlocked.push(s);
      else if (r.code === 'ALREADY_UNLOCKED') unlocked.push(s);
      else failed.push(s);
    }

    if (unlocked.length === 0) {
      const first = failed[0]?.response;
      const detail = first && isControlError(first) ? `${first.error} (${first.code})` : 'unknown error';
      return { message: `sigil unlock: ${detail}`, code: 1 };
    }

    const portals = portalsOf(unlocked);
    const sessionWord = unlocked.length === 1 ? 'session' : 'sessions';
    const portalPart = portals.length === 0
      ? ' (no portals on disk yet — add one with "sigil portal add")'
      : `: ${portals.join(', ')}`;
    let message = `unlocked ${unlocked.length} ${sessionWord}${portalPart}`;
    if (failed.length > 0) message += ` — ${failed.length} session(s) failed to load keys`;
    return { message, code: 0 };
  }

  // lock: never returns ALREADY_*/WRONG; every answered session is now locked.
  const n = answered.length;
  return { message: `locked ${n} session${n === 1 ? '' : 's'}`, code: 0 };
}

/** Distinct portal handles across the given sessions, in first-seen order. */
function portalsOf(sessions: SessionResult[]): string[] {
  const seen = new Set<string>();
  for (const s of sessions) {
    const r = s.response;
    if (r && !isControlError(r)) {
      for (const p of r.portals) seen.add(p.handle);
    }
  }
  return [...seen];
}
