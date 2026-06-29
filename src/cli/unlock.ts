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

  if (answered.length === 0) {
    // Nothing live answered. Whether the directory was empty or every socket
    // in it was stale (reaped this run), the actionable advice is the same:
    // there's no running sigil-mcp to talk to.
    return {
      message:
        `sigil-mcp is not running. Start a Claude Code session (which spawns it via your MCP config) and try again.`,
      code: 1,
    };
  }

  if (action === 'unlock') {
    const wrong = answered.find(
      (s) => s.response && isControlError(s.response) && s.response.code === 'WRONG_PASSPHRASE',
    );
    if (wrong) return { message: `sigil unlock: wrong passphrase`, code: 2 };

    // Unlocked = freshly unlocked (ok: true, carries authoritative portals) OR
    // already unlocked. A current sigil-mcp reports already-unlocked sessions
    // as ok: true too; the legacy ALREADY_UNLOCKED error is still accepted here
    // for forward-compat with an older server process. Anything else is a
    // per-session failure we surface without sinking the sessions that worked.
    const portalBearing: SessionResult[] = []; // ok: true — knows its portals
    const unlockedNoInfo: SessionResult[] = []; // legacy ALREADY_UNLOCKED — portals unknown
    const failed: SessionResult[] = [];
    for (const s of answered) {
      const r = s.response!;
      if (!isControlError(r)) portalBearing.push(s);
      else if (r.code === 'ALREADY_UNLOCKED') unlockedNoInfo.push(s);
      else failed.push(s);
    }
    const unlockedCount = portalBearing.length + unlockedNoInfo.length;

    if (unlockedCount === 0) {
      const first = failed[0]?.response;
      const detail = first && isControlError(first) ? `${first.error} (${first.code})` : 'unknown error';
      return { message: `sigil unlock: ${detail}`, code: 1 };
    }

    const portals = portalsOf(portalBearing);
    const sessionWord = unlockedCount === 1 ? 'session' : 'sessions';
    let portalPart: string;
    if (portals.length > 0) {
      portalPart = `: ${portals.join(', ')}`;
    } else if (portalBearing.length > 0) {
      // At least one session authoritatively reported its (empty) portal set.
      portalPart = ' (no portals on disk yet — add one with "sigil portal add")';
    } else {
      // Only legacy already-unlocked responses, which don't echo portals.
      portalPart = '';
    }
    let message = `unlocked ${unlockedCount} ${sessionWord}${portalPart}`;
    if (failed.length > 0) message += ` — ${failed.length} session(s) failed to unlock`;
    return { message, code: 0 };
  }

  // lock: every answered session is now locked.
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
