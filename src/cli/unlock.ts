import {
  ControlClientError,
  controlRequest,
  isControlError,
  type ControlResponse,
} from '../control/index.js';
import type { SigilPaths } from './paths.js';

export interface UnlockOpts {
  paths: SigilPaths;
  /** Buffer holding the passphrase. Caller is responsible for zeroizing it. */
  passphrase: Buffer;
  /** Optional connect timeout in ms (default 5000). */
  timeoutMs?: number;
}

export interface UnlockResult {
  /** Server-side response, or null if the server is unreachable. */
  response: ControlResponse | null;
  /** Set when the control socket couldn't be reached. */
  clientError?: ControlClientError;
}

/**
 * Send an unlock request to the running sigil-mcp. Encodes the passphrase as
 * base64 for transport; does NOT clear the caller's buffer (the caller owns
 * lifetime). Returns the parsed response, or a client error if the server
 * was unreachable.
 */
export async function unlock(opts: UnlockOpts): Promise<UnlockResult> {
  const passphraseB64 = opts.passphrase.toString('base64');
  try {
    const response = await controlRequest({
      socketPath: opts.paths.controlSocket,
      request: { method: 'unlock', passphraseB64 },
      ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    });
    return { response };
  } catch (err) {
    if (err instanceof ControlClientError) return { response: null, clientError: err };
    throw err;
  }
}

export interface LockOpts {
  paths: SigilPaths;
  timeoutMs?: number;
}

export async function lock(opts: LockOpts): Promise<UnlockResult> {
  try {
    const response = await controlRequest({
      socketPath: opts.paths.controlSocket,
      request: { method: 'lock' },
      ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
    });
    return { response };
  } catch (err) {
    if (err instanceof ControlClientError) return { response: null, clientError: err };
    throw err;
  }
}

/**
 * Format a result for human-readable CLI output. Returns the message and the
 * exit code the CLI should use.
 */
export function formatResult(action: 'unlock' | 'lock', result: UnlockResult): {
  message: string;
  code: number;
} {
  if (result.clientError) {
    if (result.clientError.code === 'SERVER_DOWN') {
      return {
        message:
          `sigil-mcp is not running. Start a Claude Code session (which spawns it via your MCP config) and try again.`,
        code: 1,
      };
    }
    return { message: `sigil ${action}: ${result.clientError.message}`, code: 1 };
  }
  const resp = result.response!;
  if (isControlError(resp)) {
    if (resp.code === 'WRONG_PASSPHRASE') {
      return { message: `sigil ${action}: wrong passphrase`, code: 2 };
    }
    if (resp.code === 'ALREADY_UNLOCKED') {
      return {
        message: `sigil ${action}: already unlocked; run "sigil lock" first if you want to re-unlock`,
        code: 1,
      };
    }
    return { message: `sigil ${action}: ${resp.error} (${resp.code})`, code: 1 };
  }
  if (action === 'unlock') {
    const n = resp.portals.length;
    return {
      message: n === 0
        ? 'unlocked (no portals on disk yet — add one with "sigil portal add")'
        : `unlocked ${n} portal${n === 1 ? '' : 's'}: ${resp.portals.map((p) => p.handle).join(', ')}`,
      code: 0,
    };
  }
  return { message: 'locked', code: 0 };
}
