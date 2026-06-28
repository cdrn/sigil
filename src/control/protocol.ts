/**
 * Wire protocol for the sigil-mcp control socket.
 *
 * One NDJSON request per connection, one NDJSON response, then the server
 * half-closes. Each session's socket lives at `~/.sigil/control/<pid>.sock`
 * (0600); the CLI fans requests out across every socket in that directory.
 *
 * Methods:
 *   - unlock: load keyfiles from disk into the running MCP server's
 *     HandleTable. Passphrase is shipped as base64 because raw bytes
 *     don't survive JSON's UTF-8 round-trip cleanly. Server decodes
 *     into a Buffer + zeroizes after use.
 *   - lock: zeroize the HandleTable. Re-lockable; a later unlock works.
 *   - status: probe — returns PID + unlocked flag + portal count.
 *
 * Error responses always carry a machine-readable `code` so the CLI can
 * branch on it without parsing the message.
 */

export const CONTROL_SOCKET_VERSION = 1;

export type ControlRequest =
  | { method: 'unlock'; passphraseB64: string }
  | { method: 'lock' }
  | { method: 'status' };

export type ControlResponse =
  | ControlSuccess
  | ControlError;

export interface ControlSuccess {
  ok: true;
  /** Server protocol version — clients should verify this matches. */
  version: number;
  /** Process ID of the running sigil-mcp. */
  pid: number;
  /** Whether the HandleTable is currently unlocked. */
  unlocked: boolean;
  /** Currently loaded portals (empty when locked, or when zero on disk). */
  portals: PortalSummary[];
}

export interface PortalSummary {
  handle: string;
  kind: 'evm';
  address: string;
}

export interface ControlError {
  ok: false;
  /** Stable error code. */
  code: ControlErrorCode;
  /** Human-readable message. */
  error: string;
}

export type ControlErrorCode =
  | 'INVALID_REQUEST'
  | 'UNKNOWN_METHOD'
  | 'ALREADY_UNLOCKED'
  | 'WRONG_PASSPHRASE'
  | 'KEYS_LOAD_FAILED'
  | 'INTERNAL';

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

export function parseControlRequest(line: string): ControlRequest | ControlError {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return invalid('request is not valid JSON');
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return invalid('request must be a JSON object');
  }
  const obj = raw as Record<string, unknown>;
  const method = obj['method'];
  if (typeof method !== 'string') {
    return invalid('request.method must be a string');
  }
  if (method === 'lock' || method === 'status') {
    return { method };
  }
  if (method === 'unlock') {
    const p = obj['passphraseB64'];
    if (typeof p !== 'string') {
      return invalid('unlock.passphraseB64 must be a string');
    }
    return { method: 'unlock', passphraseB64: p };
  }
  return {
    ok: false,
    code: 'UNKNOWN_METHOD',
    error: `unknown control method "${method}"`,
  };
}

export function isControlError(resp: ControlResponse): resp is ControlError {
  return resp.ok === false;
}

function invalid(message: string): ControlError {
  return { ok: false, code: 'INVALID_REQUEST', error: message };
}
