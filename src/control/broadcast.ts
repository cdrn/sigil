import { existsSync, readdirSync, statSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { ControlClientError, controlRequest } from './client.js';
import type { ControlRequest, ControlResponse } from './protocol.js';

/**
 * Fan-out client for the per-session control sockets.
 *
 * Each running sigil-mcp binds `<controlDir>/<pid>.sock`. The CLI broadcasts a
 * single control request to every one of them so `sigil unlock` (etc.) reaches
 * all live Claude Code sessions at once, not just whichever process happened to
 * start first. Sockets left behind by hard-killed processes are detected on
 * connect (refused / missing) and unlinked, so the directory self-heals.
 */

const SOCK_RE = /^(\d+)\.sock$/;

export interface SessionSocket {
  /** PID parsed from the socket filename. */
  pid: number;
  socketPath: string;
}

export interface SessionResult extends SessionSocket {
  /** Server response, or null if the socket was unreachable. */
  response: ControlResponse | null;
  /** Set when the socket couldn't be reached. */
  clientError?: ControlClientError;
  /** True when the socket was stale (refused / missing) and got unlinked. */
  reaped: boolean;
}

/**
 * List the `<pid>.sock` entries in `controlDir`, sorted by PID for stable
 * output. Returns `[]` if the directory is missing. Ignores anything that
 * isn't a `<digits>.sock` name.
 */
export function listSessionSockets(controlDir: string): SessionSocket[] {
  if (!existsSync(controlDir)) return [];
  try {
    if (!statSync(controlDir).isDirectory()) return [];
  } catch {
    return [];
  }
  const out: SessionSocket[] = [];
  for (const name of readdirSync(controlDir)) {
    const m = SOCK_RE.exec(name);
    if (!m) continue;
    out.push({ pid: Number(m[1]), socketPath: join(controlDir, name) });
  }
  out.sort((a, b) => a.pid - b.pid);
  return out;
}

/**
 * Send `request` to every live session socket in parallel and collect the
 * per-session outcomes. Sockets that refuse the connection or have vanished
 * are treated as stale: they're unlinked and reported with `reaped: true`.
 * Never throws — transport failures land in each result's `clientError`.
 */
export async function broadcast(
  controlDir: string,
  request: ControlRequest,
  timeoutMs?: number,
): Promise<SessionResult[]> {
  const sockets = listSessionSockets(controlDir);
  return Promise.all(
    sockets.map((s) => sendOne(s, request, timeoutMs)),
  );
}

async function sendOne(
  s: SessionSocket,
  request: ControlRequest,
  timeoutMs?: number,
): Promise<SessionResult> {
  try {
    const response = await controlRequest({
      socketPath: s.socketPath,
      request,
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    });
    return { ...s, response, reaped: false };
  } catch (err) {
    if (!(err instanceof ControlClientError)) throw err;
    // SERVER_DOWN means the file is gone (ENOENT) or nothing is listening
    // (ECONNREFUSED) — the owning process died without cleaning up. Reap it.
    // TIMEOUT / BAD_RESPONSE / NO_RESPONSE could be a live-but-busy server, so
    // leave those sockets in place.
    let reaped = false;
    if (err.code === 'SERVER_DOWN') {
      try { unlinkSync(s.socketPath); reaped = true; } catch { /* raced another reaper */ }
    }
    return { ...s, response: null, clientError: err, reaped };
  }
}
