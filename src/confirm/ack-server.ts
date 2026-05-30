import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';

/**
 * Local HTTP listener that resolves OOB-confirm clicks. One per sigil-mcp
 * process, bound to 127.0.0.1 on a random port assigned by the kernel.
 *
 * Wire shape (intentionally trivial — every transport hands the human these
 * two URLs, and tapping either resolves the gate):
 *
 *   POST /approve?t=<token>   → 200 if token matches a pending request
 *   POST /deny?t=<token>      → 200 if token matches a pending request
 *   GET  variants are accepted too, so a stock email/SMS link that's
 *     followed by a phone browser also works (some clients refuse to POST
 *     from a tap).
 *
 * Token semantics:
 *   - 32-byte cryptographically random, base64url-encoded, kept in process
 *     memory only.
 *   - Bound to one pending request — a token issued for sign-request A
 *     cannot approve sign-request B.
 *   - Single-use: cleared the moment we resolve. A replayed approval click
 *     after timeout gets a 410 Gone, not a silent re-approve.
 *
 * No TLS: the listener is on 127.0.0.1. A local attacker who can already
 * make HTTP requests from this machine could also read the process's
 * memory, so TLS here would be theatre.
 */

/** Outcome the ack server hands back to the gate. */
export type AckOutcome = 'approve' | 'deny';

interface Pending {
  resolve: (outcome: AckOutcome) => void;
  /** Tracked so the server can synthesize a "cancelled" reply if the gate
   *  abandons (timeout fires) before the human clicks. */
  cancelled: boolean;
}

export interface AckServer {
  /** Hostname-and-port base, e.g. "http://127.0.0.1:42424". No trailing slash. */
  readonly baseUrl: string;
  /**
   * Mint a single-use token bound to a pending request, and return the
   * approve/deny URLs the human will click. The returned Promise resolves
   * when the human clicks (or the caller calls `cancel(token)` — e.g. on
   * timeout).
   */
  pending(): {
    token: string;
    approveUrl: string;
    denyUrl: string;
    settled: Promise<AckOutcome>;
  };
  /** Drop a pending token without resolving (e.g. the gate timed out).
   *  Subsequent clicks for that token get 410 Gone. */
  cancel(token: string): void;
  close(): Promise<void>;
}

/**
 * Start a local ack server on 127.0.0.1 and resolve when it's listening.
 * The chosen port is observable via `baseUrl`.
 */
export function startAckServer(): Promise<AckServer> {
  const pending = new Map<string, Pending>();

  const handle = (req: IncomingMessage, res: ServerResponse): void => {
    // Strip query, route on path. We accept GET and POST equivalently — the
    // ntfy "http,Approve,..." button POSTs, but a fallback SMS link a human
    // taps would be a GET.
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    let outcome: AckOutcome;
    if (url.pathname === '/approve') outcome = 'approve';
    else if (url.pathname === '/deny') outcome = 'deny';
    else {
      reply(res, 404, 'unknown path\n');
      return;
    }
    const token = url.searchParams.get('t');
    if (!token) {
      reply(res, 400, 'missing token\n');
      return;
    }
    const entry = pending.get(token);
    if (!entry) {
      // Either never existed, or already settled, or cancelled by timeout.
      reply(res, 410, 'token expired or already used\n');
      return;
    }
    pending.delete(token);
    entry.resolve(outcome);
    reply(
      res,
      200,
      outcome === 'approve'
        ? 'approved — you can close this tab\n'
        : 'denied — you can close this tab\n',
    );
  };

  const server: Server = createServer(handle);

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      const addr = server.address() as AddressInfo;
      const baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve(makeApi(server, baseUrl, pending));
    });
  });
}

function makeApi(server: Server, baseUrl: string, pending: Map<string, Pending>): AckServer {
  return {
    baseUrl,
    pending() {
      const token = randomBytes(32).toString('base64url');
      let resolveFn!: (outcome: AckOutcome) => void;
      const settled = new Promise<AckOutcome>((res) => {
        resolveFn = res;
      });
      pending.set(token, { resolve: resolveFn, cancelled: false });
      const approveUrl = `${baseUrl}/approve?t=${token}`;
      const denyUrl = `${baseUrl}/deny?t=${token}`;
      return { token, approveUrl, denyUrl, settled };
    },
    cancel(token) {
      const entry = pending.get(token);
      if (!entry) return;
      entry.cancelled = true;
      pending.delete(token);
      // Note: we deliberately do not resolve `settled`. The gate owns the
      // timeout race and will already have moved on by the time it calls
      // cancel(). A settled-after-timeout resolution would cause the gate
      // to double-decide.
    },
    close() {
      return new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}

function reply(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
}
