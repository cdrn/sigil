import type { AckServer } from './ack-server.js';
import type { ConfirmDecision, ConfirmTransport } from './types.js';

export interface ConfirmGateOpts {
  /** Pluggable transport — ntfy in production; mock in tests. */
  transport: ConfirmTransport;
  /** Shared local ack server (one per process). */
  ackServer: AckServer;
  /** Per-portal override comes from policy; this is the cross-portal default.
   *  Configurable so tests can use ms-scale timeouts without slowing the suite. */
  timeoutMs?: number;
}

/**
 * The OOB confirm gate. Mints a token, pushes the prompt over the transport,
 * races the human's click against a timeout, returns the decision.
 *
 * Failure modes (all map to a final ConfirmDecision):
 *   - transport.send() throws       → `transport_error` (gate doesn't fall
 *                                      back to silently allowing the sign;
 *                                      the caller maps this to RPC_POLICY_DENIED)
 *   - human clicks Approve / Deny   → `approved` / `denied`
 *   - clock runs out                → `timeout` (cancels the token so a late
 *                                      click returns 410 Gone instead of being
 *                                      silently absorbed)
 *
 * Concurrent requests are isolated: each call mints its own token, the ack
 * server matches by token, so two pending confirms cannot cross-resolve.
 */
export class ConfirmGate {
  readonly #transport: ConfirmTransport;
  readonly #ackServer: AckServer;
  readonly #timeoutMs: number;

  constructor(opts: ConfirmGateOpts) {
    this.#transport = opts.transport;
    this.#ackServer = opts.ackServer;
    this.#timeoutMs = opts.timeoutMs ?? 60_000;
  }

  /** Transport name — used for audit log + startup banner. */
  get transportName(): string {
    return this.#transport.name;
  }

  async request(input: { portal: string; summary: string }): Promise<ConfirmDecision> {
    const { token, approveUrl, denyUrl, settled } = this.#ackServer.pending();
    try {
      await this.#transport.send({
        portal: input.portal,
        summary: input.summary,
        approveUrl,
        denyUrl,
        token,
      });
    } catch (err) {
      this.#ackServer.cancel(token);
      return { kind: 'transport_error', message: (err as Error).message };
    }

    // Race the click against the timeout. We use a unique sentinel rather
    // than null so that an Outcome of falsy value (no such thing today, but
    // future-proofing) doesn't get misread as a timeout.
    const TIMEOUT = Symbol('confirm-timeout');
    let timer: NodeJS.Timeout | undefined;
    const timeoutP = new Promise<typeof TIMEOUT>((resolve) => {
      timer = setTimeout(() => resolve(TIMEOUT), this.#timeoutMs);
      // Don't keep the event loop alive just for the timeout — sigil-mcp
      // exits when stdin closes, and a hanging timeout would prevent that.
      timer.unref?.();
    });
    const winner = await Promise.race([settled, timeoutP]);
    if (timer) clearTimeout(timer);

    if (winner === TIMEOUT) {
      this.#ackServer.cancel(token);
      return { kind: 'timeout' };
    }
    return winner === 'approve' ? { kind: 'approved' } : { kind: 'denied' };
  }
}
