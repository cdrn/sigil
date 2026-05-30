/**
 * Out-of-band confirmation: when a sign request crosses the policy's confirm
 * threshold, sigil pushes a notification to a channel the human controls
 * (not the agent) and waits for an explicit human ack before signing.
 *
 * The transport interface is intentionally tiny. The shared ack mechanism
 * (a localhost HTTP listener that resolves clicks) lives in ack-server.ts
 * and isn't a per-transport concern — every transport just emits a
 * notification carrying the two URLs.
 */

/**
 * A pending sign request that needs an out-of-band human ack. The transport
 * is told about it via `send`; the human resolves it by hitting one of the
 * two URLs from a device the agent process can't reach.
 *
 * `token` is opaque to the transport — it's already baked into approveUrl
 * and denyUrl. The transport may surface it (e.g. for logging) but should
 * not transmit it separately, since the URLs are the only thing the ack
 * server matches against.
 */
export interface ConfirmRequest {
  /** Portal handle, e.g. "evm:executor". Used as the notification title. */
  portal: string;
  /** One-line description of what's about to be signed. Comes from the policy
   *  evaluator. Safe to put in the push body — does not include key material. */
  summary: string;
  /** Full URL the human clicks (or taps) to approve. Hits the ack server on
   *  127.0.0.1; the token in the query string is single-use + request-bound. */
  approveUrl: string;
  /** Same shape, deny path. */
  denyUrl: string;
  /** Token (also embedded in the URLs above). Exposed for transports that
   *  want to log/correlate without parsing URLs. */
  token: string;
}

/**
 * Implementation contract. Transports just push the prompt — the ack
 * round-trips back through the local HTTP server, not through the transport.
 *
 * Implementations should reject with a thrown Error on transport failure
 * (network down, push provider 5xx, etc). The gate treats any throw as a
 * push failure and surfaces it as a deny (fail-closed): we'd rather decline
 * the sign than silently let it through because the notification didn't
 * reach the human's phone.
 */
export interface ConfirmTransport {
  /** Short identifier — used in audit log + startup banner. */
  readonly name: string;
  send(req: ConfirmRequest): Promise<void>;
}

/**
 * Outcome of a confirm round-trip. The gate returns one of these; the sign
 * method then either proceeds (approved) or throws RPC_POLICY_DENIED with
 * the appropriate reason (denied | timeout | transport_error).
 */
export type ConfirmDecision =
  | { kind: 'approved' }
  | { kind: 'denied' }
  | { kind: 'timeout' }
  | { kind: 'transport_error'; message: string };
