import {
  buildTempoCredential,
  parseMppChallenges,
  parseMppReceipt,
  tempoCandidate,
  type MppChallenge,
} from './mpp.js';
import type { FetchLike, PaymentCandidate, PayOutcome } from './types.js';
import {
  buildX402Payment,
  parseX402Receipt,
  parseX402Requirements,
  x402Candidate,
  type X402Requirement,
} from './x402.js';

/**
 * Protocol-agnostic 402 payment flow. The security-relevant property of this
 * module is that IT makes the HTTP requests: the challenge that determines
 * who gets paid and how much comes off the wire from the origin server over
 * TLS, is judged by the caller's `authorize` gate, and is then signed — the
 * MCP client (the model) only ever chose the URL. A doctored challenge can't
 * be injected through tool arguments because there is no argument that
 * carries one.
 */

export class PayError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PayError';
  }
}

/**
 * Wrapper the authorize gate uses to say "this candidate is not payable, but
 * you may try the next one". ONLY static policy denials qualify. A human
 * confirm that was denied, timed out, or whose transport failed must NOT be
 * wrapped: those propagate raw and end the purchase, otherwise a malicious
 * server could list an expensive option first and a cheap sub-threshold one
 * second, and a human tapping Deny would silently buy the second.
 */
export class CandidateRejected extends Error {
  override readonly cause: unknown;
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause));
    this.name = 'CandidateRejected';
    this.cause = cause;
  }
}

export interface PayRequest {
  url: string;
  method: string;
  body?: string;
  contentType?: string;
}

export interface PayDeps {
  fetchImpl: FetchLike;
  now: () => number;
  /**
   * Origin gate, consulted BEFORE the first request goes out. Without it,
   * sigil_pay would be a general-purpose HTTP deputy: a prompt-injected
   * agent could POST to any host (or to loopback services) and read the
   * response, entirely outside the payment allowlist. Throws to refuse.
   */
  authorizeOrigin: (origin: string) => Promise<void>;
  /**
   * Policy + confirm gate for a specific parsed candidate. Throws to refuse:
   * wrap the throw in CandidateRejected to allow falling through to the next
   * candidate, throw raw to abort the whole purchase.
   */
  authorize: (candidate: PaymentCandidate) => Promise<void>;
  /**
   * Called after a signed credential has been put on the wire but before the
   * outcome is known. The spend authorization has escaped at this point, so
   * it must be recorded even if the response never arrives.
   */
  onCredentialReleased?: (candidate: PaymentCandidate) => void;
  privateKey: Buffer | Uint8Array;
}

const BODY_PREVIEW_BYTES = 2048;
const MAX_BODY_BYTES = 256 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * Read at most MAX_BODY_BYTES, enforcing the cap while streaming rather than
 * after buffering. `res.text()` would let a hostile endpoint hand a
 * long-lived signing process an arbitrarily large body before we ever got to
 * truncate it.
 */
export async function readCapped(res: Response, maxBytes = MAX_BODY_BYTES): Promise<string> {
  const body = res.body;
  if (!body) return '';
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const remaining = maxBytes - total;
      if (value.length >= remaining) {
        chunks.push(value.subarray(0, remaining));
        total = maxBytes;
        break;
      }
      chunks.push(value);
      total += value.length;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c)), total).toString('utf8');
}

function preview(text: string): string {
  return text.length > BODY_PREVIEW_BYTES ? text.slice(0, BODY_PREVIEW_BYTES) + '…' : text;
}

function requestInit(req: PayRequest, extraHeaders: Record<string, string>): RequestInit {
  const headers: Record<string, string> = { ...extraHeaders };
  if (req.body !== undefined) {
    headers['content-type'] = req.contentType ?? 'application/json';
  }
  return {
    method: req.method,
    headers,
    ...(req.body !== undefined ? { body: req.body } : {}),
    // A redirect would detach the challenge from the origin the policy
    // judged. Refuse rather than follow.
    redirect: 'manual',
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  };
}

interface Payable {
  candidate: PaymentCandidate;
  build: () => { headerName: string; headerValue: string };
  kind: 'mpp' | 'x402';
}

/**
 * Fetch the resource; if it answers 402, extract every payable option (MPP
 * and x402), authorize one through the policy gate, sign, retry once, and
 * report the outcome. Non-402 responses pass through untouched.
 */
export async function pay(req: PayRequest, deps: PayDeps): Promise<PayOutcome> {
  const url = new URL(req.url);
  if (url.protocol !== 'https:' && url.hostname !== '127.0.0.1' && url.hostname !== 'localhost') {
    throw new PayError('payment challenges are only accepted over https');
  }
  const origin = url.origin;

  // Origin gate first: no bytes leave the machine until policy says this
  // host is payable. Otherwise the tool doubles as an SSRF primitive.
  await deps.authorizeOrigin(origin);

  const first = await deps.fetchImpl(req.url, requestInit(req, {}));
  const firstBody = await readCapped(first);
  if (first.status >= 300 && first.status < 400) {
    throw new PayError(`refusing to follow redirect (${first.status}) from ${origin}`);
  }
  if (first.status !== 402) {
    return {
      status: first.status,
      paid: false,
      settlement: 'none',
      bodyPreview: preview(firstBody),
    };
  }

  const nowMs = deps.now();
  const skips: string[] = [];
  const payables: Payable[] = [];

  // MPP challenges ride WWW-Authenticate. getSetCookie-style splitting is
  // not available for arbitrary headers, but undici folds repeats into a
  // comma-joined value, which the auth-param parser handles.
  const wwwAuth = first.headers.get('www-authenticate');
  const mppChallenges: MppChallenge[] = wwwAuth ? parseMppChallenges([wwwAuth]) : [];
  for (const ch of mppChallenges) {
    const judged = tempoCandidate(ch, origin);
    if ('skip' in judged) {
      skips.push(`mpp/${ch.method}: ${judged.skip}`);
      continue;
    }
    if (judged.candidate.expiresAtMs !== undefined && judged.candidate.expiresAtMs <= nowMs) {
      skips.push('mpp/tempo: challenge already expired');
      continue;
    }
    payables.push({
      candidate: judged.candidate,
      build: () => ({
        headerName: 'authorization',
        headerValue: buildTempoCredential(ch, deps.privateKey, deps.now()),
      }),
      kind: 'mpp',
    });
  }

  const x402Reqs: X402Requirement[] = parseX402Requirements(
    first.headers.get('payment-required'),
    firstBody,
  );
  for (const requirement of x402Reqs) {
    payables.push({
      candidate: x402Candidate(requirement, origin),
      build: () => {
        const p = buildX402Payment(requirement, deps.privateKey, deps.now());
        return { headerName: p.headerName, headerValue: p.headerValue };
      },
      kind: 'x402',
    });
  }

  if (payables.length === 0) {
    const detail = skips.length ? ` (skipped: ${skips.join('; ')})` : '';
    throw new PayError(`402 from ${origin} but no payable challenge found${detail}`);
  }

  // Server preference order; the first candidate the policy allows wins.
  // Only CandidateRejected (a static policy deny) falls through to the next
  // option — a confirm denial/timeout propagates immediately so a human's
  // "no" can never be routed around by a cheaper second candidate.
  let chosen: Payable | undefined;
  let lastDeny: unknown;
  for (const payable of payables) {
    try {
      await deps.authorize(payable.candidate);
      chosen = payable;
      break;
    } catch (err) {
      if (!(err instanceof CandidateRejected)) throw err;
      lastDeny = err.cause;
    }
  }
  if (!chosen) throw lastDeny;

  const { headerName, headerValue } = chosen.build();
  // From here the spend authorization is on the wire and may settle even if
  // we never see the response. Record that before awaiting.
  deps.onCredentialReleased?.(chosen.candidate);

  let second: Response;
  let secondBody: string;
  try {
    second = await deps.fetchImpl(req.url, requestInit(req, { [headerName]: headerValue }));
    secondBody = await readCapped(second);
  } catch (err) {
    // The credential is out there. The server may well have settled it, so
    // this is "unknown", not "unpaid" — retrying blind would double-spend.
    throw new PayError(
      `payment credential was sent to ${origin} but the response never arrived ` +
        `(${(err as Error).message}) — settlement is UNKNOWN, check the audit log before retrying`,
    );
  }

  const receipt =
    chosen.kind === 'mpp'
      ? parseMppReceipt(second.headers.get('payment-receipt'))
      : parseX402Receipt(
          second.headers.get('payment-response') ?? second.headers.get('x-payment-response'),
        );

  // 2xx only. A 3xx carries no settlement evidence, and 4xx/5xx after the
  // credential left is ambiguous rather than safe.
  const paid = second.status >= 200 && second.status < 300;
  const settlement: PayOutcome['settlement'] = paid
    ? 'settled'
    : second.status === 402
      ? 'rejected'
      : 'unknown';

  return {
    status: second.status,
    paid,
    settlement,
    candidate: chosen.candidate,
    ...(receipt !== undefined ? { receipt } : {}),
    bodyPreview: preview(secondBody),
  };
}
