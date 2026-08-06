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
   * Policy + confirm gate, supplied by the daemon layer. Throws to refuse
   * (the throw propagates unchanged, so RPC_POLICY_DENIED semantics and the
   * audit trail stay where they live today). Called once per attempted
   * candidate, in server-preference order, until one is authorized.
   */
  authorize: (candidate: PaymentCandidate) => Promise<void>;
  privateKey: Buffer | Uint8Array;
}

const BODY_PREVIEW_BYTES = 2048;
const MAX_BODY_BYTES = 256 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;

async function readBody(res: Response): Promise<string> {
  const text = await res.text();
  return text.length > MAX_BODY_BYTES ? text.slice(0, MAX_BODY_BYTES) : text;
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

  const first = await deps.fetchImpl(req.url, requestInit(req, {}));
  const firstBody = await readBody(first);
  if (first.status >= 300 && first.status < 400) {
    throw new PayError(`refusing to follow redirect (${first.status}) from ${origin}`);
  }
  if (first.status !== 402) {
    return { status: first.status, paid: false, bodyPreview: preview(firstBody) };
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
  // authorize() throws on deny — only the LAST deny propagates if every
  // candidate is refused, which is the specific error the user can act on.
  let chosen: Payable | undefined;
  let lastDeny: unknown;
  for (const payable of payables) {
    try {
      await deps.authorize(payable.candidate);
      chosen = payable;
      break;
    } catch (err) {
      lastDeny = err;
    }
  }
  if (!chosen) throw lastDeny;

  const { headerName, headerValue } = chosen.build();
  const second = await deps.fetchImpl(req.url, requestInit(req, { [headerName]: headerValue }));
  const secondBody = await readBody(second);

  const receipt =
    chosen.kind === 'mpp'
      ? parseMppReceipt(second.headers.get('payment-receipt'))
      : parseX402Receipt(
          second.headers.get('payment-response') ?? second.headers.get('x-payment-response'),
        );

  return {
    status: second.status,
    paid: second.status < 400,
    candidate: chosen.candidate,
    ...(receipt !== undefined ? { receipt } : {}),
    bodyPreview: preview(secondBody),
  };
}
