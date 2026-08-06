import { addressFromPrivateKey } from '../eth/address.js';
import { keccak256 } from '../eth/keccak.js';
import type { Hex } from '../eth/sign-tx.js';
import { parsePaymentChallenges } from './authparam.js';
import {
  encodeTransferWithMemo,
  EXPIRING_NONCE_KEY,
  randomValidAfter,
  signTempoForFeePayer,
  type TempoChargeTx,
} from './tempo.js';
import type { PaymentCandidate, PaymentReceipt } from './types.js';

/**
 * MPP (Machine Payments Protocol) client for the tempo method, charge intent,
 * pull mode. draft-httpauth-payment-00 + draft-tempo-charge-00.
 *
 * Supported deliberately narrowly:
 *   - method="tempo", intent="charge", non-zero amount
 *   - pull mode (we sign, the server broadcasts — no RPC dependency)
 *   - fee sponsorship (feePayer=true) or not; splits and server-supplied
 *     memos with the wrong width are rejected, not guessed at.
 */

const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const DEC_RE = /^[0-9]+$/;

export const TEMPO_DEFAULT_CHAIN_ID = 42431;
/** Generous fixed budget: TIP-20 transfer + expiring-nonce bookkeeping. */
const GAS_LIMIT = 120_000n;
const MAX_PRIORITY_FEE = 1_000_000_000n; // 1 gwei
/**
 * Static cap in lieu of an RPC fee estimate (sigil deliberately has no chain
 * reader). Tempo Moderato's base fee floats around the 5-15 gwei range; the
 * fee payer only spends the actual base fee, so a high cap costs nothing,
 * while a cap below base fee makes the sponsored broadcast fail. Sponsor
 * policies cap at 100 gwei; stay well under.
 */
const MAX_FEE = 30_000_000_000n; // 30 gwei
/** Sign-window seconds; mirrors the reference client's expiring-nonce cap. */
const MAX_EXPIRY_SECS = 25;

export interface MppChallenge {
  id: string;
  realm: string;
  method: string;
  intent: string;
  /** base64url-encoded request JSON, exactly as it appeared on the wire. */
  requestB64: string;
  request: MppChargeRequest;
  expires?: string;
  description?: string;
  opaque?: string;
  digest?: string;
}

export interface MppChargeRequest {
  amount: string;
  currency: string;
  recipient?: string;
  description?: string;
  externalId?: string;
  methodDetails?: {
    chainId?: number;
    feePayer?: boolean;
    memo?: string;
    splits?: unknown[];
    supportedModes?: string[];
  };
}

/**
 * MPP attribution memo (bytes32) for transferWithMemo. Servers verify the
 * challenge binding, so this is load-bearing, not telemetry:
 *
 *   [0..3]   keccak256("mpp")[0..3]     — on-chain MPP tag
 *   [4]      0x01                       — memo version
 *   [5..14]  keccak256(realm)[0..9]     — server fingerprint
 *   [15..24] zero                       — anonymous client
 *   [25..31] keccak256(challengeId)[0..6] — challenge binding
 */
export function attributionMemo(challengeId: string, realm: string): Hex {
  const memo = Buffer.alloc(32);
  keccak256(Buffer.from('mpp', 'utf8')).copy(memo, 0, 0, 4);
  memo[4] = 0x01;
  keccak256(Buffer.from(realm, 'utf8')).copy(memo, 5, 0, 10);
  keccak256(Buffer.from(challengeId, 'utf8')).copy(memo, 25, 0, 7);
  return ('0x' + memo.toString('hex')) as Hex;
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

function b64urlEncode(b: Buffer): string {
  return b.toString('base64url');
}

/**
 * Extract MPP challenges from WWW-Authenticate header values. Challenges that
 * fail structural validation are dropped (another challenge in the response
 * may still be payable); nothing here throws on malformed server input.
 */
export function parseMppChallenges(headerValues: readonly string[]): MppChallenge[] {
  const out: MppChallenge[] = [];
  for (const { params } of parsePaymentChallenges(headerValues)) {
    const id = params['id'];
    const realm = params['realm'];
    const method = params['method'];
    const intent = params['intent'];
    const requestB64 = params['request'];
    if (!id || !realm || !method || !intent || !requestB64) continue;
    let request: unknown;
    try {
      request = JSON.parse(b64urlDecode(requestB64).toString('utf8'));
    } catch {
      continue;
    }
    if (typeof request !== 'object' || request === null || Array.isArray(request)) continue;
    const req = request as MppChargeRequest;
    out.push({
      id,
      realm,
      method,
      intent,
      requestB64,
      request: req,
      ...(params['expires'] !== undefined ? { expires: params['expires'] } : {}),
      ...(params['description'] !== undefined ? { description: params['description'] } : {}),
      ...(params['opaque'] !== undefined ? { opaque: params['opaque'] } : {}),
      ...(params['digest'] !== undefined ? { digest: params['digest'] } : {}),
    });
  }
  return out;
}

/**
 * Judge whether we can pay a challenge with the tempo pull path, and if so
 * normalize it into a PaymentCandidate for the policy engine. Returns a
 * skip reason string otherwise (surfaced in errors so the caller can see why
 * nothing matched).
 */
export function tempoCandidate(
  ch: MppChallenge,
  origin: string,
): { candidate: PaymentCandidate } | { skip: string } {
  if (ch.method !== 'tempo') return { skip: `method "${ch.method}" unsupported` };
  if (ch.intent !== 'charge') return { skip: `intent "${ch.intent}" unsupported` };
  const req = ch.request;
  if (typeof req.amount !== 'string' || !DEC_RE.test(req.amount)) {
    return { skip: 'malformed amount' };
  }
  const amount = BigInt(req.amount);
  if (amount === 0n) return { skip: 'zero-amount proof charges unsupported' };
  if (typeof req.currency !== 'string' || !ADDR_RE.test(req.currency)) {
    return { skip: 'currency is not a TIP-20 token address' };
  }
  if (typeof req.recipient !== 'string' || !ADDR_RE.test(req.recipient)) {
    return { skip: 'missing or malformed recipient' };
  }
  const md = req.methodDetails ?? {};
  if (md.splits && md.splits.length > 0) return { skip: 'split payments unsupported' };
  if (md.supportedModes && !md.supportedModes.includes('pull')) {
    return { skip: 'server does not support pull mode' };
  }
  if (md.memo !== undefined && !/^0x[0-9a-fA-F]{64}$/.test(md.memo)) {
    return { skip: 'malformed memo (must be bytes32)' };
  }
  const chainId = md.chainId ?? TEMPO_DEFAULT_CHAIN_ID;
  if (!Number.isInteger(chainId) || chainId <= 0) return { skip: 'malformed chainId' };
  let expiresAtMs: number | undefined;
  if (ch.expires !== undefined) {
    expiresAtMs = Date.parse(ch.expires);
    if (Number.isNaN(expiresAtMs)) return { skip: 'malformed expires' };
  }
  return {
    candidate: {
      protocol: 'mpp',
      origin,
      method: 'tempo',
      chainId,
      currency: req.currency.toLowerCase(),
      amount,
      recipient: req.recipient as Hex,
      ...(ch.description !== undefined ? { description: ch.description } : {}),
      ...(expiresAtMs !== undefined ? { expiresAtMs } : {}),
    },
  };
}

/**
 * Build the Authorization header value for a tempo pull-mode charge: sign the
 * fee-sponsored (or self-serialized) transfer and wrap it in the credential
 * envelope, echoing every challenge parameter verbatim as the core spec
 * requires.
 */
export function buildTempoCredential(
  ch: MppChallenge,
  privateKey: Buffer | Uint8Array,
  nowMs: number,
): string {
  const req = ch.request;
  const md = req.methodDetails ?? {};
  const chainId = md.chainId ?? TEMPO_DEFAULT_CHAIN_ID;
  const amount = BigInt(req.amount);
  const recipient = req.recipient as Hex;
  const currency = req.currency as Hex;
  const sender = addressFromPrivateKey(privateKey) as Hex;

  const nowSeconds = Math.floor(nowMs / 1000);
  const validBefore = (() => {
    const cap = nowSeconds + MAX_EXPIRY_SECS;
    if (ch.expires === undefined) return cap;
    const challengeExpiry = Math.floor(Date.parse(ch.expires) / 1000);
    return Math.min(cap, challengeExpiry);
  })();

  // Server-supplied memo wins; otherwise the attribution memo binds the
  // transfer to this challenge (servers reject unbound transfers to prevent
  // transaction-hash stealing across challenges).
  const memo = (md.memo as Hex | undefined) ?? attributionMemo(ch.id, ch.realm);
  const data = encodeTransferWithMemo(recipient, amount, memo);

  const tx: TempoChargeTx = {
    chainId,
    maxPriorityFeePerGas: MAX_PRIORITY_FEE,
    maxFeePerGas: MAX_FEE,
    gasLimit: GAS_LIMIT,
    calls: [{ to: currency, value: 0n, data }],
    nonceKey: EXPIRING_NONCE_KEY,
    nonce: 0n,
    validBefore,
    validAfter: randomValidAfter(nowSeconds),
  };
  const signature = signTempoForFeePayer(tx, sender, privateKey);

  // The credential echoes the challenge exactly as received — the server
  // re-derives its HMAC-bound id over these values, so nothing may be
  // re-serialized or reordered.
  const challenge: Record<string, string> = {
    id: ch.id,
    realm: ch.realm,
    method: ch.method,
    intent: ch.intent,
    request: ch.requestB64,
  };
  if (ch.description !== undefined) challenge['description'] = ch.description;
  if (ch.opaque !== undefined) challenge['opaque'] = ch.opaque;
  if (ch.digest !== undefined) challenge['digest'] = ch.digest;
  if (ch.expires !== undefined) challenge['expires'] = ch.expires;

  const credential = {
    challenge,
    payload: { signature, type: 'transaction' },
    source: `did:pkh:eip155:${chainId}:${sender}`,
  };
  return 'Payment ' + b64urlEncode(Buffer.from(JSON.stringify(credential), 'utf8'));
}

/** Decode a Payment-Receipt response header. Returns undefined on garbage. */
export function parseMppReceipt(headerValue: string | null): PaymentReceipt | undefined {
  if (!headerValue) return undefined;
  try {
    const raw = JSON.parse(b64urlDecode(headerValue).toString('utf8')) as Record<string, unknown>;
    return {
      protocol: 'mpp',
      ...(typeof raw['reference'] === 'string' ? { reference: raw['reference'] } : {}),
      raw,
    };
  } catch {
    return undefined;
  }
}
