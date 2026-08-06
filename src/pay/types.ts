import type { Hex } from '../eth/sign-tx.js';

/**
 * A single payable option extracted from a 402 response, normalized across
 * protocols so the policy engine can judge them uniformly. Everything here
 * comes from the origin server's challenge — never from tool arguments —
 * which is what makes it trustworthy policy input.
 */
export interface PaymentCandidate {
  protocol: 'mpp' | 'x402';
  /** Origin (scheme://host[:port]) the challenge was fetched from. */
  origin: string;
  /** MPP method or x402 scheme, e.g. "tempo" / "exact". */
  method: string;
  chainId: number;
  /** Token address (lowercased) or ISO 4217 code. */
  currency: string;
  /** Base units. */
  amount: bigint;
  recipient: Hex;
  description?: string;
  /** Challenge expiry, ms since epoch, when the protocol conveys one. */
  expiresAtMs?: number;
}

export interface PaymentReceipt {
  protocol: 'mpp' | 'x402';
  /** Settlement reference: tx hash, invoice id, etc. */
  reference?: string;
  raw?: unknown;
}

export interface PayOutcome {
  status: number;
  paid: boolean;
  /**
   * What is known about the money:
   *   'none'     — no payment was attempted (the resource wasn't 402).
   *   'settled'  — credential sent, server answered 2xx.
   *   'rejected' — server answered 402 again; the credential was refused.
   *   'unknown'  — the credential is on the wire and may have settled, but
   *                the response was an error or never arrived. Do NOT retry
   *                blind: a fresh authorization could double-spend.
   */
  settlement: 'none' | 'settled' | 'rejected' | 'unknown';
  candidate?: PaymentCandidate;
  receipt?: PaymentReceipt;
  /** First 2 KiB of the response body. */
  bodyPreview: string;
}

/** Same injection seam the ntfy transport uses. */
export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;
