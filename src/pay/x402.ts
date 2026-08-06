import { randomBytes } from 'node:crypto';

import { addressFromPrivateKey } from '../eth/address.js';
import type { Hex } from '../eth/sign-tx.js';
import { signTypedData, type TypedData } from '../eth/sign-typed.js';
import type { PaymentCandidate, PaymentReceipt } from './types.js';

/**
 * x402 client for the `exact` scheme on EVM via EIP-3009
 * transferWithAuthorization. Covers both deployed wire generations:
 *
 *   v1 — 402 JSON body { x402Version: 1, accepts: [...] }; retry with the
 *        X-PAYMENT header; settlement result in X-PAYMENT-RESPONSE.
 *   v2 — 402 with base64 PAYMENT-REQUIRED header; retry with
 *        PAYMENT-SIGNATURE; settlement result in PAYMENT-RESPONSE.
 *
 * Networks are CAIP-2 (`eip155:8453`) in v2 and short names in v1; both
 * normalize to a numeric chain ID here. Anything that is not exact+eip3009
 * on an eip155 network is skipped, never guessed at.
 */

const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const DEC_RE = /^[0-9]+$/;

/** v1 network short names → chain IDs (the set the CDP facilitator settles). */
const V1_NETWORKS: Record<string, number> = {
  'base': 8453,
  'base-sepolia': 84532,
  'avalanche': 43114,
  'avalanche-fuji': 43113,
  'polygon': 137,
  'polygon-amoy': 80002,
  'sei': 1329,
  'sei-testnet': 1328,
};

export interface X402Requirement {
  x402Version: 1 | 2;
  scheme: string;
  chainId: number;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extraName: string;
  extraVersion: string;
  description?: string;
  /** The requirement object exactly as the server sent it (echoed in v2). */
  raw: Record<string, unknown>;
  /** v2 resource block, echoed back in the payment payload. */
  resource?: Record<string, unknown>;
}

function parseChainId(network: unknown): number | undefined {
  if (typeof network !== 'string') return undefined;
  const caip = /^eip155:(\d+)$/.exec(network);
  if (caip) return Number(caip[1]);
  return V1_NETWORKS[network];
}

function parseRequirement(
  raw: unknown,
  version: 1 | 2,
  resource: Record<string, unknown> | undefined,
): X402Requirement | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  if (r['scheme'] !== 'exact') return undefined;
  const chainId = parseChainId(r['network']);
  if (chainId === undefined) return undefined;
  const amount = version === 2 ? r['amount'] : (r['amount'] ?? r['maxAmountRequired']);
  if (typeof amount !== 'string' || !DEC_RE.test(amount)) return undefined;
  const asset = r['asset'];
  const payTo = r['payTo'];
  if (typeof asset !== 'string' || !ADDR_RE.test(asset)) return undefined;
  if (typeof payTo !== 'string' || !ADDR_RE.test(payTo)) return undefined;
  const extra = r['extra'];
  if (typeof extra !== 'object' || extra === null) return undefined;
  const { name, version: tokenVersion, assetTransferMethod } = extra as Record<string, unknown>;
  if (typeof name !== 'string' || typeof tokenVersion !== 'string') return undefined;
  if (assetTransferMethod !== undefined && assetTransferMethod !== 'eip3009') return undefined;
  const maxTimeoutSeconds = typeof r['maxTimeoutSeconds'] === 'number' ? r['maxTimeoutSeconds'] : 60;
  const description = r['description'];
  return {
    x402Version: version,
    scheme: 'exact',
    chainId,
    amount,
    asset,
    payTo,
    maxTimeoutSeconds,
    extraName: name,
    extraVersion: tokenVersion,
    ...(typeof description === 'string' ? { description } : {}),
    raw: r,
    ...(resource !== undefined ? { resource } : {}),
  };
}

/**
 * Parse x402 requirements from a 402 response: the v2 PAYMENT-REQUIRED
 * header when present, else a v1 JSON body. Unpayable entries are dropped.
 */
export function parseX402Requirements(
  paymentRequiredHeader: string | null,
  bodyText: string,
): X402Requirement[] {
  let doc: unknown;
  if (paymentRequiredHeader) {
    try {
      doc = JSON.parse(Buffer.from(paymentRequiredHeader, 'base64').toString('utf8'));
    } catch {
      return [];
    }
  } else {
    try {
      doc = JSON.parse(bodyText);
    } catch {
      return [];
    }
  }
  if (typeof doc !== 'object' || doc === null) return [];
  const d = doc as Record<string, unknown>;
  const version = d['x402Version'];
  if (version !== 1 && version !== 2) return [];
  const accepts = d['accepts'];
  if (!Array.isArray(accepts)) return [];
  const resource =
    typeof d['resource'] === 'object' && d['resource'] !== null
      ? (d['resource'] as Record<string, unknown>)
      : undefined;
  const out: X402Requirement[] = [];
  for (const raw of accepts) {
    const req = parseRequirement(raw, version, resource);
    if (req) out.push(req);
  }
  return out;
}

export function x402Candidate(req: X402Requirement, origin: string): PaymentCandidate {
  return {
    protocol: 'x402',
    origin,
    method: 'exact',
    chainId: req.chainId,
    currency: req.asset.toLowerCase(),
    amount: BigInt(req.amount),
    recipient: req.payTo as Hex,
    ...(req.description !== undefined ? { description: req.description } : {}),
  };
}

export interface X402Payment {
  headerName: string;
  headerValue: string;
}

/**
 * Sign an EIP-3009 transferWithAuthorization for the requirement and wrap it
 * in the version-appropriate retry header. The typed-data message is built
 * from the parsed requirement (which came from the origin server), so the
 * signature can never authorize more than the policy engine already judged.
 */
export function buildX402Payment(
  req: X402Requirement,
  privateKey: Buffer | Uint8Array,
  nowMs: number,
): X402Payment {
  const from = addressFromPrivateKey(privateKey) as Hex;
  const nowSeconds = Math.floor(nowMs / 1000);
  // validAfter backdated to tolerate clock skew between us and the settler.
  const validAfter = BigInt(Math.max(0, nowSeconds - 600));
  const validBefore = BigInt(nowSeconds + Math.max(10, req.maxTimeoutSeconds));
  const nonce = ('0x' + randomBytes(32).toString('hex')) as Hex;

  const typedData: TypedData = {
    types: {
      TransferWithAuthorization: [
        { name: 'from', type: 'address' },
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' },
        { name: 'nonce', type: 'bytes32' },
      ],
    },
    primaryType: 'TransferWithAuthorization',
    domain: {
      name: req.extraName,
      version: req.extraVersion,
      chainId: req.chainId,
      verifyingContract: req.asset as Hex,
    },
    message: {
      from,
      to: req.payTo,
      value: BigInt(req.amount),
      validAfter,
      validBefore,
      nonce,
    },
  };
  const signature = ('0x' + signTypedData(typedData, privateKey).toString('hex')) as Hex;

  const authorization = {
    from,
    to: req.payTo,
    value: req.amount,
    validAfter: validAfter.toString(),
    validBefore: validBefore.toString(),
    nonce,
  };

  if (req.x402Version === 2) {
    const payload = {
      x402Version: 2,
      ...(req.resource !== undefined ? { resource: req.resource } : {}),
      accepted: req.raw,
      payload: { signature, authorization },
    };
    return {
      headerName: 'PAYMENT-SIGNATURE',
      headerValue: Buffer.from(JSON.stringify(payload), 'utf8').toString('base64'),
    };
  }
  const network = (req.raw['network'] as string | undefined) ?? `eip155:${req.chainId}`;
  const payload = {
    x402Version: 1,
    scheme: 'exact',
    network,
    payload: { signature, authorization },
  };
  return {
    headerName: 'X-PAYMENT',
    headerValue: Buffer.from(JSON.stringify(payload), 'utf8').toString('base64'),
  };
}

/** Decode PAYMENT-RESPONSE / X-PAYMENT-RESPONSE. Returns undefined on garbage. */
export function parseX402Receipt(headerValue: string | null): PaymentReceipt | undefined {
  if (!headerValue) return undefined;
  try {
    const raw = JSON.parse(Buffer.from(headerValue, 'base64').toString('utf8')) as Record<
      string,
      unknown
    >;
    return {
      protocol: 'x402',
      ...(typeof raw['transaction'] === 'string' && raw['transaction'] !== ''
        ? { reference: raw['transaction'] }
        : {}),
      raw,
    };
  } catch {
    return undefined;
  }
}
