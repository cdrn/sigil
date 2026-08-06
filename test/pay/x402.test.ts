import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import {
  addressFromPrivateKey,
  addressFromPublicKey,
  recoverPublicKey,
  typedDataDigest,
  type TypedData,
} from '../../src/eth/index.js';
import {
  buildX402Payment,
  parseX402Receipt,
  parseX402Requirements,
  x402Candidate,
} from '../../src/pay/index.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }

const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const PAY_TO = '0x209693Bc6afc0C5328bA36FaF03C514EF312287C';

function v2Doc() {
  return {
    x402Version: 2,
    resource: { url: 'https://api.example.com/premium', mimeType: 'application/json' },
    accepts: [
      {
        scheme: 'exact',
        network: 'eip155:8453',
        amount: '10000',
        asset: USDC_BASE,
        payTo: PAY_TO,
        maxTimeoutSeconds: 60,
        extra: { name: 'USD Coin', version: '2' },
      },
    ],
  };
}

test('parses a v2 PAYMENT-REQUIRED header', () => {
  const headerValue = Buffer.from(JSON.stringify(v2Doc())).toString('base64');
  const [req] = parseX402Requirements(headerValue, '');
  equal(req!.x402Version, 2);
  equal(req!.chainId, 8453);
  equal(req!.amount, '10000');
  equal(req!.extraName, 'USD Coin');
});

test('parses a v1 JSON body with maxAmountRequired and network short names', () => {
  const body = JSON.stringify({
    x402Version: 1,
    accepts: [
      {
        scheme: 'exact',
        network: 'base-sepolia',
        maxAmountRequired: '5000',
        asset: USDC_BASE,
        payTo: PAY_TO,
        maxTimeoutSeconds: 30,
        extra: { name: 'USDC', version: '2' },
      },
    ],
  });
  const [req] = parseX402Requirements(null, body);
  equal(req!.x402Version, 1);
  equal(req!.chainId, 84532);
  equal(req!.amount, '5000');
});

test('drops schemes, transfer methods, and networks it cannot pay', () => {
  const doc = v2Doc();
  doc.accepts = [
    { ...doc.accepts[0]!, scheme: 'upto' },
    { ...doc.accepts[0]!, network: 'solana:mainnet' },
    { ...doc.accepts[0]!, extra: { name: 'USDC', version: '2', assetTransferMethod: 'permit2' } },
  ] as never;
  const headerValue = Buffer.from(JSON.stringify(doc)).toString('base64');
  equal(parseX402Requirements(headerValue, '').length, 0);
});

test('x402Candidate carries the origin, not anything model-supplied', () => {
  const headerValue = Buffer.from(JSON.stringify(v2Doc())).toString('base64');
  const [req] = parseX402Requirements(headerValue, '');
  const c = x402Candidate(req!, 'https://api.example.com');
  equal(c.origin, 'https://api.example.com');
  equal(c.amount, 10000n);
  equal(c.currency, USDC_BASE.toLowerCase());
});

test('buildX402Payment signs an EIP-3009 authorization that recovers to the payer', () => {
  const key = priv(5);
  const from = addressFromPrivateKey(key);
  const headerValue = Buffer.from(JSON.stringify(v2Doc())).toString('base64');
  const [req] = parseX402Requirements(headerValue, '');
  const nowMs = 1_800_000_000_000;
  const payment = buildX402Payment(req!, key, nowMs);
  equal(payment.headerName, 'PAYMENT-SIGNATURE');

  const payload = JSON.parse(Buffer.from(payment.headerValue, 'base64').toString('utf8')) as {
    x402Version: number;
    accepted: Record<string, unknown>;
    payload: { signature: string; authorization: Record<string, string> };
  };
  equal(payload.x402Version, 2);
  equal(payload.accepted['scheme'], 'exact');
  const auth = payload.payload.authorization;
  equal(auth['from'], from);
  equal(auth['to'], PAY_TO);
  equal(auth['value'], '10000');
  ok(Number(auth['validBefore']) > nowMs / 1000);

  // Recompute the typed-data digest from the authorization and recover the
  // signer — must be the payer address.
  const typed: TypedData = {
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
      name: 'USD Coin',
      version: '2',
      chainId: 8453,
      verifyingContract: USDC_BASE as `0x${string}`,
    },
    message: {
      from: auth['from']!,
      to: auth['to']!,
      value: BigInt(auth['value']!),
      validAfter: BigInt(auth['validAfter']!),
      validBefore: BigInt(auth['validBefore']!),
      nonce: auth['nonce']!,
    },
  };
  const digest = typedDataDigest(typed);
  const sig = Buffer.from(payload.payload.signature.slice(2), 'hex');
  equal(sig.length, 65);
  const recovery = ((sig[64]! >= 27 ? sig[64]! - 27 : sig[64]!) & 1) as 0 | 1;
  const pub = recoverPublicKey(digest, {
    r: sig.subarray(0, 32),
    s: sig.subarray(32, 64),
    recovery,
  });
  equal(addressFromPublicKey(pub), from);
});

test('v1 payment rides the X-PAYMENT header and echoes the network name', () => {
  const body = JSON.stringify({
    x402Version: 1,
    accepts: [
      {
        scheme: 'exact',
        network: 'base',
        maxAmountRequired: '100',
        asset: USDC_BASE,
        payTo: PAY_TO,
        maxTimeoutSeconds: 30,
        extra: { name: 'USD Coin', version: '2' },
      },
    ],
  });
  const [req] = parseX402Requirements(null, body);
  const payment = buildX402Payment(req!, priv(6), 1_800_000_000_000);
  equal(payment.headerName, 'X-PAYMENT');
  const payload = JSON.parse(Buffer.from(payment.headerValue, 'base64').toString('utf8')) as {
    x402Version: number;
    network: string;
    scheme: string;
  };
  equal(payload.x402Version, 1);
  equal(payload.network, 'base');
  equal(payload.scheme, 'exact');
});

test('parseX402Receipt extracts the settlement transaction', () => {
  const value = Buffer.from(
    JSON.stringify({ success: true, transaction: '0xdeadbeef', network: 'eip155:8453' }),
  ).toString('base64');
  equal(parseX402Receipt(value)!.reference, '0xdeadbeef');
  equal(parseX402Receipt('garbage!!!'), undefined);
});
