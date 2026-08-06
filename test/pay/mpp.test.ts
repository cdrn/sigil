import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { addressFromPrivateKey } from '../../src/eth/index.js';
import {
  attributionMemo,
  buildTempoCredential,
  parseMppChallenges,
  parseMppReceipt,
  tempoCandidate,
} from '../../src/pay/index.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }

const TOKEN = '0x20c0000000000000000000000000000000000000';
const RECIPIENT = '0xaB782182720864538E26bC424460d96ff364F94C';

function requestB64(over: Record<string, unknown> = {}): string {
  const req = {
    amount: '10000',
    currency: TOKEN,
    recipient: RECIPIENT,
    methodDetails: { chainId: 42431, feePayer: true },
    ...over,
  };
  return Buffer.from(JSON.stringify(req), 'utf8').toString('base64url');
}

function header(over: { request?: string; method?: string; intent?: string } = {}): string {
  return (
    `Payment id="ch1", realm="api.test", method="${over.method ?? 'tempo'}", ` +
    `intent="${over.intent ?? 'charge'}", expires="2030-01-01T00:00:00Z", ` +
    `request="${over.request ?? requestB64()}"`
  );
}

test('parseMppChallenges decodes the request JSON and keeps the wire base64', () => {
  const [ch] = parseMppChallenges([header()]);
  equal(ch!.id, 'ch1');
  equal(ch!.request.amount, '10000');
  equal(ch!.requestB64, requestB64());
});

test('tempoCandidate normalizes a payable challenge', () => {
  const [ch] = parseMppChallenges([header()]);
  const judged = tempoCandidate(ch!, 'https://api.test');
  ok('candidate' in judged);
  equal(judged.candidate.protocol, 'mpp');
  equal(judged.candidate.chainId, 42431);
  equal(judged.candidate.amount, 10000n);
  equal(judged.candidate.currency, TOKEN);
  equal(judged.candidate.recipient, RECIPIENT);
});

test('tempoCandidate skips what it cannot pay, with reasons', () => {
  const cases: [Record<string, unknown> | null, string, string][] = [
    [null, 'stripe', 'method'],
    [{ amount: '0' }, 'tempo', 'zero-amount'],
    [{ recipient: undefined }, 'tempo', 'recipient'],
    [{ currency: 'usd' }, 'tempo', 'token address'],
    [
      { methodDetails: { feePayer: true, splits: [{ recipient: RECIPIENT, amount: '1' }] } },
      'tempo',
      'split',
    ],
    [{ methodDetails: { feePayer: true, supportedModes: ['push'] } }, 'tempo', 'pull'],
    [{ methodDetails: { chainId: 42431 } }, 'tempo', 'sponsor'],
  ];
  for (const [over, method, expect] of cases) {
    const [ch] = parseMppChallenges([
      header({ method, ...(over ? { request: requestB64(over) } : {}) }),
    ]);
    const judged = tempoCandidate(ch!, 'https://api.test');
    ok('skip' in judged, `expected skip for ${expect}`);
    ok(judged.skip.toLowerCase().includes(expect.toLowerCase()), `"${judged.skip}" ~ ${expect}`);
  }
});

test('buildTempoCredential echoes the challenge verbatim and signs a 0x78 envelope', () => {
  const [ch] = parseMppChallenges([header()]);
  const key = priv(3);
  const headerValue = buildTempoCredential(ch!, key, Date.parse('2029-12-31T23:59:00Z'));
  ok(headerValue.startsWith('Payment '));
  const credential = JSON.parse(
    Buffer.from(headerValue.slice('Payment '.length), 'base64url').toString('utf8'),
  ) as {
    challenge: Record<string, string>;
    payload: { signature: string; type: string };
    source: string;
  };
  // Challenge echo: byte-identical fields, most critically the request b64.
  equal(credential.challenge['id'], 'ch1');
  equal(credential.challenge['request'], requestB64());
  equal(credential.challenge['expires'], '2030-01-01T00:00:00Z');
  equal(credential.payload.type, 'transaction');
  ok(credential.payload.signature.startsWith('0x78'));
  equal(credential.source, `did:pkh:eip155:42431:${addressFromPrivateKey(key)}`);
});

test('validBefore is capped by the challenge expiry when it is sooner', () => {
  const expires = '2029-01-01T00:00:10Z';
  const [ch] = parseMppChallenges([
    `Payment id="c", realm="r", method="tempo", intent="charge", expires="${expires}", request="${requestB64()}"`,
  ]);
  // now + 25s would land past the expiry; the tx must not outlive the challenge.
  const nowMs = Date.parse('2029-01-01T00:00:00Z');
  const headerValue = buildTempoCredential(ch!, priv(4), nowMs);
  ok(headerValue.length > 0);
  // (Envelope-level validBefore assertions live in tempo.test.ts; here we
  // only pin that building against a tight expiry does not throw.)
});

test('attributionMemo binds tag, version, realm, and challenge id', () => {
  const memo = attributionMemo('challenge-123', 'api.example.com');
  ok(/^0x[0-9a-f]{64}$/.test(memo));
  const bytes = Buffer.from(memo.slice(2), 'hex');
  // keccak256("mpp")[0..3] tag + version 0x01.
  equal(bytes[4], 0x01);
  // Anonymous client slot stays zero.
  equal(bytes.subarray(15, 25).toString('hex'), '00'.repeat(10));
  // Different challenge → different nonce; different realm → different fingerprint.
  const other = Buffer.from(attributionMemo('challenge-124', 'api.example.com').slice(2), 'hex');
  ok(!bytes.subarray(25).equals(other.subarray(25)));
  ok(bytes.subarray(5, 15).equals(other.subarray(5, 15)));
});

test('parseMppReceipt decodes reference and tolerates garbage', () => {
  const receipt = parseMppReceipt(
    Buffer.from(JSON.stringify({ status: 'success', reference: '0xabc' })).toString('base64url'),
  );
  equal(receipt!.reference, '0xabc');
  equal(parseMppReceipt('%%%not-base64-json'), undefined);
  equal(parseMppReceipt(null), undefined);
});
