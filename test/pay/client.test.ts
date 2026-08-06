import { test } from 'node:test';
import { deepEqual, equal, ok, rejects } from 'node:assert/strict';
import {
  CandidateRejected,
  pay,
  PayError,
  type FetchLike,
  type PaymentCandidate,
} from '../../src/pay/index.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }

const TOKEN = '0x20c0000000000000000000000000000000000000';
const RECIPIENT = '0xaB782182720864538E26bC424460d96ff364F94C';

function mppChallengeHeader(): string {
  const request = Buffer.from(
    JSON.stringify({
      amount: '10000',
      currency: TOKEN,
      recipient: RECIPIENT,
      methodDetails: { chainId: 42431, feePayer: true },
    }),
  ).toString('base64url');
  return `Payment id="ch1", realm="api.test", method="tempo", intent="charge", expires="2030-01-01T00:00:00Z", request="${request}"`;
}

interface Recorded {
  url: string;
  init: RequestInit;
}

function fakeFetch(
  script: ((call: Recorded, n: number) => Response)[],
  recorded: Recorded[],
): FetchLike {
  return async (url, init) => {
    const call = { url, init: init ?? {} };
    recorded.push(call);
    const step = script[recorded.length - 1];
    if (!step) throw new Error(`unexpected fetch #${recorded.length} to ${url}`);
    return step(call, recorded.length);
  };
}

function deps(fetchImpl: FetchLike, authorized: PaymentCandidate[]) {
  return {
    fetchImpl,
    now: () => Date.parse('2029-12-31T23:59:00Z'),
    authorizeOrigin: async () => undefined,
    authorize: async (c: PaymentCandidate) => {
      authorized.push(c);
    },
    privateKey: priv(1),
  };
}

test('non-402 responses pass through unpaid', async () => {
  const recorded: Recorded[] = [];
  const fetchImpl = fakeFetch([() => new Response('hello', { status: 200 })], recorded);
  const outcome = await pay({ url: 'https://api.test/x', method: 'GET' }, deps(fetchImpl, []));
  equal(outcome.status, 200);
  equal(outcome.paid, false);
  equal(outcome.bodyPreview, 'hello');
  equal(recorded.length, 1);
});

test('MPP flow: 402 → authorize → signed retry → receipt', async () => {
  const recorded: Recorded[] = [];
  const receipt = Buffer.from(
    JSON.stringify({ status: 'success', method: 'tempo', reference: '0xtx' }),
  ).toString('base64url');
  const fetchImpl = fakeFetch(
    [
      () =>
        new Response('{"title":"Payment Required"}', {
          status: 402,
          headers: { 'www-authenticate': mppChallengeHeader() },
        }),
      (call) => {
        const headers = call.init.headers as Record<string, string>;
        ok(headers['authorization']!.startsWith('Payment '), 'retry must carry the credential');
        return new Response('{"item":"paid"}', {
          status: 201,
          headers: { 'payment-receipt': receipt },
        });
      },
    ],
    recorded,
  );
  const authorized: PaymentCandidate[] = [];
  const outcome = await pay({ url: 'https://api.test/buy', method: 'POST', body: '{"name":"n"}' }, deps(fetchImpl, authorized));
  equal(outcome.status, 201);
  equal(outcome.paid, true);
  equal(authorized.length, 1);
  equal(authorized[0]!.origin, 'https://api.test');
  equal(authorized[0]!.amount, 10000n);
  equal(outcome.receipt!.reference, '0xtx');
  // Body must be resent identically on the paid retry.
  equal(recorded[0]!.init.body, '{"name":"n"}');
  equal(recorded[1]!.init.body, '{"name":"n"}');
});

test('x402 v1 flow pays via X-PAYMENT and reads X-PAYMENT-RESPONSE', async () => {
  const body = JSON.stringify({
    x402Version: 1,
    accepts: [
      {
        scheme: 'exact',
        network: 'base-sepolia',
        maxAmountRequired: '50',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        payTo: RECIPIENT,
        maxTimeoutSeconds: 30,
        extra: { name: 'USDC', version: '2' },
      },
    ],
  });
  const settlement = Buffer.from(
    JSON.stringify({ success: true, transaction: '0xsettled' }),
  ).toString('base64');
  const recorded: Recorded[] = [];
  const fetchImpl = fakeFetch(
    [
      () => new Response(body, { status: 402 }),
      (call) => {
        const headers = call.init.headers as Record<string, string>;
        ok(headers['X-PAYMENT'] ?? headers['x-payment'], 'retry must carry X-PAYMENT');
        return new Response('data', {
          status: 200,
          headers: { 'x-payment-response': settlement },
        });
      },
    ],
    recorded,
  );
  const authorized: PaymentCandidate[] = [];
  const outcome = await pay({ url: 'https://api.test/data', method: 'GET' }, deps(fetchImpl, authorized));
  equal(outcome.paid, true);
  equal(outcome.receipt!.reference, '0xsettled');
  equal(authorized[0]!.protocol, 'x402');
  equal(authorized[0]!.chainId, 84532);
});

test('authorize rejection propagates and nothing is signed or retried', async () => {
  const recorded: Recorded[] = [];
  const fetchImpl = fakeFetch(
    [
      () =>
        new Response('', {
          status: 402,
          headers: { 'www-authenticate': mppChallengeHeader() },
        }),
    ],
    recorded,
  );
  const denied = new Error('policy denied');
  await rejects(
    () =>
      pay(
        { url: 'https://api.test/buy', method: 'GET' },
        {
          fetchImpl,
          now: () => Date.parse('2029-12-31T23:59:00Z'),
          authorizeOrigin: async () => undefined,
          authorize: async () => {
            throw new CandidateRejected(denied);
          },
          privateKey: priv(1),
        },
      ),
    (err: unknown) => err === denied,
  );
  equal(recorded.length, 1, 'no second request after deny');
});

test('server preference order: first authorized candidate wins', async () => {
  const request = Buffer.from(
    JSON.stringify({
      amount: '10000',
      currency: TOKEN,
      recipient: RECIPIENT,
      methodDetails: { chainId: 42431, feePayer: true },
    }),
  ).toString('base64url');
  const twoChallenges =
    `Payment id="a", realm="r", method="stripe", intent="charge", request="e30", ` +
    `Payment id="b", realm="r", method="tempo", intent="charge", expires="2030-01-01T00:00:00Z", request="${request}"`;
  const recorded: Recorded[] = [];
  const fetchImpl = fakeFetch(
    [
      () => new Response('', { status: 402, headers: { 'www-authenticate': twoChallenges } }),
      () => new Response('ok', { status: 200 }),
    ],
    recorded,
  );
  const authorized: PaymentCandidate[] = [];
  const outcome = await pay({ url: 'https://api.test/x', method: 'GET' }, deps(fetchImpl, authorized));
  // stripe was skipped as unpayable; tempo was the only candidate offered.
  deepEqual(authorized.map((c) => c.method), ['tempo']);
  equal(outcome.paid, true);
});

test('refuses redirects and non-https URLs', async () => {
  const recorded: Recorded[] = [];
  const fetchImpl = fakeFetch(
    [() => new Response('', { status: 302, headers: { location: 'https://evil.test' } })],
    recorded,
  );
  await rejects(
    () => pay({ url: 'https://api.test/x', method: 'GET' }, deps(fetchImpl, [])),
    PayError,
  );
  await rejects(
    () => pay({ url: 'http://api.test/x', method: 'GET' }, deps(fakeFetch([], []), [])),
    PayError,
  );
});

// ---------------------------------------------------------------------------
// Security regressions (found in review)
// ---------------------------------------------------------------------------

test('origin gate runs BEFORE any request leaves the machine', async () => {
  const recorded: Recorded[] = [];
  const fetchImpl = fakeFetch([() => new Response('secret', { status: 200 })], recorded);
  const denied = new Error('origin denied');
  await rejects(
    () =>
      pay(
        { url: 'https://internal.test/admin', method: 'POST', body: 'do-a-thing' },
        {
          fetchImpl,
          now: () => Date.parse('2029-12-31T23:59:00Z'),
          authorizeOrigin: async () => {
            throw denied;
          },
          authorize: async () => undefined,
          privateKey: priv(1),
        },
      ),
    (err: unknown) => err === denied,
  );
  equal(recorded.length, 0, 'no HTTP request may be made for a disallowed origin');
});

test('a non-CandidateRejected throw (human deny) aborts instead of trying the next candidate', async () => {
  // Two payable tempo candidates; the human denies the first.
  const mk = (id: string, amount: string) => {
    const request = Buffer.from(
      JSON.stringify({
        amount,
        currency: TOKEN,
        recipient: RECIPIENT,
        methodDetails: { chainId: 42431, feePayer: true },
      }),
    ).toString('base64url');
    return `Payment id="${id}", realm="r", method="tempo", intent="charge", expires="2030-01-01T00:00:00Z", request="${request}"`;
  };
  const recorded: Recorded[] = [];
  const fetchImpl = fakeFetch(
    [
      () =>
        new Response('', {
          status: 402,
          headers: { 'www-authenticate': `${mk('big', '900000')}, ${mk('small', '10')}` },
        }),
      () => new Response('should never happen', { status: 200 }),
    ],
    recorded,
  );
  const humanDenied = new Error('confirm denied by human');
  const seen: bigint[] = [];
  await rejects(
    () =>
      pay(
        { url: 'https://api.test/x', method: 'GET' },
        {
          fetchImpl,
          now: () => Date.parse('2029-12-31T23:59:00Z'),
          authorizeOrigin: async () => undefined,
          authorize: async (c) => {
            seen.push(c.amount);
            throw humanDenied; // raw, not CandidateRejected
          },
          privateKey: priv(1),
        },
      ),
    (err: unknown) => err === humanDenied,
  );
  deepEqual(seen, [900000n], 'must not fall through to the cheaper candidate');
  equal(recorded.length, 1, 'nothing may be paid after a human deny');
});

test('a CandidateRejected still falls through to the next candidate', async () => {
  const mk = (id: string, amount: string) => {
    const request = Buffer.from(
      JSON.stringify({
        amount,
        currency: TOKEN,
        recipient: RECIPIENT,
        methodDetails: { chainId: 42431, feePayer: true },
      }),
    ).toString('base64url');
    return `Payment id="${id}", realm="r", method="tempo", intent="charge", expires="2030-01-01T00:00:00Z", request="${request}"`;
  };
  const recorded: Recorded[] = [];
  const fetchImpl = fakeFetch(
    [
      () =>
        new Response('', {
          status: 402,
          headers: { 'www-authenticate': `${mk('big', '900000')}, ${mk('small', '10')}` },
        }),
      () => new Response('ok', { status: 200 }),
    ],
    recorded,
  );
  const seen: bigint[] = [];
  const outcome = await pay(
    { url: 'https://api.test/x', method: 'GET' },
    {
      fetchImpl,
      now: () => Date.parse('2029-12-31T23:59:00Z'),
      authorizeOrigin: async () => undefined,
      authorize: async (c) => {
        seen.push(c.amount);
        if (c.amount > 1000n) throw new CandidateRejected(new Error('over cap'));
      },
      privateKey: priv(1),
    },
  );
  deepEqual(seen, [900000n, 10n]);
  equal(outcome.paid, true);
  equal(outcome.candidate!.amount, 10n);
});

test('credential release is reported before the outcome is known, and a dropped response is UNKNOWN', async () => {
  const recorded: Recorded[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    recorded.push({ url, init: init ?? {} });
    if (recorded.length === 1) {
      return new Response('', {
        status: 402,
        headers: { 'www-authenticate': mppChallengeHeader() },
      });
    }
    throw new Error('socket hang up');
  };
  const released: PaymentCandidate[] = [];
  await rejects(
    () =>
      pay(
        { url: 'https://api.test/buy', method: 'GET' },
        {
          fetchImpl,
          now: () => Date.parse('2029-12-31T23:59:00Z'),
          authorizeOrigin: async () => undefined,
          authorize: async () => undefined,
          onCredentialReleased: (c) => released.push(c),
          privateKey: priv(1),
        },
      ),
    (err: unknown) =>
      err instanceof PayError &&
      err.message.includes('UNKNOWN') &&
      err.message.includes('audit log'),
  );
  equal(released.length, 1, 'the released spend authorization must be recorded');
  equal(released[0]!.amount, 10000n);
});

test('a 3xx after payment is not reported as paid', async () => {
  const recorded: Recorded[] = [];
  const fetchImpl = fakeFetch(
    [
      () =>
        new Response('', {
          status: 402,
          headers: { 'www-authenticate': mppChallengeHeader() },
        }),
      () => new Response('', { status: 302, headers: { location: 'https://elsewhere.test' } }),
    ],
    recorded,
  );
  const outcome = await pay({ url: 'https://api.test/x', method: 'GET' }, deps(fetchImpl, []));
  equal(outcome.paid, false, '3xx carries no settlement evidence');
  equal(outcome.settlement, 'unknown');
});

test('a 402 answer to the paid retry is a rejection, not an unknown settlement', async () => {
  const fetchImpl = fakeFetch(
    [
      () =>
        new Response('', {
          status: 402,
          headers: { 'www-authenticate': mppChallengeHeader() },
        }),
      () => new Response('{"detail":"verification failed"}', { status: 402 }),
    ],
    [],
  );
  const outcome = await pay({ url: 'https://api.test/x', method: 'GET' }, deps(fetchImpl, []));
  equal(outcome.paid, false);
  equal(outcome.settlement, 'rejected');
});

test('response bodies are capped while streaming', async () => {
  const huge = 'x'.repeat(600_000);
  const fetchImpl = fakeFetch([() => new Response(huge, { status: 200 })], []);
  const outcome = await pay({ url: 'https://api.test/x', method: 'GET' }, deps(fetchImpl, []));
  // Preview is bounded, and the underlying read stopped at MAX_BODY_BYTES.
  ok(outcome.bodyPreview.length <= 2049, `preview was ${outcome.bodyPreview.length}`);
});

test('402 with no payable challenge surfaces the skip reasons', async () => {
  const request = Buffer.from(
    JSON.stringify({ amount: '0', currency: TOKEN, recipient: RECIPIENT }),
  ).toString('base64url');
  const fetchImpl = fakeFetch(
    [
      () =>
        new Response('', {
          status: 402,
          headers: {
            'www-authenticate': `Payment id="z", realm="r", method="tempo", intent="charge", request="${request}"`,
          },
        }),
    ],
    [],
  );
  await rejects(
    () => pay({ url: 'https://api.test/x', method: 'GET' }, deps(fetchImpl, [])),
    (err: unknown) => err instanceof PayError && err.message.includes('zero-amount'),
  );
});
