import { test } from 'node:test';
import { equal, ok, throws } from 'node:assert/strict';
import type { PaymentCandidate } from '../../src/pay/index.js';
import {
  evaluate,
  parsePolicy,
  type Policy,
  type PolicyDecision,
} from '../../src/policy/index.js';

const TOKEN = '0x20c0000000000000000000000000000000000000';

function candidate(over: Partial<PaymentCandidate> = {}): PaymentCandidate {
  return {
    protocol: 'mpp',
    origin: 'https://api.test',
    method: 'tempo',
    chainId: 42431,
    currency: TOKEN,
    amount: 10_000n,
    recipient: '0xaB782182720864538E26bC424460d96ff364F94C',
    ...over,
  };
}

function strict(over: Partial<Omit<Policy, 'mode'>> = {}): Policy {
  return {
    mode: 'strict',
    chainIds: [42431],
    allowTo: [],
    maxValueWei: 0n,
    allowedSelectors: [],
    allowMessageSigning: false,
    allowTypedData: false,
    payOrigins: ['https://api.test'],
    payMaxAmount: 100_000n,
    payCurrencies: [TOKEN],
    payRecipients: [],
    ...over,
  };
}

function payReq(c: PaymentCandidate): { kind: 'payment'; payment: PaymentCandidate } {
  return { kind: 'payment', payment: c };
}

function denyReason(d: PolicyDecision): string {
  if (d.kind !== 'deny') throw new Error(`expected deny, got ${d.kind}`);
  return d.reason;
}

test('strict payment: allows an in-policy candidate', () => {
  equal(evaluate(payReq(candidate()), strict()).kind, 'allow');
});

test('strict payment: empty pay_origins denies everything', () => {
  const reason = denyReason(evaluate(payReq(candidate()), strict({ payOrigins: [] })));
  ok(reason.includes('pay_origins'));
});

test('strict payment: unlisted origin denied', () => {
  const reason = denyReason(
    evaluate(payReq(candidate({ origin: 'https://evil.test' })), strict()),
  );
  ok(reason.includes('evil.test'));
});

test('strict payment: origin match is case-insensitive', () => {
  equal(evaluate(payReq(candidate({ origin: 'https://API.test' })), strict()).kind, 'allow');
});

test('strict payment: chain outside chain_ids denied', () => {
  const reason = denyReason(evaluate(payReq(candidate({ chainId: 8453 })), strict()));
  ok(reason.includes('chain 8453'));
});

test('strict payment: currency outside pay_currencies denied', () => {
  const reason = denyReason(
    evaluate(payReq(candidate({ currency: '0x' + 'ee'.repeat(20) })), strict()),
  );
  ok(reason.includes('pay_currencies'));
});

test('strict payment: empty pay_currencies means any currency', () => {
  const decision = evaluate(
    payReq(candidate({ currency: '0x' + 'ee'.repeat(20) })),
    strict({ payCurrencies: [] }),
  );
  equal(decision.kind, 'allow');
});

test('strict payment: amount above pay_max_amount denied; boundary allowed', () => {
  ok(denyReason(evaluate(payReq(candidate({ amount: 100_001n })), strict())).includes('pay_max_amount'));
  equal(evaluate(payReq(candidate({ amount: 100_000n })), strict()).kind, 'allow');
});

test('strict payment: default pay_max_amount of 0 denies all payments', () => {
  const reason = denyReason(evaluate(payReq(candidate({ amount: 1n })), strict({ payMaxAmount: 0n })));
  ok(reason.includes('pay_max_amount'));
});

test('strict payment: recipient outside pay_recipients denied', () => {
  const reason = denyReason(
    evaluate(payReq(candidate()), strict({ payRecipients: ['0x' + 'aa'.repeat(20)] })),
  );
  ok(reason.includes('pay_recipients'));
});

test('strict payment: pinned recipient allowed, case-insensitively', () => {
  const decision = evaluate(
    payReq(candidate()),
    strict({ payRecipients: ['0xab782182720864538e26bc424460d96ff364f94c'] }),
  );
  equal(decision.kind, 'allow');
});

test('payment_origin pre-flight: denies before any request, allows listed origins', () => {
  const p = strict();
  equal(evaluate({ kind: 'payment_origin', origin: 'https://api.test' }, p).kind, 'allow');
  const reason = denyReason(evaluate({ kind: 'payment_origin', origin: 'https://evil.test' }, p));
  ok(reason.includes('pay_origins'));
  // Empty allowlist denies everything, matching the full payment evaluation.
  ok(
    denyReason(
      evaluate({ kind: 'payment_origin', origin: 'https://api.test' }, strict({ payOrigins: [] })),
    ).includes('pay_origins'),
  );
});

test('confirm threshold triggers in both modes', () => {
  const strictDecision = evaluate(
    payReq(candidate({ amount: 50_000n })),
    strict({ payRequireConfirmAbove: 10_000n }),
  );
  equal(strictDecision.kind, 'confirm');
  const permissive: Policy = {
    mode: 'permissive',
    chainIds: [], allowTo: [], maxValueWei: 0n, allowedSelectors: [],
    allowMessageSigning: true, allowTypedData: true,
    payOrigins: [], payMaxAmount: 0n, payCurrencies: [], payRecipients: [],
    payRequireConfirmAbove: 10_000n,
  };
  const permissiveDecision = evaluate(payReq(candidate({ amount: 50_000n })), permissive);
  equal(permissiveDecision.kind, 'confirm');
  if (permissiveDecision.kind === 'confirm') {
    ok(permissiveDecision.summary.includes('https://api.test'));
  }
});

test('permissive mode allows payments without pay fields set', () => {
  const permissive: Policy = {
    mode: 'permissive',
    chainIds: [], allowTo: [], maxValueWei: 0n, allowedSelectors: [],
    allowMessageSigning: true, allowTypedData: true,
    payOrigins: [], payMaxAmount: 0n, payCurrencies: [], payRecipients: [],
  };
  equal(evaluate(payReq(candidate()), permissive).kind, 'allow');
});

// ---------------------------------------------------------------------------
// loader
// ---------------------------------------------------------------------------

test('parsePolicy: pay fields parse, normalize, and validate', () => {
  const policy = parsePolicy(`
mode = "strict"
chain_ids = [42431]
pay_origins = ["HTTPS://API.Test"]
pay_max_amount = "100000"
pay_currencies = ["0x20C0000000000000000000000000000000000000"]
pay_require_confirm_above = "10000"
`);
  equal(policy.payOrigins[0], 'https://api.test');
  equal(policy.payMaxAmount, 100_000n);
  equal(policy.payCurrencies[0], TOKEN);
  equal(policy.payRequireConfirmAbove, 10_000n);
});

test('parsePolicy: pay_origins with a path is rejected', () => {
  throws(
    () => parsePolicy(`
mode = "strict"
chain_ids = [1]
pay_origins = ["https://api.test/buy"]
`),
    /bare origin/,
  );
});

test('parsePolicy: confirm threshold at or above the cap is rejected', () => {
  throws(
    () => parsePolicy(`
mode = "strict"
chain_ids = [1]
pay_max_amount = "1000"
pay_require_confirm_above = "1000"
`),
    /pay_require_confirm_above/,
  );
});
