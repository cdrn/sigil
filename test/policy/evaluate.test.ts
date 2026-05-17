import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import type { Eip1559Tx, LegacyTx, TypedData } from '../../src/eth/index.js';
import {
  evaluate,
  parsePolicy,
  type Policy,
  type PolicyRequest,
} from '../../src/policy/index.js';

const DEAD = '0x000000000000000000000000000000000000dead' as const;

function tx(over: Partial<Eip1559Tx> = {}): Eip1559Tx {
  return {
    type: 'eip1559',
    chainId: 1n,
    nonce: 0n,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 100n,
    gasLimit: 21000n,
    to: DEAD,
    value: 0n,
    data: '0x',
    accessList: [],
    ...over,
  };
}

function strict(over: Partial<Omit<Policy, 'mode'>> = {}): Policy {
  return {
    mode: 'strict',
    chainIds: [1],
    allowTo: [DEAD],
    maxValueWei: 1_000_000_000_000_000n, // 0.001 eth
    allowedSelectors: [],
    allowMessageSigning: false,
    allowTypedData: false,
    ...over,
  };
}

function txReq(t: Eip1559Tx | LegacyTx): PolicyRequest {
  return { kind: 'transaction', tx: t };
}

// ---------------------------------------------------------------------------
// permissive mode — short-circuits to allow
// ---------------------------------------------------------------------------

test('permissive mode allows transactions, messages, typed data', () => {
  const p: Policy = {
    mode: 'permissive',
    chainIds: [], allowTo: [], maxValueWei: 0n, allowedSelectors: [],
    allowMessageSigning: false, allowTypedData: false,
  };
  ok(evaluate(txReq(tx()), p).allow);
  ok(evaluate({ kind: 'message', messageBytes: Buffer.from('hi') }, p).allow);
  ok(evaluate({ kind: 'typed_data', typedData: {} as TypedData }, p).allow);
});

// ---------------------------------------------------------------------------
// transaction — chain ID
// ---------------------------------------------------------------------------

test('strict tx: rejects unallowed chain', () => {
  const r = evaluate(txReq(tx({ chainId: 42n })), strict({ chainIds: [1] }));
  ok(!r.allow);
  if (!r.allow) ok(/chain 42 not in/.test(r.reason));
});

test('strict tx: allows on-allowlist chain', () => {
  ok(evaluate(txReq(tx({ chainId: 8453n })), strict({ chainIds: [1, 8453] })).allow);
});

// ---------------------------------------------------------------------------
// transaction — destination
// ---------------------------------------------------------------------------

test('strict tx: rejects to outside allow_to', () => {
  const r = evaluate(
    txReq(tx({ to: '0x1111111111111111111111111111111111111111' })),
    strict(),
  );
  ok(!r.allow);
  if (!r.allow) ok(/not in allow_to/.test(r.reason));
});

test('strict tx: rejects contract creation (to: null)', () => {
  const r = evaluate(txReq(tx({ to: null })), strict());
  ok(!r.allow);
  if (!r.allow) ok(/contract creation/.test(r.reason));
});

test('strict tx: destination match is case-insensitive', () => {
  ok(evaluate(
    txReq(tx({ to: '0x000000000000000000000000000000000000DEAD' })),
    strict({ allowTo: [DEAD] }),
  ).allow);
});

// ---------------------------------------------------------------------------
// transaction — value caps
// ---------------------------------------------------------------------------

test('strict tx: allows value at the exact cap', () => {
  ok(evaluate(
    txReq(tx({ value: 1_000_000_000_000_000n })),
    strict({ maxValueWei: 1_000_000_000_000_000n }),
  ).allow);
});

test('strict tx: rejects value exactly 1 wei over the cap', () => {
  const r = evaluate(
    txReq(tx({ value: 1_000_000_000_000_001n })),
    strict({ maxValueWei: 1_000_000_000_000_000n }),
  );
  ok(!r.allow);
  if (!r.allow) ok(/exceeds max_value_wei/.test(r.reason));
});

test('strict tx: max_value_wei = 0 forbids any nonzero value', () => {
  const r = evaluate(txReq(tx({ value: 1n })), strict({ maxValueWei: 0n }));
  ok(!r.allow);
});

test('strict tx: max_value_wei = 0 allows pure data calls with value=0 (if selector allowed)', () => {
  // value=0, data is a transfer() call to allowlisted address with allowed selector
  ok(evaluate(
    txReq(tx({
      value: 0n,
      data: '0xa9059cbb000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000000000000000001',
    })),
    strict({ maxValueWei: 0n, allowedSelectors: ['0xa9059cbb'] }),
  ).allow);
});

// ---------------------------------------------------------------------------
// transaction — selector allowlist
// ---------------------------------------------------------------------------

test('strict tx: pure ETH send (no data) is OK regardless of selector list', () => {
  ok(evaluate(
    txReq(tx({ data: '0x' })),
    strict({ allowedSelectors: [] }),
  ).allow);
});

test('strict tx: empty allowed_selectors blocks any tx with calldata', () => {
  const r = evaluate(
    txReq(tx({ data: '0xa9059cbb00000000' })),
    strict({ allowedSelectors: [] }),
  );
  ok(!r.allow);
  if (!r.allow) ok(/not in allowed_selectors/.test(r.reason));
});

test('strict tx: selector match is case-insensitive', () => {
  ok(evaluate(
    txReq(tx({ data: '0xA9059CBB00000000' })),
    strict({ allowedSelectors: ['0xa9059cbb'] }),
  ).allow);
});

test('strict tx: malformed calldata (too short for selector) is denied', () => {
  // data has hex but fewer than 4 bytes
  const r = evaluate(
    txReq(tx({ data: '0xab' })),
    strict({ allowedSelectors: ['0xa9059cbb'] }),
  );
  ok(!r.allow);
});

// ---------------------------------------------------------------------------
// non-transaction signing
// ---------------------------------------------------------------------------

test('strict mode + allow_message_signing=false denies personal_sign', () => {
  const r = evaluate({ kind: 'message', messageBytes: Buffer.from('login challenge') }, strict());
  ok(!r.allow);
  if (!r.allow) ok(/personal_sign denied/.test(r.reason));
});

test('strict mode + allow_message_signing=true allows personal_sign', () => {
  ok(evaluate(
    { kind: 'message', messageBytes: Buffer.from('login') },
    strict({ allowMessageSigning: true }),
  ).allow);
});

test('strict mode + allow_typed_data=false denies EIP-712', () => {
  const r = evaluate({ kind: 'typed_data', typedData: {} as TypedData }, strict());
  ok(!r.allow);
  if (!r.allow) ok(/typed-data denied/.test(r.reason));
});

test('strict mode + allow_typed_data=true allows EIP-712', () => {
  ok(evaluate(
    { kind: 'typed_data', typedData: {} as TypedData },
    strict({ allowTypedData: true }),
  ).allow);
});

// ---------------------------------------------------------------------------
// end-to-end via TOML
// ---------------------------------------------------------------------------

test('end-to-end: parse + evaluate a realistic ERC-20 transfer policy', () => {
  const source = `
    mode = "strict"
    chain_ids = [1]
    allow_to = ["0x000000000000000000000000000000000000dead"]
    max_value_wei = "0"
    allowed_selectors = ["0xa9059cbb"]
    allow_message_signing = false
    allow_typed_data = false
  `;
  const p = parsePolicy(source);
  // transfer to dead address — should allow
  const transferData = ('0xa9059cbb' + '00'.repeat(64)) as `0x${string}`;
  const approveData = ('0x095ea7b3' + '00'.repeat(64)) as `0x${string}`;
  ok(evaluate(txReq(tx({ data: transferData, value: 0n })), p).allow);
  // value send with no data — denied (max_value_wei = 0)
  ok(!evaluate(txReq(tx({ data: '0x', value: 1n })), p).allow);
  // approve() — denied (selector not in allowlist)
  ok(!evaluate(txReq(tx({ data: approveData, value: 0n })), p).allow);
  // wrong chain — denied
  ok(!evaluate(txReq(tx({ data: transferData, value: 0n, chainId: 137n })), p).allow);
});
