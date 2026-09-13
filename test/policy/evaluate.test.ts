import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import type { Eip1559Tx, LegacyTx, TypedData } from '../../src/eth/index.js';
import {
  evaluate,
  parsePolicy,
  type Policy,
  type PolicyDecision,
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
    allowContractCreation: false,
    allowMessageSigning: false,
    allowTypedData: false,
    allowSvmMessageSigning: false,
    svmAllowTo: [],
    svmMaxLamports: 0n,
    typedDataVerifyingContracts: [],
    typedDataPrimaryTypes: [],
    ...over,
  };
}

function txReq(t: Eip1559Tx | LegacyTx): PolicyRequest {
  return { kind: 'transaction', tx: t };
}

function isAllow(d: PolicyDecision): boolean {
  return d.kind === 'allow';
}

function denyReason(d: PolicyDecision): string {
  if (d.kind !== 'deny') throw new Error(`expected deny, got ${d.kind}`);
  return d.reason;
}

function confirmSummary(d: PolicyDecision): string {
  if (d.kind !== 'confirm') throw new Error(`expected confirm, got ${d.kind}`);
  return d.summary;
}

// ---------------------------------------------------------------------------
// permissive mode — short-circuits to allow
// ---------------------------------------------------------------------------

test('permissive mode allows transactions, messages, typed data', () => {
  const p: Policy = {
    mode: 'permissive',
    chainIds: [],
    allowTo: [],
    maxValueWei: 0n,
    allowedSelectors: [],
    allowContractCreation: true,
    allowMessageSigning: false,
    allowTypedData: false,
    allowSvmMessageSigning: false,
    svmAllowTo: [],
    svmMaxLamports: 0n,
    typedDataVerifyingContracts: [],
    typedDataPrimaryTypes: [],
  };
  ok(isAllow(evaluate(txReq(tx()), p)));
  ok(isAllow(evaluate({ kind: 'message', messageBytes: Buffer.from('hi') }, p)));
  ok(isAllow(evaluate({ kind: 'typed_data', typedData: {} as TypedData }, p)));
});

// ---------------------------------------------------------------------------
// transaction — chain ID
// ---------------------------------------------------------------------------

test('strict tx: rejects unallowed chain', () => {
  const r = evaluate(txReq(tx({ chainId: 42n })), strict({ chainIds: [1] }));
  ok(/chain 42 not in/.test(denyReason(r)));
});

test('strict tx: allows on-allowlist chain', () => {
  ok(isAllow(evaluate(txReq(tx({ chainId: 8453n })), strict({ chainIds: [1, 8453] }))));
});

// ---------------------------------------------------------------------------
// transaction — destination
// ---------------------------------------------------------------------------

test('strict tx: rejects to outside allow_to', () => {
  const r = evaluate(txReq(tx({ to: '0x1111111111111111111111111111111111111111' })), strict());
  ok(/not in allow_to/.test(denyReason(r)));
});

test('strict tx: rejects contract creation (to: null) by default', () => {
  const r = evaluate(txReq(tx({ to: null })), strict());
  ok(/contract creation not allowed/.test(denyReason(r)));
});

// ---------------------------------------------------------------------------
// transaction — contract creation (allow_contract_creation)
// ---------------------------------------------------------------------------

test('strict tx: allow_contract_creation=true routes a deploy to confirm, never plain allow', () => {
  const r = evaluate(
    txReq(tx({ to: null, data: '0x60806040' })),
    strict({ allowContractCreation: true }),
  );
  const summary = confirmSummary(r);
  ok(/contract creation/.test(summary), summary);
  ok(/4-byte initcode/.test(summary), summary);
  ok(/chain 1/.test(summary), summary);
});

test('strict tx: deploy skips allow_to and allowed_selectors (no address/selector to match)', () => {
  // Empty allowlists would deny any call tx with this calldata; a creation
  // tx carries initcode, not a selector, so neither list applies.
  const r = evaluate(
    txReq(tx({ to: null, data: '0x6080604052600080fd' })),
    strict({ allowContractCreation: true, allowTo: [], allowedSelectors: [] }),
  );
  equal(r.kind, 'confirm');
});

test('strict tx: deploy still respects max_value_wei', () => {
  const r = evaluate(
    txReq(tx({ to: null, value: 2_000n })),
    strict({ allowContractCreation: true, maxValueWei: 1_000n }),
  );
  ok(/exceeds max_value_wei/.test(denyReason(r)));
});

test('strict tx: deploy still respects chain_ids', () => {
  const r = evaluate(
    txReq(tx({ to: null, chainId: 42n })),
    strict({ allowContractCreation: true, chainIds: [1] }),
  );
  ok(/chain 42 not in/.test(denyReason(r)));
});

test('strict tx: deploy value exactly at max_value_wei is allowed (routes to confirm)', () => {
  const r = evaluate(
    txReq(tx({ to: null, value: 1_000n })),
    strict({ allowContractCreation: true, maxValueWei: 1_000n }),
  );
  equal(r.kind, 'confirm');
});

test('strict tx: legacy-type deploy routes to confirm the same way', () => {
  const legacy: LegacyTx = {
    type: 'legacy',
    chainId: 1n,
    nonce: 0n,
    gasPrice: 1n,
    gasLimit: 100_000n,
    to: null,
    value: 0n,
    data: '0x6080',
  };
  const r = evaluate(txReq(legacy), strict({ allowContractCreation: true }));
  const summary = confirmSummary(r);
  ok(/2-byte initcode/.test(summary), summary);
});

test('strict tx: deploy summary counts initcode bytes for Buffer data too', () => {
  const r = evaluate(
    txReq(tx({ to: null, data: Buffer.from('60806040526000', 'hex') })),
    strict({ allowContractCreation: true }),
  );
  ok(/7-byte initcode/.test(confirmSummary(r)));
});

test('strict tx: deploy summary includes the ETH value', () => {
  const r = evaluate(
    txReq(tx({ to: null, value: 500_000_000_000_000n })),
    strict({ allowContractCreation: true, maxValueWei: 1_000_000_000_000_000n }),
  );
  ok(/^0\.0005 ETH /.test(confirmSummary(r)), confirmSummary(r));
});

test('strict tx: destination match is case-insensitive', () => {
  ok(
    isAllow(
      evaluate(
        txReq(tx({ to: '0x000000000000000000000000000000000000DEAD' })),
        strict({ allowTo: [DEAD] }),
      ),
    ),
  );
});

// ---------------------------------------------------------------------------
// transaction — value caps
// ---------------------------------------------------------------------------

test('strict tx: allows value at the exact cap', () => {
  ok(
    isAllow(
      evaluate(
        txReq(tx({ value: 1_000_000_000_000_000n })),
        strict({ maxValueWei: 1_000_000_000_000_000n }),
      ),
    ),
  );
});

test('strict tx: rejects value exactly 1 wei over the cap', () => {
  const r = evaluate(
    txReq(tx({ value: 1_000_000_000_000_001n })),
    strict({ maxValueWei: 1_000_000_000_000_000n }),
  );
  ok(/exceeds max_value_wei/.test(denyReason(r)));
});

test('strict tx: max_value_wei = 0 forbids any nonzero value', () => {
  const r = evaluate(txReq(tx({ value: 1n })), strict({ maxValueWei: 0n }));
  equal(r.kind, 'deny');
});

test('strict tx: max_value_wei = 0 allows pure data calls with value=0 (if selector allowed)', () => {
  ok(
    isAllow(
      evaluate(
        txReq(
          tx({
            value: 0n,
            data: '0xa9059cbb000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000000000000000001',
          }),
        ),
        strict({ maxValueWei: 0n, allowedSelectors: ['0xa9059cbb'] }),
      ),
    ),
  );
});

// ---------------------------------------------------------------------------
// transaction — selector allowlist
// ---------------------------------------------------------------------------

test('strict tx: pure ETH send (no data) is OK regardless of selector list', () => {
  ok(isAllow(evaluate(txReq(tx({ data: '0x' })), strict({ allowedSelectors: [] }))));
});

test('strict tx: empty allowed_selectors blocks any tx with calldata', () => {
  const r = evaluate(txReq(tx({ data: '0xa9059cbb00000000' })), strict({ allowedSelectors: [] }));
  ok(/not in allowed_selectors/.test(denyReason(r)));
});

test('strict tx: selector match is case-insensitive', () => {
  ok(
    isAllow(
      evaluate(
        txReq(tx({ data: '0xA9059CBB00000000' })),
        strict({ allowedSelectors: ['0xa9059cbb'] }),
      ),
    ),
  );
});

test('strict tx: malformed calldata (too short for selector) is denied', () => {
  const r = evaluate(txReq(tx({ data: '0xab' })), strict({ allowedSelectors: ['0xa9059cbb'] }));
  equal(r.kind, 'deny');
});

// ---------------------------------------------------------------------------
// non-transaction signing
// ---------------------------------------------------------------------------

test('strict mode + allow_message_signing=false denies personal_sign', () => {
  const r = evaluate({ kind: 'message', messageBytes: Buffer.from('login challenge') }, strict());
  ok(/personal_sign denied/.test(denyReason(r)));
});

test('strict mode + allow_message_signing=true allows personal_sign', () => {
  ok(
    isAllow(
      evaluate(
        { kind: 'message', messageBytes: Buffer.from('login') },
        strict({ allowMessageSigning: true }),
      ),
    ),
  );
});

test('strict mode + allow_typed_data=false denies EIP-712', () => {
  const r = evaluate({ kind: 'typed_data', typedData: {} as TypedData }, strict());
  ok(/typed-data denied/.test(denyReason(r)));
});

test('strict mode + allow_typed_data=true allows EIP-712', () => {
  ok(
    isAllow(
      evaluate(
        { kind: 'typed_data', typedData: {} as TypedData },
        strict({ allowTypedData: true }),
      ),
    ),
  );
});

// ---------------------------------------------------------------------------
// require_confirm_above_wei — confirm decision arm
// ---------------------------------------------------------------------------

test('confirm: strict tx — value exactly at threshold does not require confirm', () => {
  const p = strict({ maxValueWei: 1_000n, requireConfirmAboveWei: 500n });
  ok(isAllow(evaluate(txReq(tx({ value: 500n })), p)));
});

test('confirm: strict tx — value 1 wei over threshold requires confirm', () => {
  const p = strict({ maxValueWei: 1_000n, requireConfirmAboveWei: 500n });
  const r = evaluate(txReq(tx({ value: 501n })), p);
  const summary = confirmSummary(r);
  ok(/0x0000…dead/.test(summary), summary);
  ok(/chain 1/.test(summary));
});

test('confirm: strict-mode static deny fires BEFORE confirm gate', () => {
  // Value over the hard cap → deny, never reaches the confirm threshold.
  const p = strict({ maxValueWei: 1_000n, requireConfirmAboveWei: 500n });
  const r = evaluate(txReq(tx({ value: 2_000n })), p);
  equal(r.kind, 'deny');
});

test('confirm: permissive mode honours the confirm threshold', () => {
  const p: Policy = {
    mode: 'permissive',
    chainIds: [],
    allowTo: [],
    maxValueWei: 0n,
    allowedSelectors: [],
    allowContractCreation: true,
    allowMessageSigning: true,
    allowTypedData: true,
    allowSvmMessageSigning: true,
    svmAllowTo: [],
    svmMaxLamports: 0n,
    typedDataVerifyingContracts: [],
    typedDataPrimaryTypes: [],
    requireConfirmAboveWei: 500n,
  };
  const r = evaluate(txReq(tx({ value: 1_000n })), p);
  equal(r.kind, 'confirm');
});

test('confirm: permissive mode without threshold → allow', () => {
  const p: Policy = {
    mode: 'permissive',
    chainIds: [],
    allowTo: [],
    maxValueWei: 0n,
    allowedSelectors: [],
    allowContractCreation: true,
    allowMessageSigning: true,
    allowTypedData: true,
    allowSvmMessageSigning: true,
    svmAllowTo: [],
    svmMaxLamports: 0n,
    typedDataVerifyingContracts: [],
    typedDataPrimaryTypes: [],
  };
  ok(isAllow(evaluate(txReq(tx({ value: 999_999n })), p)));
});

test('confirm: contract creation summary names "contract creation"', () => {
  const p: Policy = {
    mode: 'permissive',
    chainIds: [],
    allowTo: [],
    maxValueWei: 0n,
    allowedSelectors: [],
    allowContractCreation: true,
    allowMessageSigning: true,
    allowTypedData: true,
    allowSvmMessageSigning: true,
    svmAllowTo: [],
    svmMaxLamports: 0n,
    typedDataVerifyingContracts: [],
    typedDataPrimaryTypes: [],
    requireConfirmAboveWei: 0n,
  };
  const r = evaluate(txReq(tx({ to: null, value: 1n, data: '0x6080604052' })), p);
  const summary = confirmSummary(r);
  ok(/contract creation/.test(summary), summary);
  ok(/5-byte initcode/.test(summary), summary);
});

test('confirm: message/typed_data do not trigger confirm gate (deferred)', () => {
  const p: Policy = {
    mode: 'permissive',
    chainIds: [],
    allowTo: [],
    maxValueWei: 0n,
    allowedSelectors: [],
    allowContractCreation: true,
    allowMessageSigning: true,
    allowTypedData: true,
    allowSvmMessageSigning: true,
    svmAllowTo: [],
    svmMaxLamports: 0n,
    typedDataVerifyingContracts: [],
    typedDataPrimaryTypes: [],
    requireConfirmAboveWei: 0n,
  };
  ok(isAllow(evaluate({ kind: 'message', messageBytes: Buffer.from('hi') }, p)));
  ok(isAllow(evaluate({ kind: 'typed_data', typedData: {} as TypedData }, p)));
});

test('confirm: summary renders 0.5 ETH cleanly', () => {
  const p: Policy = {
    mode: 'permissive',
    chainIds: [],
    allowTo: [],
    maxValueWei: 0n,
    allowedSelectors: [],
    allowContractCreation: true,
    allowMessageSigning: true,
    allowTypedData: true,
    allowSvmMessageSigning: true,
    svmAllowTo: [],
    svmMaxLamports: 0n,
    typedDataVerifyingContracts: [],
    typedDataPrimaryTypes: [],
    requireConfirmAboveWei: 0n,
  };
  const r = evaluate(txReq(tx({ value: 500_000_000_000_000_000n })), p);
  ok(/^0\.5 ETH /.test(confirmSummary(r)));
});

test('confirm: summary renders whole-ETH amounts without a decimal', () => {
  const p: Policy = {
    mode: 'permissive',
    chainIds: [],
    allowTo: [],
    maxValueWei: 0n,
    allowedSelectors: [],
    allowContractCreation: true,
    allowMessageSigning: true,
    allowTypedData: true,
    allowSvmMessageSigning: true,
    svmAllowTo: [],
    svmMaxLamports: 0n,
    typedDataVerifyingContracts: [],
    typedDataPrimaryTypes: [],
    requireConfirmAboveWei: 0n,
  };
  const r = evaluate(txReq(tx({ value: 1_000_000_000_000_000_000n })), p);
  ok(/^1 ETH /.test(confirmSummary(r)));
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
  const transferData = ('0xa9059cbb' + '00'.repeat(64)) as `0x${string}`;
  const approveData = ('0x095ea7b3' + '00'.repeat(64)) as `0x${string}`;
  ok(isAllow(evaluate(txReq(tx({ data: transferData, value: 0n })), p)));
  ok(!isAllow(evaluate(txReq(tx({ data: '0x', value: 1n })), p)));
  ok(!isAllow(evaluate(txReq(tx({ data: approveData, value: 0n })), p)));
  ok(!isAllow(evaluate(txReq(tx({ data: transferData, value: 0n, chainId: 137n })), p)));
});

test('end-to-end: parse + evaluate a deploy-enabled policy', () => {
  const source = `
    mode = "strict"
    chain_ids = [1]
    allow_contract_creation = true
  `;
  const p = parsePolicy(source);
  const initcode = ('0x6080604052' + '00'.repeat(100)) as `0x${string}`;
  // Deploy → confirm, never plain allow.
  const deploy = evaluate(txReq(tx({ to: null, data: initcode })), p);
  equal(deploy.kind, 'confirm');
  // The toggle doesn't loosen anything else: a normal call is still denied
  // by the (empty) allow_to list.
  const call = evaluate(txReq(tx({ data: '0x', value: 0n })), p);
  equal(call.kind, 'deny');
  // Wrong chain still denies the deploy itself.
  equal(evaluate(txReq(tx({ to: null, data: initcode, chainId: 137n })), p).kind, 'deny');
});

// ---------------------------------------------------------------------------
// EIP-712 domain / primary-type allowlists (strict mode)
// ---------------------------------------------------------------------------

const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3';

function td(over: Partial<TypedData> = {}, domain: TypedData['domain'] = {}): TypedData {
  return {
    types: { Permit: [{ name: 'owner', type: 'address' }] },
    primaryType: 'Permit',
    domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2, ...domain },
    message: { owner: DEAD },
    ...over,
  };
}

function tdReq(t: TypedData): PolicyRequest {
  return { kind: 'typed_data', typedData: t };
}

test('typed data: allow_typed_data=false denies before any domain check', () => {
  const r = denyReason(evaluate(tdReq(td()), strict({ allowTypedData: false })));
  ok(/allow_typed_data=false/.test(r));
});

test('typed data: empty allowlists + allowed = unrestricted (backwards compatible)', () => {
  ok(isAllow(evaluate(tdReq(td()), strict({ allowTypedData: true }))));
  ok(
    isAllow(
      evaluate(
        tdReq(td({ primaryType: 'Anything' }, { verifyingContract: DEAD })),
        strict({ allowTypedData: true }),
      ),
    ),
  );
});

test('typed data: domain.chainId must be in chain_ids when present', () => {
  const p = strict({ allowTypedData: true, chainIds: [1, 8453] });
  ok(isAllow(evaluate(tdReq(td({}, { chainId: 8453 })), p)));
  ok(isAllow(evaluate(tdReq(td({}, { chainId: 1n })), p)), 'bigint chainId');
  const r = denyReason(evaluate(tdReq(td({}, { chainId: 137 })), p));
  ok(/domain\.chainId 137 not in chain_ids/.test(r), r);
});

test('typed data: a domain without chainId is not chain-bound and passes', () => {
  const p = strict({ allowTypedData: true, chainIds: [1] });
  const noChain = td();
  delete (noChain.domain as { chainId?: unknown }).chainId;
  ok(isAllow(evaluate(tdReq(noChain), p)));
});

test('typed data: a non-integer chainId is denied, not thrown', () => {
  const p = strict({ allowTypedData: true });
  const weird = td({}, { chainId: '1' as unknown as number });
  ok(/domain\.chainId/.test(denyReason(evaluate(tdReq(weird), p))));
});

test('typed data: verifyingContract allowlist is enforced, case-insensitively, when set', () => {
  const p = strict({ allowTypedData: true, typedDataVerifyingContracts: [PERMIT2] });
  ok(isAllow(evaluate(tdReq(td()), p)));
  ok(
    isAllow(
      evaluate(
        tdReq(
          td({}, { verifyingContract: PERMIT2.toUpperCase().replace('0X', '0x') as `0x${string}` }),
        ),
        p,
      ),
    ),
  );
  ok(
    /verifyingContract 0x0000…dead|verifyingContract 0x000000000000000000000000000000000000dead/.test(
      denyReason(evaluate(tdReq(td({}, { verifyingContract: DEAD })), p)),
    ),
  );
  const absent = td();
  delete (absent.domain as { verifyingContract?: unknown }).verifyingContract;
  ok(/verifyingContract \(absent\)/.test(denyReason(evaluate(tdReq(absent), p))));
});

test('typed data: primaryType allowlist is enforced when set', () => {
  const p = strict({ allowTypedData: true, typedDataPrimaryTypes: ['Permit', 'Order'] });
  ok(isAllow(evaluate(tdReq(td({ primaryType: 'Order' })), p)));
  ok(
    /primaryType Mail not in typed_data_primary_types/.test(
      denyReason(evaluate(tdReq(td({ primaryType: 'Mail' })), p)),
    ),
  );
  const missing = td();
  delete (missing as { primaryType?: unknown }).primaryType;
  ok(/primaryType \(absent\)/.test(denyReason(evaluate(tdReq(missing), p))));
});

test('typed data: checks run in order chain → contract → type', () => {
  const p = strict({
    allowTypedData: true,
    typedDataVerifyingContracts: [DEAD],
    typedDataPrimaryTypes: ['X'],
  });
  ok(/chainId/.test(denyReason(evaluate(tdReq(td({ primaryType: 'Y' }, { chainId: 2 })), p))));
  ok(/verifyingContract/.test(denyReason(evaluate(tdReq(td({ primaryType: 'Y' })), p))));
  ok(
    /primaryType/.test(
      denyReason(evaluate(tdReq(td({ primaryType: 'Y' }, { verifyingContract: DEAD })), p)),
    ),
  );
});

test('typed data: a malformed domain (null / non-object) is denied when contracts are required, allowed when unrestricted', () => {
  const restricted = strict({ allowTypedData: true, typedDataVerifyingContracts: [PERMIT2] });
  const bad = td({ domain: null as unknown as TypedData['domain'] });
  ok(/verifyingContract \(absent\)/.test(denyReason(evaluate(tdReq(bad), restricted))));
  ok(isAllow(evaluate(tdReq(bad), strict({ allowTypedData: true }))));
});

test('typed data: permissive mode ignores the allowlists entirely', () => {
  const p: Policy = {
    ...strict({
      allowTypedData: true,
      typedDataVerifyingContracts: [DEAD],
      typedDataPrimaryTypes: ['X'],
    }),
    mode: 'permissive',
  };
  ok(isAllow(evaluate(tdReq(td({ primaryType: 'Y' }, { chainId: 999 })), p)));
});
