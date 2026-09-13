import type { SignableTx, TypedData } from '../eth/index.js';
import type { Policy, PolicyDecision, PolicyRequest, SvmTransferView } from './types.js';

/**
 * Pure evaluator. Returns Allow, Deny(reason), or ConfirmRequired(summary).
 *
 * The reason string is what the caller writes into the audit log and surfaces
 * as the RPC_POLICY_DENIED error message — write it for a human.
 *
 * Order of checks for transactions:
 *   1. strict-mode static deny rules (chain, contract creation, allow_to,
 *      value cap, selector) — an allowed contract creation short-circuits
 *      to a mandatory confirm here
 *   2. require_confirm_above_wei — independent of mode
 *   3. allow
 *
 * Step 2 runs even in permissive mode: if the user wrote a confirm threshold
 * into their TOML, honour it regardless of whether the rest of the file is
 * permissive. Personal_sign and EIP-712 don't carry a `value` field and so
 * never trigger the confirm path; that's tracked as a follow-up.
 */
export function evaluate(request: PolicyRequest, policy: Policy): PolicyDecision {
  if (policy.mode === 'permissive') {
    if (request.kind === 'transaction') {
      const confirm = confirmForTx(request.tx, policy);
      if (confirm) return confirm;
    }
    if (request.kind === 'svm_transaction') {
      const confirm = confirmForSvmTx(request, policy);
      if (confirm) return confirm;
    }
    return { kind: 'allow' };
  }
  switch (request.kind) {
    case 'transaction': {
      const decision = evaluateTransactionStrict(request.tx, policy);
      if (decision) return decision;
      const confirm = confirmForTx(request.tx, policy);
      if (confirm) return confirm;
      return { kind: 'allow' };
    }
    case 'message':
      return policy.allowMessageSigning
        ? { kind: 'allow' }
        : {
            kind: 'deny',
            reason: 'personal_sign denied — strict mode + allow_message_signing=false',
          };
    case 'typed_data': {
      if (!policy.allowTypedData) {
        return {
          kind: 'deny',
          reason: 'EIP-712 typed-data denied — strict mode + allow_typed_data=false',
        };
      }
      return evaluateTypedDataStrict(request.typedData, policy) ?? { kind: 'allow' };
    }
    case 'svm_message':
      return policy.allowSvmMessageSigning
        ? { kind: 'allow' }
        : {
            kind: 'deny',
            reason: 'svm message signing denied — strict mode + allow_svm_message_signing=false',
          };
    case 'svm_transaction': {
      const decision = evaluateSvmTxStrict(request, policy);
      if (decision) return decision;
      const confirm = confirmForSvmTx(request, policy);
      if (confirm) return confirm;
      return { kind: 'allow' };
    }
  }
}

/**
 * Strict-mode Solana transaction check. All-or-nothing decode:
 *   - if any instruction couldn't be decoded offline, we can't reason about
 *     what it does → route to a human confirm (NOT a silent allow);
 *   - otherwise every transfer's destination must be allowlisted and the
 *     total must be within the cap, else hard deny.
 * Returns a deny/confirm decision, or null when the static checks pass (the
 * caller then applies the value-based confirm threshold).
 */
function evaluateSvmTxStrict(
  req: Extract<PolicyRequest, { kind: 'svm_transaction' }>,
  policy: Policy,
): ({ kind: 'deny'; reason: string } | { kind: 'confirm'; summary: string }) | null {
  if (!req.allDecoded) {
    return {
      kind: 'confirm',
      summary: `unrecognized Solana tx — ${req.instructionCount} instruction${req.instructionCount === 1 ? '' : 's'}, contents not decodable offline`,
    };
  }
  let total = 0n;
  for (const t of req.transfers) {
    if (!policy.svmAllowTo.includes(t.to)) {
      return { kind: 'deny', reason: `svm tx denied — recipient ${t.to} not in svm_allow_to` };
    }
    total += t.lamports;
  }
  if (total > policy.svmMaxLamports) {
    return {
      kind: 'deny',
      reason: `svm tx denied — total ${total} lamports exceeds svm_max_lamports ${policy.svmMaxLamports}`,
    };
  }
  return null;
}

/**
 * If require_confirm_above_lamports is set and the total transferred exceeds
 * it, return a Confirm. Only sums the decoded transfers — in permissive mode
 * an undecoded tx contributes nothing here (permissive allows it outright).
 */
function confirmForSvmTx(
  req: Extract<PolicyRequest, { kind: 'svm_transaction' }>,
  policy: Policy,
): { kind: 'confirm'; summary: string } | null {
  if (policy.requireConfirmAboveLamports === undefined) return null;
  let total = 0n;
  for (const t of req.transfers) total += t.lamports;
  if (total <= policy.requireConfirmAboveLamports) return null;
  return { kind: 'confirm', summary: `${formatSol(total)} SOL → ${svmDest(req.transfers)}` };
}

function svmDest(transfers: readonly SvmTransferView[]): string {
  if (transfers.length === 1) return shortB58(transfers[0]!.to);
  return `${transfers.length} recipients`;
}

function shortB58(addr: string): string {
  return addr.length > 12 ? `${addr.slice(0, 4)}…${addr.slice(-4)}` : addr;
}

function formatSol(lamports: bigint): string {
  const LAMPORTS_PER_SOL = 1_000_000_000n;
  const whole = lamports / LAMPORTS_PER_SOL;
  const frac = lamports % LAMPORTS_PER_SOL;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(9, '0').slice(0, 6).replace(/0+$/, '');
  return fracStr === '' ? whole.toString() : `${whole}.${fracStr}`;
}

/**
 * Strict-mode static checks. Returns a Deny decision on the first failure,
 * a Confirm for an allowed contract creation, or `null` if everything passes
 * (the caller then runs the confirm check).
 */
function evaluateTransactionStrict(
  tx: SignableTx,
  policy: Policy,
): ({ kind: 'deny'; reason: string } | { kind: 'confirm'; summary: string }) | null {
  // 1. chain ID
  if (!policy.chainIds.includes(Number(tx.chainId))) {
    return {
      kind: 'deny',
      reason: `tx denied — chain ${tx.chainId} not in chain_ids ${JSON.stringify(policy.chainIds)}`,
    };
  }

  // 2. contract creation (to: null) — off by default. Initcode is arbitrary
  //    code, so there is no address or selector to allowlist; when enabled,
  //    a deploy still respects the value cap and ALWAYS routes to a human
  //    confirm rather than an unconditional allow.
  if (tx.to === null) {
    if (!policy.allowContractCreation) {
      return {
        kind: 'deny',
        reason: 'tx denied — contract creation not allowed (allow_contract_creation = false)',
      };
    }
    if (tx.value > policy.maxValueWei) {
      return {
        kind: 'deny',
        reason: `tx denied — value ${tx.value} wei exceeds max_value_wei ${policy.maxValueWei}`,
      };
    }
    return { kind: 'confirm', summary: txSummary(tx) };
  }

  // 3. destination allowlist (case-insensitive; allow_to is pre-lowercased)
  const to = tx.to.toLowerCase();
  if (!policy.allowTo.includes(to)) {
    return { kind: 'deny', reason: `tx denied — destination ${to} not in allow_to` };
  }

  // 4. per-tx value cap
  if (tx.value > policy.maxValueWei) {
    return {
      kind: 'deny',
      reason: `tx denied — value ${tx.value} wei exceeds max_value_wei ${policy.maxValueWei}`,
    };
  }

  // 5. function selector allowlist (only for txs with calldata)
  const dataHex = typeof tx.data === 'string' ? tx.data : '0x' + tx.data.toString('hex');
  if (dataHex.length > 2) {
    if (dataHex.length < 10) {
      return { kind: 'deny', reason: `tx denied — calldata too short to extract selector` };
    }
    const selector = dataHex.slice(0, 10).toLowerCase();
    if (!policy.allowedSelectors.includes(selector)) {
      return {
        kind: 'deny',
        reason: `tx denied — selector ${selector} not in allowed_selectors`,
      };
    }
  }

  return null;
}

/**
 * If require_confirm_above_wei is set and this tx exceeds it, return a
 * Confirm decision. Otherwise null.
 *
 * The summary is what the human sees on their phone. The destination is
 * shortened so the notification preview isn't dominated by hex.
 */
function confirmForTx(tx: SignableTx, policy: Policy): { kind: 'confirm'; summary: string } | null {
  if (policy.requireConfirmAboveWei === undefined) return null;
  const value = BigInt(tx.value);
  if (value <= policy.requireConfirmAboveWei) return null;
  return { kind: 'confirm', summary: txSummary(tx) };
}

/**
 * One-line description of a tx for the confirm push. A deploy has no
 * destination address, so it shows the initcode size instead — enough for
 * the human to sanity-check against the deploy they actually asked for.
 */
function txSummary(tx: SignableTx): string {
  const dest =
    tx.to === null ? `contract creation (${initcodeBytes(tx)}-byte initcode)` : shortAddr(tx.to);
  return `${formatWei(BigInt(tx.value))} ETH → ${dest} on chain ${BigInt(tx.chainId)}`;
}

function initcodeBytes(tx: SignableTx): number {
  const dataHex = typeof tx.data === 'string' ? tx.data : '0x' + tx.data.toString('hex');
  return (dataHex.length - 2) / 2;
}

function shortAddr(addr: string): string {
  const a = addr.toLowerCase();
  return a.length === 42 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

function formatWei(v: bigint): string {
  // Render with up to 6 fractional digits, trimming trailing zeros. The push
  // notification is a glance, not a settlement statement.
  const WEI_PER_ETH = 1_000_000_000_000_000_000n;
  const whole = v / WEI_PER_ETH;
  const frac = v % WEI_PER_ETH;
  if (frac === 0n) return whole.toString();
  const fracStr = frac.toString().padStart(18, '0').slice(0, 6).replace(/0+$/, '');
  return fracStr === '' ? whole.toString() : `${whole}.${fracStr}`;
}

/**
 * Strict-mode EIP-712 checks, applied once allow_typed_data has passed.
 * A typed-data signature can move funds (Permit, Permit2, exchange orders),
 * so the domain gets the same treatment a transaction's `to` does:
 *   1. domain.chainId must be present and in chain_ids — a signature for
 *      another chain is exactly the kind of thing an injected prompt asks
 *      for, and a chain-less domain can't be checked at all.
 *   2. domain.verifyingContract must be allowlisted when the list is set.
 *   3. primaryType must be allowlisted when the list is set.
 * Domain fields are read defensively: the evaluator runs before sign-typed.ts
 * validates the structure, and a malformed domain must deny, not throw.
 */
function evaluateTypedDataStrict(
  td: TypedData,
  policy: Policy,
): { kind: 'deny'; reason: string } | null {
  if (typeof td.domain !== 'object' || td.domain === null || Array.isArray(td.domain)) {
    return { kind: 'deny', reason: 'EIP-712 denied — domain must be an object' };
  }
  const domain = td.domain as unknown as Record<string, unknown>;
  const chainId = domain['chainId'];
  if (chainId === undefined) {
    // A chain-less domain can't be checked against chain_ids, and a
    // signature over one is valid wherever that domain is accepted. Strict
    // mode therefore requires the domain to be chain-bound.
    return {
      kind: 'deny',
      reason:
        'EIP-712 denied — strict mode requires domain.chainId (chain-less domains cannot be checked against chain_ids)',
    };
  }
  const id = exactChainId(chainId);
  if (id === null || !policy.chainIds.some((c) => BigInt(c) === id)) {
    return {
      kind: 'deny',
      reason: `EIP-712 denied — domain.chainId ${String(chainId)} not in chain_ids ${JSON.stringify(policy.chainIds)}`,
    };
  }
  if (policy.typedDataVerifyingContracts.length > 0) {
    const vc = domain['verifyingContract'];
    const norm = typeof vc === 'string' ? vc.toLowerCase() : undefined;
    if (norm === undefined || !policy.typedDataVerifyingContracts.includes(norm)) {
      return {
        kind: 'deny',
        reason: `EIP-712 denied — domain.verifyingContract ${norm ?? '(absent)'} not in typed_data_verifying_contracts`,
      };
    }
  }
  if (policy.typedDataPrimaryTypes.length > 0) {
    const pt = td.primaryType;
    if (typeof pt !== 'string' || !policy.typedDataPrimaryTypes.includes(pt)) {
      return {
        kind: 'deny',
        reason: `EIP-712 denied — primaryType ${typeof pt === 'string' ? pt : '(absent)'} not in typed_data_primary_types`,
      };
    }
  }
  return null;
}

/** Exact integer chain id as a bigint, or null if it isn't a safe integer / bigint. */
function exactChainId(v: unknown): bigint | null {
  if (typeof v === 'bigint') return v >= 0n ? v : null;
  if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  return null;
}
