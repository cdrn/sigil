import type { SignableTx } from '../eth/index.js';
import type { Policy, PolicyDecision, PolicyRequest } from './types.js';

/**
 * Pure evaluator. Takes a (request, policy), returns Allow or Deny(reason).
 *
 * The reason string is what the caller writes into the audit log and surfaces
 * as the RPC_POLICY_DENIED error message — write it for a human.
 *
 * Permissive mode short-circuits to Allow for everything. Strict mode walks
 * the rules in a fixed order and returns the first failing one — the order
 * doesn't matter for correctness, only for which reason the user sees first.
 */
export function evaluate(request: PolicyRequest, policy: Policy): PolicyDecision {
  if (policy.mode === 'permissive') return { allow: true };
  switch (request.kind) {
    case 'transaction':
      return evaluateTransaction(request.tx, policy);
    case 'message':
      return policy.allowMessageSigning
        ? { allow: true }
        : {
            allow: false,
            reason: 'personal_sign denied — strict mode + allow_message_signing=false',
          };
    case 'typed_data':
      return policy.allowTypedData
        ? { allow: true }
        : {
            allow: false,
            reason: 'EIP-712 typed-data denied — strict mode + allow_typed_data=false',
          };
  }
}

function evaluateTransaction(tx: SignableTx, policy: Policy): PolicyDecision {
  // 1. chain ID
  if (!policy.chainIds.includes(Number(tx.chainId))) {
    return {
      allow: false,
      reason: `tx denied — chain ${tx.chainId} not in chain_ids ${JSON.stringify(policy.chainIds)}`,
    };
  }

  // 2. contract creation (to: null) — denied by default; future "allow_contract_creation" toggle
  if (tx.to === null) {
    return { allow: false, reason: 'tx denied — contract creation not allowed' };
  }

  // 3. destination allowlist (case-insensitive; allow_to is pre-lowercased)
  const to = tx.to.toLowerCase();
  if (!policy.allowTo.includes(to)) {
    return { allow: false, reason: `tx denied — destination ${to} not in allow_to` };
  }

  // 4. per-tx value cap
  if (tx.value > policy.maxValueWei) {
    return {
      allow: false,
      reason: `tx denied — value ${tx.value} wei exceeds max_value_wei ${policy.maxValueWei}`,
    };
  }

  // 5. function selector allowlist (only for txs with calldata)
  const dataHex = typeof tx.data === 'string' ? tx.data : ('0x' + tx.data.toString('hex'));
  if (dataHex.length > 2) {
    if (dataHex.length < 10) {
      return { allow: false, reason: `tx denied — calldata too short to extract selector` };
    }
    const selector = dataHex.slice(0, 10).toLowerCase();
    if (!policy.allowedSelectors.includes(selector)) {
      return {
        allow: false,
        reason: `tx denied — selector ${selector} not in allowed_selectors`,
      };
    }
  }

  return { allow: true };
}
