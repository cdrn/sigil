import type { SignableTx } from '../eth/index.js';
import type { PaymentCandidate } from '../pay/types.js';
import type { Policy, PolicyDecision, PolicyRequest } from './types.js';

/**
 * Pure evaluator. Returns Allow, Deny(reason), or ConfirmRequired(summary).
 *
 * The reason string is what the caller writes into the audit log and surfaces
 * as the RPC_POLICY_DENIED error message — write it for a human.
 *
 * Order of checks for transactions:
 *   1. strict-mode static deny rules (chain, allow_to, value cap, selector)
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
    if (request.kind === 'payment') {
      const confirm = confirmForPayment(request.payment, policy);
      if (confirm) return confirm;
    }
    return { kind: 'allow' };
  }
  switch (request.kind) {
    case 'transaction': {
      const deny = evaluateTransactionStrict(request.tx, policy);
      if (deny) return deny;
      const confirm = confirmForTx(request.tx, policy);
      if (confirm) return confirm;
      return { kind: 'allow' };
    }
    case 'payment': {
      const deny = evaluatePaymentStrict(request.payment, policy);
      if (deny) return deny;
      const confirm = confirmForPayment(request.payment, policy);
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
    case 'typed_data':
      return policy.allowTypedData
        ? { kind: 'allow' }
        : {
            kind: 'deny',
            reason: 'EIP-712 typed-data denied — strict mode + allow_typed_data=false',
          };
  }
}

/**
 * Strict-mode static checks. Returns a Deny decision on the first failure, or
 * `null` if everything passes (the caller then runs the confirm check).
 */
function evaluateTransactionStrict(
  tx: SignableTx,
  policy: Policy,
): ({ kind: 'deny'; reason: string }) | null {
  // 1. chain ID
  if (!policy.chainIds.includes(Number(tx.chainId))) {
    return {
      kind: 'deny',
      reason: `tx denied — chain ${tx.chainId} not in chain_ids ${JSON.stringify(policy.chainIds)}`,
    };
  }

  // 2. contract creation (to: null) — denied by default; future "allow_contract_creation" toggle
  if (tx.to === null) {
    return { kind: 'deny', reason: 'tx denied — contract creation not allowed' };
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
  const dataHex = typeof tx.data === 'string' ? tx.data : ('0x' + tx.data.toString('hex'));
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
function confirmForTx(
  tx: SignableTx,
  policy: Policy,
): ({ kind: 'confirm'; summary: string }) | null {
  if (policy.requireConfirmAboveWei === undefined) return null;
  const value = BigInt(tx.value);
  if (value <= policy.requireConfirmAboveWei) return null;
  const dest = tx.to === null ? 'contract creation' : shortAddr(tx.to);
  return {
    kind: 'confirm',
    summary: `${formatWei(value)} ETH → ${dest} on chain ${BigInt(tx.chainId)}`,
  };
}

/**
 * Strict-mode checks for a sigil_pay candidate. Same shape as the tx rules:
 * first failure denies with a reason a human can act on. The origin check is
 * the load-bearing one — a payment challenge is only as trustworthy as the
 * server it came from, so strict mode requires the user to have named that
 * server in advance.
 */
function evaluatePaymentStrict(
  p: PaymentCandidate,
  policy: Policy,
): ({ kind: 'deny'; reason: string }) | null {
  if (policy.payOrigins.length === 0) {
    return {
      kind: 'deny',
      reason: 'payment denied — strict mode + empty pay_origins (add the origins you trust)',
    };
  }
  if (!policy.payOrigins.includes(p.origin.toLowerCase())) {
    return { kind: 'deny', reason: `payment denied — origin ${p.origin} not in pay_origins` };
  }
  if (policy.chainIds.length > 0 && !policy.chainIds.includes(p.chainId)) {
    return {
      kind: 'deny',
      reason: `payment denied — chain ${p.chainId} not in chain_ids ${JSON.stringify(policy.chainIds)}`,
    };
  }
  if (policy.payCurrencies.length > 0 && !policy.payCurrencies.includes(p.currency)) {
    return { kind: 'deny', reason: `payment denied — currency ${p.currency} not in pay_currencies` };
  }
  if (p.amount > policy.payMaxAmount) {
    return {
      kind: 'deny',
      reason: `payment denied — amount ${p.amount} base units exceeds pay_max_amount ${policy.payMaxAmount}`,
    };
  }
  return null;
}

function confirmForPayment(
  p: PaymentCandidate,
  policy: Policy,
): ({ kind: 'confirm'; summary: string }) | null {
  if (policy.payRequireConfirmAbove === undefined) return null;
  if (p.amount <= policy.payRequireConfirmAbove) return null;
  return {
    kind: 'confirm',
    summary: `pay ${p.amount} base units of ${shortAddr(p.currency)} → ${shortAddr(p.recipient)} via ${p.protocol} at ${p.origin}`,
  };
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
