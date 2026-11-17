import { type AuditPreview, type AuditWriter } from '../audit/index.js';
import type { ConfirmGate } from '../confirm/index.js';
import {
  type Eip1559Tx,
  type Hex,
  type LegacyTx,
  personalSign,
  type SignableTx,
  signTransaction,
  signTypedData,
  type TypedData,
} from '../eth/index.js';
import {
  checkWindowCaps,
  evaluate,
  type Policy,
  PolicyLoadError,
  type PolicyRequest,
  type PolicyResolver,
  type SpendAsset,
  type SpendLedger,
  SpendLedgerError,
  windowCapsFor,
} from '../policy/index.js';
import {
  base58Encode,
  decodeTx,
  getPublicKey as svmGetPublicKey,
  sign as svmSign,
} from '../svm/index.js';
import { SecretBufferDisposedError } from '../crypto/index.js';
import {
  AbiRegistry,
  auditPreview,
  buildTxPreview,
  jsonSafe,
  previewFailure,
  type TxPreview,
} from '../preview/index.js';
import type { JsonRpcUpstream } from '../rpc/upstream.js';
import { type HandleTable } from './handles.js';

const MAX_UINT256 = (1n << 256n) - 1n;
/** Decimal digits in 2^256−1; longer strings are rejected before BigInt parses them. */
const MAX_UINT256_DIGITS = 78;

// Error codes — these match JSON-RPC 2.0 standard error codes plus a
// sigil-specific range (-32000..-32099). They flow through the MCP wire
// unchanged so the client sees the exact diagnosis.
export const RPC_INVALID_PARAMS = -32602;
export const RPC_METHOD_NOT_FOUND = -32601;
// Sigil-specific:
export const RPC_PORTAL_NOT_FOUND = -32000;
export const RPC_POLICY_DENIED = -32001;
export const RPC_INVALID_PAYLOAD = -32002;
export const RPC_DAEMON_LOCKED = -32003;

export class RpcMethodError extends Error {
  readonly code: number;
  readonly data: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = 'RpcMethodError';
    this.code = code;
    this.data = data;
  }
}

export interface MethodContext {
  handles: HandleTable;
  audit: AuditWriter;
  /**
   * Resolves the per-portal policy at evaluation time. Wrapped in an
   * interface so tests can inject a constant policy without touching the
   * filesystem.
   */
  policy: PolicyResolver;
  /**
   * Out-of-band confirm gate. Optional: only consulted when the policy
   * evaluator returns a `confirm` decision (today, only sign_transaction
   * can trigger this). When undefined, a confirm decision becomes a hard
   * deny — fail closed.
   */
  confirm?: ConfirmGate;
  /**
   * Per-portal spend ledger backing the rolling-window value caps
   * (max_value_per_hour_wei etc.). Optional so tests can omit it; a policy
   * that sets a window cap while no ledger is configured is a hard deny —
   * fail closed, never silently uncapped.
   */
  ledger?: SpendLedger;
  /**
   * Transaction preview (decode + simulate) for EVM transactions. Optional:
   * when undefined, sign_transaction still decodes calldata against the
   * built-in registry (no RPC needed) and reports the simulation as
   * skipped — so require_simulation in a policy denies, fail closed.
   */
  preview?: PreviewContext;
}

export interface PreviewContext {
  /** User ABIs from ~/.sigil/abi, loaded once at boot. */
  registry: AbiRegistry;
  /**
   * The node that dry-runs transactions for a chain, or undefined when none
   * is configured. May resolve asynchronously (the [rpc] proxy upstream's
   * chain is looked up on first use); must not reject.
   */
  simulatorFor(chainId: bigint): JsonRpcUpstream | undefined | Promise<JsonRpcUpstream | undefined>;
  /** Per-RPC-call timeout; the preview as a whole is bounded at ~2×. */
  timeoutMs?: number;
}

export type MethodHandler = (params: unknown, ctx: MethodContext) => unknown | Promise<unknown>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function asObject(params: unknown, methodName: string): Record<string, unknown> {
  if (typeof params !== 'object' || params === null || Array.isArray(params)) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `${methodName}: params must be an object`);
  }
  return params as Record<string, unknown>;
}

function asString(obj: Record<string, unknown>, key: string, methodName: string): string {
  const v = obj[key];
  if (typeof v !== 'string') {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `${methodName}: ${key} must be a string`);
  }
  return v;
}

function hexToBuf(s: string, methodName: string, key: string): Buffer {
  if (!/^0x[0-9a-fA-F]*$/.test(s)) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `${methodName}: ${key} must be 0x-prefixed hex`);
  }
  return Buffer.from(s.slice(2), 'hex');
}

/** Decode a base64 byte payload, rejecting anything that isn't valid base64. */
function b64ToBuf(s: string, methodName: string, key: string): Buffer {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `${methodName}: ${key} must be base64`);
  }
  const buf = Buffer.from(s, 'base64');
  // Buffer.from is lenient (drops stray chars); re-encode to confirm a clean round-trip.
  if (buf.toString('base64').replace(/=+$/, '') !== s.replace(/=+$/, '')) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `${methodName}: ${key} is not valid base64`);
  }
  return buf;
}

function requirePortal(handles: HandleTable, handle: string): Buffer {
  if (!handles.isUnlocked()) {
    throw new RpcMethodError(
      RPC_DAEMON_LOCKED,
      'sigil is locked — run "sigil unlock" in a terminal to load keys',
    );
  }
  const sb = handles.get(handle);
  if (!sb) {
    throw new RpcMethodError(RPC_PORTAL_NOT_FOUND, `portal "${handle}" not found`);
  }
  try {
    return sb.bytes();
  } catch (err) {
    if (err instanceof SecretBufferDisposedError) {
      throw new RpcMethodError(
        RPC_DAEMON_LOCKED,
        'sigil locked or shutting down while this request was in flight — refusing to sign',
      );
    }
    throw err;
  }
}

/**
 * Resolve the portal's policy and evaluate the request. On Deny — or on any
 * PolicyLoadError (missing file, malformed TOML) — appends a deny entry to
 * the audit log AND throws RPC_POLICY_DENIED. Returns silently on Allow.
 *
 * The order is: require unlocked + portal first, then policy. That way the
 * caller's mistakes (wrong handle, daemon locked) error before we touch the
 * policy file at all.
 */
/**
 * Result of the policy gate:
 *   - 'allow': caller proceeds to sign.
 *   - 'confirm': caller must run the OOB confirm flow before signing; the
 *     audit entry for the request will be appended by the caller after the
 *     confirm decision resolves.
 *
 * Deny is not returned: gatePolicy throws RPC_POLICY_DENIED directly.
 */
type GateResult =
  { proceed: 'allow'; policy: Policy } | { proceed: 'confirm'; summary: string; policy: Policy };

/** The native value a request would add to the portal's rolling windows. */
interface Spend {
  asset: SpendAsset;
  amount: bigint;
  /** False when part of the debit is unknown (undecodable Solana instruction). */
  bounded?: boolean;
}

function spendOf(request: PolicyRequest): Spend | null {
  if (request.kind === 'transaction') return { asset: 'wei', amount: BigInt(request.tx.value) };
  if (request.kind === 'svm_transaction') {
    let total = 0n;
    for (const t of request.transfers) total += t.lamports;
    return { asset: 'lamports', amount: total, bounded: request.allDecoded };
  }
  return null;
}

function looksLikeSvmTransaction(bytes: Buffer): boolean {
  try {
    decodeTx(bytes);
    return true;
  } catch {
    return false;
  }
}

const UNBOUNDED_REASON =
  'tx denied — rolling-window lamport caps are set but this transaction has an instruction sigil ' +
  'cannot decode, so its native SOL debit cannot be bounded (only System-Program transfers count)';

/**
 * Rolling-window pre-check, run before any confirm push so a human isn't
 * asked to approve something the cap would deny anyway. Read-only: the
 * authoritative check-and-record happens in reserveSpend, right before
 * signing. Returns a deny reason or null.
 */
function windowPrecheck(
  ctx: MethodContext,
  handle: string,
  policy: Policy,
  spend: Spend,
): string | null {
  const caps = windowCapsFor(policy, spend.asset);
  if (caps.length === 0) return null;
  if (spend.bounded === false) return UNBOUNDED_REASON;
  if (!ctx.ledger) {
    return 'policy sets rolling-window value caps but no spend ledger is configured — refusing to sign';
  }
  const ledger = ctx.ledger;
  try {
    const reason = checkWindowCaps(
      caps,
      spend.amount,
      (w) => ledger.spent(handle, spend.asset, w),
      spend.asset,
    );
    return reason === null ? null : `tx ${reason}`;
  } catch (err) {
    if (err instanceof SpendLedgerError) return err.message;
    throw err;
  }
}

/**
 * Atomically check the rolling-window caps against the ledger and record
 * this spend. Called after the policy gate and any confirm have passed,
 * immediately before the signature is produced, so two windows racing for
 * the last of an allowance can't both get it. On breach: audit a deny and
 * throw RPC_POLICY_DENIED.
 */
function reserveSpend(
  ctx: MethodContext,
  handle: string,
  kind: string,
  payload: unknown,
  policy: Policy,
  spend: Spend,
  preview?: AuditPreview,
): void {
  const caps = windowCapsFor(policy, spend.asset);
  if (caps.length === 0) return;
  let reason: string | null;
  if (spend.bounded === false) {
    reason = UNBOUNDED_REASON;
  } else if (!ctx.ledger) {
    reason =
      'policy sets rolling-window value caps but no spend ledger is configured — refusing to sign';
  } else {
    try {
      const r = ctx.ledger.reserve(handle, spend.asset, spend.amount, caps);
      reason = r === null ? null : `tx ${r}`;
    } catch (err) {
      if (!(err instanceof SpendLedgerError)) throw err;
      reason = err.message;
    }
  }
  if (reason === null) return;
  ctx.audit.append({
    kind,
    portal: handle,
    payload,
    decision: 'deny',
    reason,
    ...(preview ? { preview } : {}),
  });
  throw new RpcMethodError(RPC_POLICY_DENIED, reason);
}

function gatePolicy(
  ctx: MethodContext,
  handle: string,
  kind: string,
  payload: unknown,
  request: PolicyRequest,
): GateResult {
  let reason: string;
  try {
    const policy = ctx.policy.resolve(handle);
    const decision = evaluate(request, policy);
    if (decision.kind !== 'deny') {
      const spend = spendOf(request);
      const windowReason = spend ? windowPrecheck(ctx, handle, policy, spend) : null;
      if (windowReason === null) {
        return decision.kind === 'allow'
          ? { proceed: 'allow', policy }
          : { proceed: 'confirm', summary: decision.summary, policy };
      }
      reason = windowReason;
    } else {
      reason = decision.reason;
    }
  } catch (err) {
    if (err instanceof PolicyLoadError) {
      reason = err.message;
    } else {
      throw err;
    }
  }
  ctx.audit.append({ kind, portal: handle, payload, decision: 'deny', reason });
  throw new RpcMethodError(RPC_POLICY_DENIED, reason);
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

const sigil_list_portals: MethodHandler = (_params, ctx) => {
  return { portals: ctx.handles.list() };
};

const sigil_eth_sign_message: MethodHandler = (params, ctx) => {
  const obj = asObject(params, 'eth_sign_message');
  const portal = asString(obj, 'portal', 'eth_sign_message');
  const messageHex = asString(obj, 'message', 'eth_sign_message');
  const message = hexToBuf(messageHex, 'eth_sign_message', 'message');
  const priv = requirePortal(ctx.handles, portal);
  gatePolicy(
    ctx,
    portal,
    'eth_sign_message',
    { message: messageHex },
    {
      kind: 'message',
      messageBytes: message,
    },
  );
  const sig = personalSign(message, priv);
  const sigHex = ('0x' + sig.toString('hex')) as Hex;
  ctx.audit.append({
    kind: 'eth_sign_message',
    portal,
    payload: { message: messageHex },
    decision: 'allow',
    sig: sigHex,
  });
  return { signature: sigHex };
};

function asTx(obj: Record<string, unknown>): SignableTx {
  const type = obj['type'];
  if (type !== 'legacy' && type !== 'eip1559') {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: type must be "legacy" or "eip1559"`);
  }

  const num = (key: string): bigint => {
    const v = obj[key];
    if (typeof v === 'string') {
      // Bound the input before BigInt sees it: a 0x prefix plus 64 hex
      // digits or 78 decimal digits covers every uint256.
      if (v.length > MAX_UINT256_DIGITS + 2) {
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: ${key} exceeds uint256`);
      }
      let n: bigint;
      try {
        n = BigInt(v);
      } catch {
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: ${key} not a valid bigint string`);
      }
      if (n < 0n) {
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: ${key} must be a non-negative integer`);
      }
      // Every tx field is at most a uint256 on the wire; anything wider is
      // garbage that would otherwise reach RLP encoding and the formatters.
      if (n > MAX_UINT256) {
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: ${key} exceeds uint256`);
      }
      return n;
    }
    if (typeof v === 'number') {
      if (!Number.isInteger(v) || v < 0) {
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: ${key} must be a non-negative integer`);
      }
      // A JSON number above 2^53 has already lost precision (1e100 is an
      // "integer" to JS but not the value anyone typed) and would skip the
      // uint256 bound the string path enforces.
      if (!Number.isSafeInteger(v)) {
        throw new RpcMethodError(
          RPC_INVALID_PARAMS,
          `tx: ${key} is not a safe integer — use a decimal string for values above 2^53`,
        );
      }
      return BigInt(v);
    }
    throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: ${key} must be number or decimal string`);
  };

  const to = obj['to'];
  if (to !== null && typeof to !== 'string') {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: to must be 0x address or null`);
  }
  if (typeof to === 'string' && !/^0x[0-9a-fA-F]{40}$/.test(to)) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: to must be 0x-prefixed 20-byte address`);
  }

  const data = obj['data'];
  if (typeof data !== 'string' || !/^0x[0-9a-fA-F]*$/.test(data)) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: data must be 0x-prefixed hex`);
  }

  if (type === 'legacy') {
    const tx: LegacyTx = {
      type: 'legacy',
      chainId: num('chainId'),
      nonce: num('nonce'),
      gasPrice: num('gasPrice'),
      gasLimit: num('gasLimit'),
      to: to as `0x${string}` | null,
      value: num('value'),
      data: data as `0x${string}`,
    };
    return tx;
  }
  // eip1559
  const accessListRaw = obj['accessList'];
  let accessList: Eip1559Tx['accessList'];
  if (accessListRaw === undefined) {
    accessList = [];
  } else if (Array.isArray(accessListRaw)) {
    accessList = accessListRaw.map((item, i) => {
      if (typeof item !== 'object' || item === null || Array.isArray(item)) {
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: accessList[${i}] must be object`);
      }
      const it = item as Record<string, unknown>;
      const addr = it['address'];
      const keys = it['storageKeys'];
      if (typeof addr !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(addr)) {
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: accessList[${i}].address`);
      }
      if (!Array.isArray(keys)) {
        throw new RpcMethodError(
          RPC_INVALID_PARAMS,
          `tx: accessList[${i}].storageKeys must be array`,
        );
      }
      for (const k of keys) {
        if (typeof k !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(k)) {
          throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: accessList[${i}].storageKeys[*]`);
        }
      }
      return { address: addr as `0x${string}`, storageKeys: keys as `0x${string}`[] };
    });
  } else {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: accessList must be array or omitted`);
  }
  const tx: Eip1559Tx = {
    type: 'eip1559',
    chainId: num('chainId'),
    nonce: num('nonce'),
    maxPriorityFeePerGas: num('maxPriorityFeePerGas'),
    maxFeePerGas: num('maxFeePerGas'),
    gasLimit: num('gasLimit'),
    to: to as `0x${string}` | null,
    value: num('value'),
    data: data as `0x${string}`,
    accessList,
  };
  return tx;
}

const sigil_eth_sign_transaction: MethodHandler = async (params, ctx) => {
  const obj = asObject(params, 'eth_sign_transaction');
  const portal = asString(obj, 'portal', 'eth_sign_transaction');
  const txObj = obj['tx'];
  if (typeof txObj !== 'object' || txObj === null || Array.isArray(txObj)) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, 'eth_sign_transaction: tx must be an object');
  }
  const tx = asTx(txObj as Record<string, unknown>);
  requirePortal(ctx.handles, portal); // locked / unknown portal errors before policy
  const kind = 'eth_sign_transaction';
  const payload = { tx: txObj };
  // Static policy first: a tx the policy denies outright never reaches the
  // simulation node.
  const gate = gatePolicy(ctx, portal, kind, payload, { kind: 'transaction', tx });

  const preview = await previewFor(ctx, portal, tx);
  const audited = auditPreview(preview);
  const previewDeny = previewGateReason(gate.policy, preview);
  if (previewDeny !== null) {
    ctx.audit.append({
      kind,
      portal,
      payload,
      decision: 'deny',
      reason: previewDeny,
      preview: audited,
    });
    throw new RpcMethodError(RPC_POLICY_DENIED, previewDeny, { preview: preview.text });
  }

  if (gate.proceed === 'confirm') {
    // The human sees the policy's one-liner, then what the tx actually does.
    const summary = [
      gate.summary,
      preview.headline,
      ...preview.warnings.slice(0, 3).map((w) => `⚠ ${w}`),
    ].join('\n');
    await runConfirmGate(ctx, portal, kind, payload, summary, audited);
  }
  // Re-acquire the key AFTER any confirm: the daemon may have locked or begun
  // shutting down (keys zeroized) while the human was deciding. A stale
  // buffer captured earlier would be all zeros by now. Nothing is reserved
  // or signed on a key that is no longer live.
  const priv = requirePortal(ctx.handles, portal);
  reserveSpend(
    ctx,
    portal,
    kind,
    payload,
    gate.policy,
    { asset: 'wei', amount: BigInt(tx.value) },
    audited,
  );
  const signed = signTransaction(tx, priv);
  ctx.audit.append({ kind, portal, payload, decision: 'allow', sig: signed, preview: audited });
  return { signed, preview: preview.text };
};

/**
 * Read-only twin of sign_transaction: the same decode + simulation, with no
 * policy gate, no confirm, no audit entry and no signature. Requires an
 * unlocked portal only because the simulation runs *as* the portal's
 * address (balances, allowances and msg.sender all depend on it).
 */
const sigil_eth_preview_transaction: MethodHandler = async (params, ctx) => {
  const obj = asObject(params, 'eth_preview_transaction');
  const portal = asString(obj, 'portal', 'eth_preview_transaction');
  const txObj = obj['tx'];
  if (typeof txObj !== 'object' || txObj === null || Array.isArray(txObj)) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, 'eth_preview_transaction: tx must be an object');
  }
  const tx = asTx(txObj as Record<string, unknown>);
  requirePortal(ctx.handles, portal);
  const p = await previewFor(ctx, portal, tx);
  return {
    preview: p.text,
    headline: p.headline,
    warnings: p.warnings,
    decoded: p.decoded,
    simulation: jsonSafe(p.simulation),
  };
};

/**
 * Build the preview for a parsed tx. Never throws for presentation
 * failures: a simulator that can't be resolved is "skipped", a node that
 * fails is "unavailable" (inside buildTxPreview), and an unexpected bug in
 * the preview code becomes previewFailure — loud, and denied by
 * require_simulation, but not by itself a reason to refuse a sign.
 */
async function previewFor(ctx: MethodContext, portal: string, tx: SignableTx): Promise<TxPreview> {
  const info = ctx.handles.info(portal);
  if (!info) throw new RpcMethodError(RPC_PORTAL_NOT_FOUND, `portal "${portal}" not found`);
  const p = ctx.preview;
  const chainId = BigInt(tx.chainId);
  let simulator: JsonRpcUpstream | undefined;
  let skippedReason: string | undefined;
  if (p) {
    try {
      simulator = await p.simulatorFor(chainId);
    } catch (err) {
      skippedReason = `simulation RPC for chain ${chainId} unavailable: ${(err as Error).message}`;
    }
  }
  try {
    return await buildTxPreview({
      tx,
      from: info.address,
      registry: p?.registry ?? AbiRegistry.empty(),
      ...(simulator ? { simulator } : {}),
      ...(skippedReason !== undefined ? { skippedReason } : {}),
      ...(p?.timeoutMs !== undefined ? { timeoutMs: p.timeoutMs } : {}),
    });
  } catch (err) {
    return previewFailure((err as Error).message);
  }
}

/**
 * The two preview-driven policy rules. Returns a deny reason or null.
 *   - require_simulation: a tx that was not simulated (no RPC for its
 *     chain, node unavailable, preview failure) is denied — fail closed.
 *   - sign_on_revert = false (default): a simulated revert is denied with
 *     the revert reason. Only applies when a simulation actually ran.
 */
function previewGateReason(policy: Policy, preview: TxPreview): string | null {
  const sim = preview.simulation;
  if (policy.requireSimulation) {
    if (sim.status === 'skipped') {
      return `tx denied — require_simulation = true but the tx could not be simulated: ${sim.reason}`;
    }
    if (sim.status === 'unavailable') {
      return `tx denied — require_simulation = true but the simulation was unavailable: ${sim.reason}`;
    }
    if (!sim.faithful) {
      return 'tx denied — require_simulation = true but the node could only simulate without the fee fields';
    }
  }
  if (sim.status === 'reverted' && !policy.signOnRevert) {
    return (
      `tx denied — simulation reverted: ${sim.revertReason ?? 'unknown reason'} ` +
      `(set sign_on_revert = true in the policy to sign anyway)`
    );
  }
  return null;
}

/**
 * The confirm half of the sign path. Pulled out so each sign method that
 * eventually opts in (today: sign_transaction; later: sign_typed_data with
 * a separate toggle) reuses the same audit + error semantics.
 *
 * If the gate is not configured, this is a hard deny — the sign request
 * cannot be honoured under the policy in force, so we refuse rather than
 * silently ignore the confirm requirement.
 *
 * Approve: returns silently, sign proceeds.
 * Deny / timeout / transport_error: audit a deny + throw POLICY_DENIED.
 */
async function runConfirmGate(
  ctx: MethodContext,
  portal: string,
  kind: string,
  payload: unknown,
  summary: string,
  preview?: AuditPreview,
): Promise<void> {
  const withPreview = preview ? { preview } : {};
  if (!ctx.confirm) {
    const reason =
      'policy requires out-of-band confirmation, but no confirm transport ' +
      'is configured — add a [confirm.ntfy] block to ~/.sigil/config.toml';
    ctx.audit.append({ kind, portal, payload, decision: 'deny', reason, ...withPreview });
    throw new RpcMethodError(RPC_POLICY_DENIED, reason);
  }
  const decision = await ctx.confirm.request({ portal, summary });
  if (decision.kind === 'approved') return;
  const reason =
    decision.kind === 'denied'
      ? `confirm denied by human (transport=${ctx.confirm.transportName})`
      : decision.kind === 'timeout'
        ? `confirm timed out — no ack within window (transport=${ctx.confirm.transportName})`
        : `confirm transport error: ${decision.message}`;
  ctx.audit.append({ kind, portal, payload, decision: 'deny', reason, ...withPreview });
  throw new RpcMethodError(RPC_POLICY_DENIED, reason);
}

const sigil_eth_sign_typed_data: MethodHandler = (params, ctx) => {
  const obj = asObject(params, 'eth_sign_typed_data');
  const portal = asString(obj, 'portal', 'eth_sign_typed_data');
  const td = obj['typedData'];
  if (typeof td !== 'object' || td === null || Array.isArray(td)) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, 'eth_sign_typed_data: typedData must be object');
  }
  // We trust the typed-data shape minimally — sign-typed.ts will throw
  // on missing fields; we wrap that as INVALID_PARAMS for the caller.
  const priv = requirePortal(ctx.handles, portal);
  gatePolicy(
    ctx,
    portal,
    'eth_sign_typed_data',
    { typedData: td },
    {
      kind: 'typed_data',
      typedData: td as TypedData,
    },
  );
  let sig: Buffer;
  try {
    sig = signTypedData(td as TypedData, priv);
  } catch (err) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, `eth_sign_typed_data: ${(err as Error).message}`);
  }
  const sigHex = ('0x' + sig.toString('hex')) as Hex;
  ctx.audit.append({
    kind: 'eth_sign_typed_data',
    portal,
    payload: { typedData: td },
    decision: 'allow',
    sig: sigHex,
  });
  return { signature: sigHex };
};

// ---------------------------------------------------------------------------
// Solana (SVM) — same secret, ed25519 key. Byte payloads are base64; the
// returned signature is base58 (Solana convention).
// ---------------------------------------------------------------------------

const sigil_svm_sign_message: MethodHandler = (params, ctx) => {
  const obj = asObject(params, 'svm_sign_message');
  const portal = asString(obj, 'portal', 'svm_sign_message');
  const messageB64 = asString(obj, 'message', 'svm_sign_message');
  const message = b64ToBuf(messageB64, 'svm_sign_message', 'message');
  // ed25519 signs arbitrary bytes, and a Solana transaction message IS
  // arbitrary bytes: signing one here would authorize a transaction while
  // skipping the transaction policy (allowlists, caps, confirm). Refuse
  // anything that parses as a transaction message; use svm_sign_transaction.
  if (looksLikeSvmTransaction(message)) {
    throw new RpcMethodError(
      RPC_INVALID_PAYLOAD,
      'svm_sign_message: payload is a Solana transaction message — use svm_sign_transaction so the transaction policy applies',
    );
  }
  const secret = requirePortal(ctx.handles, portal);
  gatePolicy(
    ctx,
    portal,
    'svm_sign_message',
    { message: messageB64 },
    {
      kind: 'svm_message',
      messageBytes: message,
    },
  );
  const sig = base58Encode(svmSign(message, secret));
  ctx.audit.append({
    kind: 'svm_sign_message',
    portal,
    payload: { message: messageB64 },
    decision: 'allow',
    sig,
  });
  return { signature: sig };
};

const sigil_svm_sign_transaction: MethodHandler = async (params, ctx) => {
  const obj = asObject(params, 'svm_sign_transaction');
  const portal = asString(obj, 'portal', 'svm_sign_transaction');
  const messageB64 = asString(obj, 'message', 'svm_sign_transaction');
  const messageBytes = b64ToBuf(messageB64, 'svm_sign_transaction', 'message');
  const secretPre = requirePortal(ctx.handles, portal);

  let decoded: ReturnType<typeof decodeTx>;
  try {
    decoded = decodeTx(messageBytes);
  } catch (err) {
    throw new RpcMethodError(
      RPC_INVALID_PAYLOAD,
      `svm_sign_transaction: not a valid Solana message — ${(err as Error).message}`,
    );
  }

  // Refuse to sign a message where our key isn't actually a required signer —
  // signing it would produce a signature in the wrong slot (or no slot at all).
  const pub = svmGetPublicKey(secretPre);
  const signers = decoded.message.staticAccountKeys.slice(0, decoded.message.numRequiredSignatures);
  if (!signers.some((k) => Buffer.from(k).equals(pub))) {
    throw new RpcMethodError(
      RPC_INVALID_PAYLOAD,
      `svm_sign_transaction: portal "${portal}" (${base58Encode(pub)}) is not a required signer of this message`,
    );
  }

  const gate = gatePolicy(
    ctx,
    portal,
    'svm_sign_transaction',
    { message: messageB64 },
    {
      kind: 'svm_transaction',
      transfers: decoded.transfers.map((t) => ({ to: t.to, lamports: t.lamports })),
      allDecoded: decoded.allDecoded,
      instructionCount: decoded.message.instructions.length,
    },
  );
  if (gate.proceed === 'confirm') {
    await runConfirmGate(
      ctx,
      portal,
      'svm_sign_transaction',
      { message: messageB64 },
      gate.summary,
    );
  }

  // Re-acquire after any confirm (see eth_sign_transaction): never reserve
  // or sign with a buffer that may have been zeroized meanwhile.
  const secret = requirePortal(ctx.handles, portal);
  let lamports = 0n;
  for (const t of decoded.transfers) lamports += t.lamports;
  reserveSpend(ctx, portal, 'svm_sign_transaction', { message: messageB64 }, gate.policy, {
    asset: 'lamports',
    amount: lamports,
  });
  const sig = base58Encode(svmSign(messageBytes, secret));
  ctx.audit.append({
    kind: 'svm_sign_transaction',
    portal,
    payload: { message: messageB64 },
    decision: 'allow',
    sig,
  });
  return { signature: sig };
};

export const METHODS: Readonly<Record<string, MethodHandler>> = Object.freeze({
  sigil_list_portals,
  sigil_eth_sign_message,
  sigil_eth_sign_transaction,
  sigil_eth_preview_transaction,
  sigil_eth_sign_typed_data,
  sigil_svm_sign_message,
  sigil_svm_sign_transaction,
});

/**
 * Dispatch a parsed RPC request to the matching method. Always async — even
 * for handlers that are synchronous — so callers can await uniformly.
 *
 * Throws RpcMethodError on user errors or method-not-found, or other Error
 * for unexpected internals.
 */
export async function dispatch(
  method: string,
  params: unknown,
  ctx: MethodContext,
): Promise<unknown> {
  const handler = METHODS[method];
  if (!handler) {
    throw new RpcMethodError(RPC_METHOD_NOT_FOUND, `method not found: ${method}`);
  }
  return await handler(params, ctx);
}
