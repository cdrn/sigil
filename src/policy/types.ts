import type { SignableTx, TypedData } from '../eth/index.js';

/**
 * A loaded + validated per-portal policy.
 *
 * Stored on disk at ~/.sigil/policy/<handle>.toml; loaded once per sign call
 * (cheap — file is small, sign calls are human-paced).
 *
 * Two modes:
 *   - "permissive": evaluator returns Allow for everything. The other fields
 *     are ignored. This is the default written by `sigil portal add`; the
 *     user is opting into key isolation without any signing constraints.
 *   - "strict": every field below is enforced. `sigil portal add --strict`
 *     writes a template with conservative defaults the user fills in.
 *
 * `max_value_wei` is a string in the TOML and is parsed to bigint at load
 * time — uint256 doesn't fit in TOML's int64.
 */
export interface Policy {
  mode: 'permissive' | 'strict';
  chainIds: readonly number[];
  /** Lowercase 0x-prefixed addresses, normalized at load time. */
  allowTo: readonly string[];
  /** Per-tx value cap, in wei. 0n means "no value sends allowed at all". */
  maxValueWei: bigint;
  /** 4-byte function selectors, lowercase 0x-prefixed, normalized at load time. */
  allowedSelectors: readonly string[];
  /**
   * Strict mode: permit contract-creation transactions (to: null). Initcode
   * is arbitrary code that no allowlist can vet, so even when enabled every
   * deploy is routed to the out-of-band confirm gate (a confirm transport
   * must be configured or sigil-mcp refuses to start). Deploys still respect
   * max_value_wei; allow_to and allowed_selectors don't apply to them.
   * Permissive mode ignores this — deploys are already allowed there.
   */
  allowContractCreation: boolean;
  allowMessageSigning: boolean;
  allowTypedData: boolean;
  /**
   * If set, transactions whose value exceeds this threshold require an
   * out-of-band human confirmation before signing. Independent of mode:
   * applies in both permissive and strict. `undefined` = no confirm gate.
   * A value > maxValueWei in strict mode would never trigger (the deny
   * fires first); validation catches that misconfiguration at load time.
   */
  requireConfirmAboveWei?: bigint;

  // --- Solana (SVM) -------------------------------------------------------
  // The same secp256k1 secret also backs an ed25519 Solana key; these fields
  // gate signing with it. Strict mode enforces all of them; permissive
  // ignores them except requireConfirmAboveLamports (mode-independent, like
  // its wei sibling).
  /** Allow signing arbitrary off-chain ed25519 messages with this key. */
  allowSvmMessageSigning: boolean;
  /** base58 recipient allowlist for native SOL transfers (strict). */
  svmAllowTo: readonly string[];
  /** Per-transaction cap on total transferred lamports (strict). 0 = none. */
  svmMaxLamports: bigint;
  /**
   * If set, a Solana tx whose total transferred lamports exceeds this — OR
   * whose instructions can't all be decoded offline — requires an out-of-band
   * confirm. Mode-independent for the value threshold; the undecodable-tx
   * confirm only applies in strict mode (permissive allows them outright).
   */
  requireConfirmAboveLamports?: bigint;
}

/** A native SOL transfer the evaluator was handed, pre-decoded by the caller. */
export interface SvmTransferView {
  /** base58 recipient. */
  to: string;
  lamports: bigint;
}

/** What the evaluator gets asked about. */
export type PolicyRequest =
  | { kind: 'transaction'; tx: SignableTx }
  | { kind: 'message'; messageBytes: Buffer }
  | { kind: 'typed_data'; typedData: TypedData }
  | { kind: 'svm_message'; messageBytes: Buffer }
  | {
      kind: 'svm_transaction';
      /** Decoded native SOL transfers (may be a subset if allDecoded is false). */
      transfers: readonly SvmTransferView[];
      /** True iff every instruction decoded to a recognized System transfer. */
      allDecoded: boolean;
      /** Total instruction count, for the confirm summary. */
      instructionCount: number;
    };

/**
 * Evaluator output. Three arms, discriminated by `kind`:
 *   - 'allow': sign without further checks.
 *   - 'deny': hard reject with a human-readable, audit-loggable reason.
 *   - 'confirm': static checks all passed, but the policy says this request
 *     needs an out-of-band human ack before signing. The caller (sign
 *     methods) gates on the confirm transport before proceeding. `summary`
 *     is the one-line description shown to the user in the push
 *     notification — keep it tight ("0.5 ETH → 0xabc…").
 */
export type PolicyDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'confirm'; summary: string };

/**
 * Resolves a portal handle to its current policy. Wrapped in an interface so
 * tests can inject a constant policy without going through the filesystem.
 *
 * Throws PolicyLoadError if the file is missing or malformed. Sign methods
 * treat any throw as a hard Deny + audit it.
 */
export interface PolicyResolver {
  resolve(handle: string): Policy;
}

export class PolicyLoadError extends Error {
  override readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'PolicyLoadError';
    if (cause !== undefined) this.cause = cause;
  }
}
