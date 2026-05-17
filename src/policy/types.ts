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
  allowMessageSigning: boolean;
  allowTypedData: boolean;
}

/** What the evaluator gets asked about. */
export type PolicyRequest =
  | { kind: 'transaction'; tx: SignableTx }
  | { kind: 'message'; messageBytes: Buffer }
  | { kind: 'typed_data'; typedData: TypedData };

/** Evaluator output. Reason is human-readable + audit-loggable on Deny. */
export type PolicyDecision =
  | { allow: true }
  | { allow: false; reason: string };

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
