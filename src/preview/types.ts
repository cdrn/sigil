/**
 * Shared shapes for the transaction preview ("show me what I'm signing").
 *
 * The preview is presentation plus two opt-in policy gates (deny on revert,
 * require simulation). Everything here is derived from attacker-influenced
 * input — calldata from the agent, logs/revert data/token symbols from the
 * simulated contracts — so every string that reaches a human or the model is
 * built by sigil's own formatters, never passed through verbatim.
 */

/**
 * ERC-20 metadata for one token, as far as it could be read. Either field
 * may be missing: a token whose symbol() reverts still renders amounts with
 * its decimals, and one whose decimals() is garbage renders raw integers.
 */
export interface TokenMeta {
  symbol?: string;
  decimals?: number;
}

/** Synchronous lookup by lowercase 0x address; undefined = nothing known. */
export type TokenMetaLookup = (address: string) => TokenMeta | undefined;

export const NO_META: TokenMetaLookup = () => undefined;

export interface DecodedArg {
  name: string;
  /** Canonical Solidity type, e.g. "uint256", "(address,uint24)[]". */
  type: string;
  /** Pre-rendered value: bigints decimal, addresses lowercase, long bytes truncated. */
  value: string;
}

export interface DecodedCall {
  /** 0x + 8 hex, or null for empty calldata / contract creation / too-short data. */
  selector: string | null;
  signature?: string;
  name?: string;
  args?: DecodedArg[];
  /** One line, for the preview text: e.g. `approve(spender=0x1111…1111, amount=UNLIMITED)`. */
  text: string;
  /** Optional terse form for the push headline: `approve UNLIMITED USDC → 0x1111…1111`. */
  short?: string;
  warnings: string[];
  source: 'builtin' | 'abi' | 'unknown' | 'empty' | 'deploy';
  /**
   * Token addresses whose metadata would sharpen this rendering (the `to` of
   * an ERC-20 call, a Permit2 token, a swap path). The simulator fetches
   * metadata for these alongside the tokens the simulation touched.
   */
  tokens?: string[];
  /**
   * For swaps: what the call itself promises to deliver — the output token
   * (null = native ETH), the minimum (decimal string, so the decoded call
   * stays JSON-plain) and the recipient. The behaviour check compares the
   * simulation against it before the friendly "swap" wording is kept.
   */
  swapOut?: SwapOut;
  /**
   * For multicall: the swap claims of its inner calls (by position). The
   * behaviour check verifies each one, since inner calls are rendered by
   * raw signature and never get a friendly verb of their own.
   */
  innerSwaps?: { index: number; out: SwapOut }[];
}

export interface SwapOut {
  token: string | null;
  min: string;
  recipient: string;
}
