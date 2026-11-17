import { AbiDecodeError, decodeAbiTypes } from '../eth/abi.js';
import type { AbiRegistry } from './abi-dir.js';
import { type DescribeCtx, type Description, KNOWN_FUNCTIONS } from './known.js';
import { type DecodedArg, type DecodedCall, NO_META, type TokenMetaLookup } from './types.js';
import { renderValue } from './units.js';

/**
 * Turn calldata into a DecodedCall: built-in English description when the
 * selector is one sigil knows, the user's ABI (argument names + values)
 * when it isn't, or an explicit "unknown function" otherwise.
 *
 * Pure and offline — no RPC. Token metadata is supplied by the caller (the
 * simulator fetches it); without it amounts render as raw integers.
 *
 * Decoding is presentation, so it fails open-but-loud: calldata that doesn't
 * match its selector's signature yields a warning, never an exception that
 * would block an otherwise-allowed sign. Only bugs (non-AbiDecodeError
 * throws from the decoder) propagate.
 */

export interface DecodeCtx {
  /** Destination (any case). null = contract creation. Omitted = unknown. */
  to?: string | null;
  value?: bigint;
  /** The portal's address, for "swap output goes elsewhere" warnings. */
  from?: string;
  /** Internal: nesting depth (multicall members decode at depth 1). */
  depth?: number;
}

/** Cap on a generic (user-ABI) call line, so one huge argument can't flood the push. */
const MAX_TEXT = 400;

export function decodeCalldata(
  data: Uint8Array,
  registry: AbiRegistry,
  meta: TokenMetaLookup = NO_META,
  ctx: DecodeCtx = {},
): DecodedCall {
  if (ctx.to === null) {
    return {
      selector: null,
      text: `contract creation, ${data.length}-byte initcode`,
      warnings: [],
      source: 'deploy',
    };
  }
  if (data.length === 0) {
    return { selector: null, text: 'plain ETH transfer', warnings: [], source: 'empty' };
  }
  if (data.length < 4) {
    return {
      selector: null,
      text: `malformed calldata (${data.length} bytes, too short for a selector)`,
      warnings: [`calldata is ${data.length} bytes — too short to hold a function selector`],
      source: 'unknown',
    };
  }
  const selector = '0x' + Buffer.from(data.subarray(0, 4)).toString('hex');
  const builtin = KNOWN_FUNCTIONS.get(selector);
  const user = registry.lookup(selector);
  const def = builtin ?? user;
  if (!def) {
    return {
      selector,
      text: `unknown function ${selector} (${data.length} bytes calldata)`,
      warnings: [`unknown selector ${selector} — calldata not decoded`],
      source: 'unknown',
    };
  }
  const source = builtin ? 'builtin' : 'abi';
  const base = { selector, signature: def.signature, name: def.name, source } as const;

  let values: unknown[];
  try {
    values = decodeAbiTypes(
      def.inputs.map((i) => i.abiType),
      data.subarray(4),
    );
  } catch (err) {
    if (!(err instanceof AbiDecodeError)) throw err;
    return {
      ...base,
      text: `${def.name}(…) — calldata does not match ${def.signature}`,
      warnings: [`calldata does not decode as ${def.signature}: ${err.message}`],
    };
  }

  // A user ABI naming the same selector supplies the argument names; the
  // built-in still writes the sentence.
  const names =
    builtin && user && user.inputs.length === builtin.inputs.length
      ? user.inputs.map((i) => i.name)
      : def.inputs.map((i) => i.name);
  const args: DecodedArg[] = def.inputs.map((inp, i) => ({
    name: names[i]!,
    type: inp.type,
    value: renderValue(inp.type, values[i]),
  }));

  if (builtin) {
    const depth = ctx.depth ?? 0;
    const dctx: DescribeCtx = {
      to: ctx.to?.toLowerCase() ?? null,
      value: ctx.value ?? 0n,
      meta,
      ...(ctx.from !== undefined ? { from: ctx.from.toLowerCase() } : {}),
      ...(depth === 0
        ? {
            decodeInner: (d: Uint8Array) => decodeCalldata(d, registry, meta, { ...ctx, depth: 1 }),
          }
        : {}),
    };
    let desc: Description;
    try {
      desc = builtin.describe(values, dctx);
    } catch (err) {
      // A describe bug must not block signing; say so and fall back to the
      // generic rendering.
      desc = {
        text: genericText(def.name, args, values, def.inputs),
        warnings: [`could not describe ${def.signature}: ${(err as Error).message}`],
      };
    }
    return {
      ...base,
      args,
      text: desc.text,
      ...(desc.short !== undefined ? { short: desc.short } : {}),
      warnings: desc.warnings,
      ...(desc.tokens && desc.tokens.length > 0 ? { tokens: dedupe(desc.tokens) } : {}),
    };
  }
  return { ...base, args, text: genericText(def.name, args, values, def.inputs), warnings: [] };
}

function genericText(
  name: string,
  args: DecodedArg[],
  values: unknown[],
  inputs: readonly { type: string }[],
): string {
  const parts = args.map((a, i) => `${a.name}=${renderValue(inputs[i]!.type, values[i], true)}`);
  const text = `${name}(${parts.join(', ')})`;
  return text.length > MAX_TEXT ? text.slice(0, MAX_TEXT - 1) + '…' : text;
}

function dedupe(xs: string[]): string[] {
  return [...new Set(xs.map((x) => x.toLowerCase()))];
}
