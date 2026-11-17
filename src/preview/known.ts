import {
  type AbiType,
  canonicalType,
  eventTopic,
  functionSelector,
  parseAbiType,
} from '../eth/abi.js';
import type { DecodedCall, SwapOut, TokenMetaLookup } from './types.js';
import {
  argAmount,
  formatEth,
  formatTimestamp,
  headAmount,
  isUnlimited,
  shortAddr,
  tokenLabel,
  truncHex,
  ZERO_ADDRESS,
} from './units.js';

/**
 * Built-in registry of the function calls an agent is most likely to be
 * asked to sign, each with a `describe` that turns decoded arguments into an
 * English sentence plus warnings. These are the calls where the 4-byte
 * selector alone hides what matters: an `approve` with value 0 looks inert
 * on a value-only summary but can hand over a whole balance.
 *
 * Selector collisions are deliberate where the standards share an ABI:
 * ERC-20 and ERC-721 `approve(address,uint256)` / `transferFrom(...)`, and
 * ERC-721 / ERC-1155 `setApprovalForAll(address,bool)`, are one entry each.
 * The descriptions read amounts with token decimals when known and fall
 * back to raw integers (which is also how a token id renders).
 */

export interface DescribeCtx {
  /** The contract being called (lowercase), or null for a deploy. */
  to: string | null;
  /** Native value sent with the call, wei. */
  value: bigint;
  /** The signing portal's address (lowercase), when known. */
  from?: string;
  meta: TokenMetaLookup;
  /**
   * Decode nested calldata (multicall members) one level deep. Absent at
   * depth ≥ 1, which is what stops recursion.
   */
  decodeInner?: (data: Uint8Array) => DecodedCall;
}

export interface Description {
  text: string;
  short?: string;
  warnings: string[];
  /** Token addresses whose metadata would sharpen the rendering. */
  tokens?: string[];
  swapOut?: SwapOut;
}

export interface KnownFunction {
  selector: string;
  signature: string;
  name: string;
  inputs: { name: string; type: string; abiType: AbiType }[];
  describe: (args: unknown[], ctx: DescribeCtx) => Description;
}

function fn(
  name: string,
  params: [type: string, name: string][],
  describe: KnownFunction['describe'],
): KnownFunction {
  const inputs = params.map(([type, n]) => {
    const abiType = parseAbiType(type);
    return { name: n, type: canonicalType(abiType), abiType };
  });
  const signature = `${name}(${inputs.map((i) => i.type).join(',')})`;
  return { selector: functionSelector(signature), signature, name, inputs, describe };
}

const a = (v: unknown): string => v as string; // address (already lowercase from the decoder)
const n = (v: unknown): bigint => v as bigint;

function zeroWarn(addr: string, what: string): string[] {
  return addr === ZERO_ADDRESS ? [`${what} to the zero address`] : [];
}

function recipientWarn(recipient: string, ctx: DescribeCtx): string[] {
  if (ctx.from === undefined || recipient === ctx.from) return [];
  // Uniswap routers use address(1)/address(2) as "msg.sender"/"this" sentinels.
  if (/^0x0{39}[12]$/.test(recipient)) return [];
  return [`swap output goes to ${shortAddr(recipient)}, not the portal`];
}

function slippageWarn(minOut: bigint): string[] {
  return minOut === 0n ? ['swap has no slippage protection (minimum output 0)'] : [];
}

// --- ERC-20 / ERC-721 ------------------------------------------------------

const transfer = fn(
  'transfer',
  [
    ['address', 'to'],
    ['uint256', 'amount'],
  ],
  ([to, amt], ctx) => {
    const token = ctx.to ?? ZERO_ADDRESS;
    return {
      text: `transfer(to=${shortAddr(a(to))}, amount=${argAmount(n(amt), token, ctx.meta)})`,
      short: `transfer ${headAmount(n(amt), token, ctx.meta)} → ${shortAddr(a(to))}`,
      warnings: zeroWarn(a(to), 'transfer'),
      tokens: [token],
    };
  },
);

const approve = fn(
  'approve',
  [
    ['address', 'spender'],
    ['uint256', 'amount'],
  ],
  ([spender, amt], ctx) => {
    const token = ctx.to ?? ZERO_ADDRESS;
    const unlimited = isUnlimited(n(amt));
    return {
      text: `approve(spender=${shortAddr(a(spender))}, amount=${argAmount(n(amt), token, ctx.meta, { allowanceBits: 256 })})`,
      short: `approve ${headAmount(n(amt), token, ctx.meta, { allowanceBits: 256 })} → ${shortAddr(a(spender))}`,
      warnings: [...(unlimited ? ['UNLIMITED approval'] : []), ...zeroWarn(a(spender), 'approve')],
      tokens: [token],
    };
  },
);

const transferFrom = fn(
  'transferFrom',
  [
    ['address', 'from'],
    ['address', 'to'],
    ['uint256', 'amount'],
  ],
  ([from, to, amt], ctx) => {
    const token = ctx.to ?? ZERO_ADDRESS;
    return {
      text: `transferFrom(from=${shortAddr(a(from))}, to=${shortAddr(a(to))}, amount=${argAmount(n(amt), token, ctx.meta)})`,
      short: `transferFrom ${headAmount(n(amt), token, ctx.meta)} ${shortAddr(a(from))} → ${shortAddr(a(to))}`,
      warnings: zeroWarn(a(to), 'transfer'),
      tokens: [token],
    };
  },
);

function allowanceDelta(name: 'increaseAllowance' | 'decreaseAllowance'): KnownFunction {
  return fn(
    name,
    [
      ['address', 'spender'],
      ['uint256', name === 'increaseAllowance' ? 'addedValue' : 'subtractedValue'],
    ],
    ([spender, amt], ctx) => {
      const token = ctx.to ?? ZERO_ADDRESS;
      const unlimited = name === 'increaseAllowance' && isUnlimited(n(amt));
      const verb = name === 'increaseAllowance' ? 'raise' : 'lower';
      return {
        text: `${name}(spender=${shortAddr(a(spender))}, amount=${argAmount(n(amt), token, ctx.meta, { allowanceBits: 256 })})`,
        short: `${verb} allowance of ${shortAddr(a(spender))} by ${headAmount(n(amt), token, ctx.meta, { allowanceBits: 256 })}`,
        warnings: unlimited ? ['UNLIMITED approval'] : [],
        tokens: [token],
      };
    },
  );
}

// --- ERC-721 / ERC-1155 ----------------------------------------------------

/** Shared with the simulator so a decoded grant and a simulated one dedupe. */
export function operatorWarning(operator: string, collection: string): string {
  return `setApprovalForAll: ${shortAddr(operator)} gets control of EVERY token in ${shortAddr(collection)}`;
}

const setApprovalForAll = fn(
  'setApprovalForAll',
  [
    ['address', 'operator'],
    ['bool', 'approved'],
  ],
  ([op, approved], ctx) => {
    const coll = shortAddr(ctx.to ?? ZERO_ADDRESS);
    const on = approved as boolean;
    return {
      text: `setApprovalForAll(operator=${shortAddr(a(op))}, approved=${on})`,
      short: on
        ? `approve ALL of ${coll} → ${shortAddr(a(op))}`
        : `revoke ${shortAddr(a(op))} on ${coll}`,
      warnings: on ? [operatorWarning(a(op), ctx.to ?? ZERO_ADDRESS)] : [],
    };
  },
);

function nftTransfer(withData: boolean): KnownFunction {
  const params: [string, string][] = [
    ['address', 'from'],
    ['address', 'to'],
    ['uint256', 'tokenId'],
  ];
  if (withData) params.push(['bytes', 'data']);
  return fn('safeTransferFrom', params, ([from, to, id], ctx) => ({
    text: `safeTransferFrom(from=${shortAddr(a(from))}, to=${shortAddr(a(to))}, tokenId=${n(id)})`,
    short: `send NFT ${shortAddr(ctx.to ?? ZERO_ADDRESS)} #${n(id)} → ${shortAddr(a(to))}`,
    warnings: zeroWarn(a(to), 'transfer'),
  }));
}

const erc1155Transfer = fn(
  'safeTransferFrom',
  [
    ['address', 'from'],
    ['address', 'to'],
    ['uint256', 'id'],
    ['uint256', 'amount'],
    ['bytes', 'data'],
  ],
  ([from, to, id, amt], ctx) => ({
    text: `safeTransferFrom(from=${shortAddr(a(from))}, to=${shortAddr(a(to))}, id=${n(id)}, amount=${n(amt)})`,
    short: `send ${n(amt)} × id ${n(id)} of ${shortAddr(ctx.to ?? ZERO_ADDRESS)} → ${shortAddr(a(to))}`,
    warnings: zeroWarn(a(to), 'transfer'),
  }),
);

const erc1155Batch = fn(
  'safeBatchTransferFrom',
  [
    ['address', 'from'],
    ['address', 'to'],
    ['uint256[]', 'ids'],
    ['uint256[]', 'amounts'],
    ['bytes', 'data'],
  ],
  ([from, to, ids], ctx) => {
    const count = (ids as unknown[]).length;
    return {
      text: `safeBatchTransferFrom(from=${shortAddr(a(from))}, to=${shortAddr(a(to))}, ${count} token ids)`,
      short: `send ${count} token ids of ${shortAddr(ctx.to ?? ZERO_ADDRESS)} → ${shortAddr(a(to))}`,
      warnings: zeroWarn(a(to), 'transfer'),
    };
  },
);

// --- WETH ------------------------------------------------------------------

const wethDeposit = fn('deposit', [], (_args, ctx) => ({
  text: `deposit() — wrap ${formatEth(ctx.value)}`,
  short: `wrap ${formatEth(ctx.value)}`,
  warnings: [],
}));

const wethWithdraw = fn('withdraw', [['uint256', 'amount']], ([amt], ctx) => {
  const token = ctx.to ?? ZERO_ADDRESS;
  return {
    text: `withdraw(amount=${argAmount(n(amt), token, ctx.meta)})`,
    short: `withdraw ${headAmount(n(amt), token, ctx.meta)}`,
    warnings: [],
    tokens: [token],
  };
});

// --- Permit2 ---------------------------------------------------------------

const permit2Approve = fn(
  'approve',
  [
    ['address', 'token'],
    ['address', 'spender'],
    ['uint160', 'amount'],
    ['uint48', 'expiration'],
  ],
  ([token, spender, amt, exp], ctx) => {
    const unlimited = isUnlimited(n(amt), 160);
    return {
      text:
        `Permit2 approve(token=${tokenLabel(a(token), ctx.meta)}, spender=${shortAddr(a(spender))}, ` +
        `amount=${argAmount(n(amt), a(token), ctx.meta, { allowanceBits: 160 })}, expiration=${formatTimestamp(n(exp))})`,
      short: `Permit2: approve ${headAmount(n(amt), a(token), ctx.meta, { allowanceBits: 160 })} → ${shortAddr(a(spender))}`,
      warnings: [...(unlimited ? ['UNLIMITED approval'] : []), ...zeroWarn(a(spender), 'approve')],
      tokens: [a(token)],
    };
  },
);

// --- Uniswap V2 router -----------------------------------------------------

function pathText(path: string[], meta: TokenMetaLookup): string {
  return path.map((t) => tokenLabel(t, meta)).join('→');
}

function v2Swap(
  name: string,
  params: [string, string][],
  render: (
    args: unknown[],
    ctx: DescribeCtx,
  ) => { short: string; minOut: bigint; outToken: string | null },
): KnownFunction {
  return fn(name, params, (args, ctx) => {
    const path = args[params.findIndex(([, nm]) => nm === 'path')] as string[];
    const recipient = a(args[params.findIndex(([, nm]) => nm === 'to')]);
    const deadline = n(args[params.length - 1]);
    const { short, minOut, outToken } = render(args, ctx);
    const head = params
      .filter(([, nm]) => nm.startsWith('amount'))
      .map(([, nm]) => `${nm}=${n(args[params.findIndex(([, x]) => x === nm)])}`);
    return {
      text: `${name}(${[...head, `path=${pathText(path, ctx.meta)}`, `to=${shortAddr(recipient)}`, `deadline=${formatTimestamp(deadline)}`].join(', ')})`,
      short,
      warnings: [...recipientWarn(recipient, ctx), ...slippageWarn(minOut)],
      tokens: path,
      swapOut: { token: outToken, min: minOut.toString(), recipient },
    };
  });
}

const first = (p: unknown): string => (p as string[])[0] ?? ZERO_ADDRESS;
const last = (p: unknown): string => (p as string[])[(p as string[]).length - 1] ?? ZERO_ADDRESS;

const swapExactTokensForTokens = v2Swap(
  'swapExactTokensForTokens',
  [
    ['uint256', 'amountIn'],
    ['uint256', 'amountOutMin'],
    ['address[]', 'path'],
    ['address', 'to'],
    ['uint256', 'deadline'],
  ],
  ([inAmt, minOut, path], ctx) => ({
    short: `swap ${headAmount(n(inAmt), first(path), ctx.meta)} → ≥${headAmount(n(minOut), last(path), ctx.meta)}`,
    minOut: n(minOut),
    outToken: last(path),
  }),
);

const swapExactETHForTokens = v2Swap(
  'swapExactETHForTokens',
  [
    ['uint256', 'amountOutMin'],
    ['address[]', 'path'],
    ['address', 'to'],
    ['uint256', 'deadline'],
  ],
  ([minOut, path], ctx) => ({
    short: `swap ${formatEth(ctx.value)} → ≥${headAmount(n(minOut), last(path), ctx.meta)}`,
    minOut: n(minOut),
    outToken: last(path),
  }),
);

const swapExactTokensForETH = v2Swap(
  'swapExactTokensForETH',
  [
    ['uint256', 'amountIn'],
    ['uint256', 'amountOutMin'],
    ['address[]', 'path'],
    ['address', 'to'],
    ['uint256', 'deadline'],
  ],
  ([inAmt, minOut, path], ctx) => ({
    short: `swap ${headAmount(n(inAmt), first(path), ctx.meta)} → ≥${formatEth(n(minOut))}`,
    minOut: n(minOut),
    outToken: null,
  }),
);

const swapTokensForExactTokens = v2Swap(
  'swapTokensForExactTokens',
  [
    ['uint256', 'amountOut'],
    ['uint256', 'amountInMax'],
    ['address[]', 'path'],
    ['address', 'to'],
    ['uint256', 'deadline'],
  ],
  ([out, inMax, path], ctx) => ({
    short: `swap ≤${headAmount(n(inMax), first(path), ctx.meta)} → ${headAmount(n(out), last(path), ctx.meta)}`,
    minOut: n(out),
    outToken: last(path),
  }),
);

// --- Uniswap V3 router -----------------------------------------------------

/** exactInputSingle / exactOutputSingle, with or without the deadline field. */
function v3Single(
  kind: 'exactInputSingle' | 'exactOutputSingle',
  deadline: boolean,
): KnownFunction {
  const amountA = kind === 'exactInputSingle' ? 'amountIn' : 'amountOut';
  const amountB = kind === 'exactInputSingle' ? 'amountOutMinimum' : 'amountInMaximum';
  const fields: [string, string][] = [
    ['address', 'tokenIn'],
    ['address', 'tokenOut'],
    ['uint24', 'fee'],
    ['address', 'recipient'],
    ...(deadline ? ([['uint256', 'deadline']] as [string, string][]) : []),
    ['uint256', amountA],
    ['uint256', amountB],
    ['uint160', 'sqrtPriceLimitX96'],
  ];
  const tupleType = `(${fields.map(([t]) => t).join(',')})`;
  return fn(kind, [[tupleType, 'params']], ([p], ctx) => {
    const v = p as unknown[];
    const get = (nm: string): unknown => v[fields.findIndex(([, x]) => x === nm)];
    const tokenIn = a(get('tokenIn'));
    const tokenOut = a(get('tokenOut'));
    const recipient = a(get('recipient'));
    const amtA = n(get(amountA));
    const amtB = n(get(amountB));
    const short =
      kind === 'exactInputSingle'
        ? `swap ${headAmount(amtA, tokenIn, ctx.meta)} → ≥${headAmount(amtB, tokenOut, ctx.meta)}`
        : `swap ≤${headAmount(amtB, tokenIn, ctx.meta)} → ${headAmount(amtA, tokenOut, ctx.meta)}`;
    const parts = [
      `tokenIn=${tokenLabel(tokenIn, ctx.meta)}`,
      `tokenOut=${tokenLabel(tokenOut, ctx.meta)}`,
      `fee=${n(get('fee'))}`,
      `recipient=${shortAddr(recipient)}`,
      ...(deadline ? [`deadline=${formatTimestamp(n(get('deadline')))}`] : []),
      `${amountA}=${amtA}`,
      `${amountB}=${amtB}`,
    ];
    return {
      text: `${kind}(${parts.join(', ')})`,
      short,
      warnings: [
        ...recipientWarn(recipient, ctx),
        ...(kind === 'exactInputSingle' ? slippageWarn(amtB) : []),
      ],
      tokens: [tokenIn, tokenOut],
      swapOut: {
        token: tokenOut,
        // exactInput*: at least amountOutMinimum; exactOutput*: exactly amountOut.
        min: (kind === 'exactInputSingle' ? amtB : amtA).toString(),
        recipient,
      },
    };
  });
}

/** Decode a V3 packed path: token(20) [fee(3) token(20)]*. Null if malformed. */
export function decodeV3Path(hex: string): string[] | null {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (body.length < 40 || (body.length - 40) % 46 !== 0) return null;
  const tokens = ['0x' + body.slice(0, 40)];
  for (let i = 40; i < body.length; i += 46) tokens.push('0x' + body.slice(i + 6, i + 46));
  return tokens.map((t) => t.toLowerCase());
}

const exactInput = fn(
  'exactInput',
  [['(bytes,address,uint256,uint256,uint256)', 'params']],
  ([p], ctx) => {
    const [path, recipient, deadline, amountIn, minOut] = p as [
      string,
      string,
      bigint,
      bigint,
      bigint,
    ];
    const tokens = decodeV3Path(path);
    const tokenIn = tokens?.[0];
    const tokenOut = tokens?.[tokens.length - 1];
    const short =
      tokenIn && tokenOut
        ? `swap ${headAmount(amountIn, tokenIn, ctx.meta)} → ≥${headAmount(minOut, tokenOut, ctx.meta)}`
        : `swap ${amountIn} via undecodable path`;
    return {
      text:
        `exactInput(path=${tokens ? pathText(tokens, ctx.meta) : 'malformed'}, recipient=${shortAddr(recipient)}, ` +
        `deadline=${formatTimestamp(deadline)}, amountIn=${amountIn}, amountOutMinimum=${minOut})`,
      short,
      warnings: [
        ...(tokens ? [] : ['exactInput path is malformed']),
        ...recipientWarn(recipient, ctx),
        ...slippageWarn(minOut),
      ],
      ...(tokens ? { tokens } : {}),
      ...(tokenOut ? { swapOut: { token: tokenOut, min: minOut.toString(), recipient } } : {}),
    };
  },
);

// --- Universal Router / multicall ------------------------------------------

const universalExecute = fn(
  'execute',
  [
    ['bytes', 'commands'],
    ['bytes[]', 'inputs'],
    ['uint256', 'deadline'],
  ],
  ([commands, , deadline]) => {
    const count = (a(commands).length - 2) / 2;
    return {
      text: `Universal Router execute(${count} command${count === 1 ? '' : 's'} ${truncHex(a(commands))}, deadline=${formatTimestamp(n(deadline))})`,
      short: `Universal Router: ${count} command${count === 1 ? '' : 's'}`,
      warnings: [],
    };
  },
);

function multicall(withDeadline: boolean): KnownFunction {
  const params: [string, string][] = withDeadline
    ? [
        ['uint256', 'deadline'],
        ['bytes[]', 'data'],
      ]
    : [['bytes[]', 'data']];
  return fn('multicall', params, (args, ctx) => {
    const calls = args[args.length - 1] as string[];
    const inner = calls.map((hex) =>
      ctx.decodeInner ? ctx.decodeInner(Buffer.from(hex.slice(2), 'hex')) : undefined,
    );
    const MAX = 8;
    const texts = inner.slice(0, MAX).map((d, i) => d?.text ?? `call ${i}`);
    if (inner.length > MAX) texts.push(`…+${inner.length - MAX} more`);
    const shorts = inner.slice(0, 3).map((d) => d?.short ?? d?.text ?? '?');
    if (inner.length > 3) shorts.push(`+${inner.length - 3} more`);
    const warnings: string[] = [];
    const tokens: string[] = [];
    inner.forEach((d, i) => {
      for (const w of d?.warnings ?? []) warnings.push(`multicall[${i}]: ${w}`);
      tokens.push(...(d?.tokens ?? []));
    });
    const dl = withDeadline ? `, deadline=${formatTimestamp(n(args[0]))}` : '';
    return {
      text: `multicall(${calls.length} call${calls.length === 1 ? '' : 's'}: ${texts.join('; ')}${dl})`,
      short: `multicall: ${shorts.join(' + ')}`,
      warnings,
      tokens,
    };
  });
}

const ALL: KnownFunction[] = [
  transfer,
  approve,
  transferFrom,
  allowanceDelta('increaseAllowance'),
  allowanceDelta('decreaseAllowance'),
  setApprovalForAll,
  nftTransfer(false),
  nftTransfer(true),
  erc1155Transfer,
  erc1155Batch,
  wethDeposit,
  wethWithdraw,
  permit2Approve,
  swapExactTokensForTokens,
  swapExactETHForTokens,
  swapExactTokensForETH,
  swapTokensForExactTokens,
  v3Single('exactInputSingle', true),
  v3Single('exactInputSingle', false),
  exactInput,
  v3Single('exactOutputSingle', true),
  universalExecute,
  multicall(false),
  multicall(true),
];

/** selector → built-in entry. */
export const KNOWN_FUNCTIONS: ReadonlyMap<string, KnownFunction> = new Map(
  ALL.map((f) => [f.selector, f]),
);

/** Selectors whose `to` is an ERC-20 (metadata for `to` improves the text). */
export const ERC20_SELECTORS: ReadonlySet<string> = new Set(
  [transfer, approve, transferFrom, wethWithdraw].map((f) => f.selector),
);

// --- Events (simulation logs) ----------------------------------------------

/** topic0 of the events the simulator understands. */
export const EVENT_TOPICS = Object.freeze({
  /** ERC-20 (3 topics + amount) and ERC-721 (4 topics, tokenId indexed). */
  Transfer: eventTopic('Transfer(address,address,uint256)'),
  /** ERC-20 (3 topics + amount) and ERC-721 (4 topics). */
  Approval: eventTopic('Approval(address,address,uint256)'),
  ApprovalForAll: eventTopic('ApprovalForAll(address,address,bool)'),
  TransferSingle: eventTopic('TransferSingle(address,address,address,uint256,uint256)'),
  TransferBatch: eventTopic('TransferBatch(address,address,address,uint256[],uint256[])'),
  /** WETH9 wrap/unwrap: no Transfer is emitted, so these move the balance. */
  Deposit: eventTopic('Deposit(address,uint256)'),
  Withdrawal: eventTopic('Withdrawal(address,uint256)'),
});
