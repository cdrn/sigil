import { dispatch, type MethodContext, RpcMethodError } from '../daemon/methods.js';
import { MCP_INTERNAL_ERROR, type ToolDefinition, type ToolResult } from './protocol.js';

export type ToolHandlerCtx = MethodContext;

export type ToolHandler = (args: unknown, ctx: ToolHandlerCtx) => Promise<ToolResult>;

export interface Tool {
  definition: ToolDefinition;
  handler: ToolHandler;
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

const listPortals: Tool = {
  definition: {
    name: 'sigil_list_portals',
    description:
      'List the signing portals currently loaded in sigil. Returns each portal handle (e.g. "evm:executor"), its kind, the EVM address (`address`, secp256k1, 0x-prefixed) and the Solana address (`svmAddress`, ed25519, base58) — both controlled by the same key.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  handler: (args, ctx) => callMethod('sigil_list_portals', args, ctx),
};

const ethSignMessage: Tool = {
  definition: {
    name: 'sigil_eth_sign_message',
    description:
      'Sign an EIP-191 personal_sign message with the named portal. The message is supplied as 0x-prefixed hex bytes (encode strings to UTF-8 first). Returns the 65-byte r||s||v signature as 0x-prefixed hex.',
    inputSchema: {
      type: 'object',
      properties: {
        portal: { type: 'string', description: 'Portal handle, e.g. "evm:executor".' },
        message: { type: 'string', description: '0x-prefixed hex of the bytes to sign.' },
      },
      required: ['portal', 'message'],
      additionalProperties: false,
    },
  },
  handler: (args, ctx) => callMethod('sigil_eth_sign_message', args, ctx),
};

const ethSignTransaction: Tool = {
  definition: {
    name: 'sigil_eth_sign_transaction',
    description:
      'Sign an Ethereum transaction (legacy or EIP-1559) with the named portal. Returns `signed` (the signed transaction as 0x-prefixed hex, ready for eth_sendRawTransaction) and `preview`: what sigil decoded the call to and, when a simulation RPC is configured, what the dry-run did (balance changes, approvals, revert reason, warnings). Show the user the preview, and treat any warning in it as a reason to stop and check. A policy may deny a tx whose simulation reverts or that cannot be simulated; the error says why.',
    inputSchema: {
      type: 'object',
      properties: {
        portal: { type: 'string', description: 'Portal handle.' },
        tx: {
          type: 'object',
          description:
            'Transaction fields. type="legacy" requires {chainId, nonce, gasPrice, gasLimit, to, value, data}. type="eip1559" requires {chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList?}. To deploy a contract, set to=null (explicit JSON null, not omitted) and put the creation bytecode in data. Numbers may be supplied as JSON numbers or decimal strings.',
        },
      },
      required: ['portal', 'tx'],
      additionalProperties: false,
    },
  },
  handler: (args, ctx) => callMethod('sigil_eth_sign_transaction', args, ctx),
};

const ethPreviewTransaction: Tool = {
  definition: {
    name: 'sigil_eth_preview_transaction',
    description:
      'Preview an Ethereum transaction WITHOUT signing it: sigil decodes the calldata to English (ERC-20/721/1155 transfers and approvals, Permit2, Uniswap swaps, multicall, plus any user ABIs) and, when a simulation RPC is configured for the chain, dry-runs it from the portal address to report status, gas, revert reason, net balance changes and approvals granted. Takes the same {portal, tx} as sigil_eth_sign_transaction. Call this before signing anything non-trivial (any calldata, approvals, swaps, or sizeable value) and show the user the `preview` text, especially its warnings, before you sign. Nothing is signed or written to the audit log. Returns {preview, headline, warnings, decoded, simulation}.',
    inputSchema: {
      type: 'object',
      properties: {
        portal: { type: 'string', description: 'Portal handle.' },
        tx: {
          type: 'object',
          description:
            'Transaction fields. type="legacy" requires {chainId, nonce, gasPrice, gasLimit, to, value, data}. type="eip1559" requires {chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList?}. To deploy a contract, set to=null (explicit JSON null, not omitted) and put the creation bytecode in data. Numbers may be supplied as JSON numbers or decimal strings.',
        },
      },
      required: ['portal', 'tx'],
      additionalProperties: false,
    },
  },
  handler: (args, ctx) => callMethod('sigil_eth_preview_transaction', args, ctx),
};

const ethSignTypedData: Tool = {
  definition: {
    name: 'sigil_eth_sign_typed_data',
    description:
      'Sign an EIP-712 typed data structure with the named portal. Returns the 65-byte signature as 0x-prefixed hex.',
    inputSchema: {
      type: 'object',
      properties: {
        portal: { type: 'string', description: 'Portal handle.' },
        typedData: {
          type: 'object',
          description: 'EIP-712 typed data: {types, primaryType, domain, message}.',
        },
      },
      required: ['portal', 'typedData'],
      additionalProperties: false,
    },
  },
  handler: (args, ctx) => callMethod('sigil_eth_sign_typed_data', args, ctx),
};

const svmSignMessage: Tool = {
  definition: {
    name: 'sigil_svm_sign_message',
    description:
      "Sign an arbitrary off-chain message with the portal's Solana (ed25519) key — the same key whose address is `svmAddress`. The message is base64-encoded bytes. Returns the 64-byte signature as a base58 string.",
    inputSchema: {
      type: 'object',
      properties: {
        portal: { type: 'string', description: 'Portal handle, e.g. "evm:executor".' },
        message: { type: 'string', description: 'base64 of the bytes to sign.' },
      },
      required: ['portal', 'message'],
      additionalProperties: false,
    },
  },
  handler: (args, ctx) => callMethod('sigil_svm_sign_message', args, ctx),
};

const svmSignTransaction: Tool = {
  definition: {
    name: 'sigil_svm_sign_transaction',
    description:
      "Sign a Solana transaction message with the portal's ed25519 key. Pass the SERIALIZED transaction message (the bytes between the signature array and that you build with your Solana SDK, e.g. message.serialize()) as base64. sigil ed25519-signs those exact bytes and returns the signature as base58 — assemble it into the transaction yourself. Policy decodes native SOL transfers to gate destination/amount; anything it can't decode offline is routed to out-of-band confirm. Supports legacy and v0 messages.",
    inputSchema: {
      type: 'object',
      properties: {
        portal: { type: 'string', description: 'Portal handle.' },
        message: {
          type: 'string',
          description: 'base64 of the serialized Solana transaction message.',
        },
      },
      required: ['portal', 'message'],
      additionalProperties: false,
    },
  },
  handler: (args, ctx) => callMethod('sigil_svm_sign_transaction', args, ctx),
};

export const TOOLS: readonly Tool[] = Object.freeze([
  listPortals,
  ethSignMessage,
  ethSignTransaction,
  ethPreviewTransaction,
  ethSignTypedData,
  svmSignMessage,
  svmSignTransaction,
]);

export function findTool(name: string): Tool | undefined {
  return TOOLS.find((t) => t.definition.name === name);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export class ToolError extends Error {
  readonly code: number;
  readonly data: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = 'ToolError';
    this.code = code;
    this.data = data;
  }
}

/**
 * Call into the in-process method dispatcher and wrap the result for MCP.
 * Maps `RpcMethodError` (raised by the dispatcher on user errors or
 * not-found method) into `ToolError` with the same code, so the original
 * error semantics flow through to the MCP client unchanged.
 */
async function callMethod(
  methodName: string,
  args: unknown,
  ctx: MethodContext,
): Promise<ToolResult> {
  try {
    const result = await dispatch(methodName, args, ctx);
    return textResult(result);
  } catch (err) {
    if (err instanceof RpcMethodError) {
      throw new ToolError(err.code, err.message, err.data);
    }
    throw new ToolError(MCP_INTERNAL_ERROR, `internal: ${(err as Error).message}`);
  }
}

function textResult(payload: unknown): ToolResult {
  // JSON-serialize the response into the MCP text content slot.
  // We also include structuredContent so MCP clients that support it can
  // access the typed payload directly without re-parsing.
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    structuredContent: payload,
  };
}
