import type { DaemonClient } from '../daemon/client.js';
import { DaemonRpcError } from '../daemon/client.js';
import { MCP_INTERNAL_ERROR, MCP_INVALID_PARAMS, type ToolDefinition, type ToolResult } from './protocol.js';

export interface ToolHandlerCtx {
  daemon: DaemonClient;
}

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
      'List the signing portals currently loaded in sigild. Returns each portal handle (e.g. "eth:executor"), its kind, and the public address it controls.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  handler: async (_args, ctx) => {
    const result = await callDaemon(ctx.daemon, 'sigil_list_portals', {});
    return textResult(result);
  },
};

const ethSignMessage: Tool = {
  definition: {
    name: 'sigil_eth_sign_message',
    description:
      'Sign an EIP-191 personal_sign message with the named portal. The message is supplied as 0x-prefixed hex bytes (encode strings to UTF-8 first). Returns the 65-byte r||s||v signature as 0x-prefixed hex.',
    inputSchema: {
      type: 'object',
      properties: {
        portal: { type: 'string', description: 'Portal handle, e.g. "eth:executor".' },
        message: { type: 'string', description: '0x-prefixed hex of the bytes to sign.' },
      },
      required: ['portal', 'message'],
      additionalProperties: false,
    },
  },
  handler: async (args, ctx) => {
    const params = ensureObject(args, 'sigil_eth_sign_message');
    const result = await callDaemon(ctx.daemon, 'sigil_eth_sign_message', params);
    return textResult(result);
  },
};

const ethSignTransaction: Tool = {
  definition: {
    name: 'sigil_eth_sign_transaction',
    description:
      'Sign an Ethereum transaction (legacy or EIP-1559) with the named portal. Returns the signed transaction as 0x-prefixed hex, ready for eth_sendRawTransaction.',
    inputSchema: {
      type: 'object',
      properties: {
        portal: { type: 'string', description: 'Portal handle.' },
        tx: {
          type: 'object',
          description:
            'Transaction fields. type="legacy" requires {chainId, nonce, gasPrice, gasLimit, to, value, data}. type="eip1559" requires {chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList?}. Numbers may be supplied as JSON numbers or decimal strings.',
        },
      },
      required: ['portal', 'tx'],
      additionalProperties: false,
    },
  },
  handler: async (args, ctx) => {
    const params = ensureObject(args, 'sigil_eth_sign_transaction');
    const result = await callDaemon(ctx.daemon, 'sigil_eth_sign_transaction', params);
    return textResult(result);
  },
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
  handler: async (args, ctx) => {
    const params = ensureObject(args, 'sigil_eth_sign_typed_data');
    const result = await callDaemon(ctx.daemon, 'sigil_eth_sign_typed_data', params);
    return textResult(result);
  },
};

export const TOOLS: readonly Tool[] = Object.freeze([
  listPortals,
  ethSignMessage,
  ethSignTransaction,
  ethSignTypedData,
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

function ensureObject(args: unknown, name: string): Record<string, unknown> {
  if (typeof args !== 'object' || args === null || Array.isArray(args)) {
    throw new ToolError(MCP_INVALID_PARAMS, `${name}: arguments must be an object`);
  }
  return args as Record<string, unknown>;
}

async function callDaemon(client: DaemonClient, method: string, params: unknown): Promise<unknown> {
  try {
    return await client.call(method, params);
  } catch (err) {
    if (err instanceof DaemonRpcError) {
      // Forward the daemon's error code unchanged so the client sees the
      // exact diagnosis (PORTAL_NOT_FOUND, INVALID_PARAMS, etc).
      throw new ToolError(err.code, err.message, err.data);
    }
    throw new ToolError(MCP_INTERNAL_ERROR, `daemon error: ${(err as Error).message}`);
  }
}

function textResult(payload: unknown): ToolResult {
  // JSON-serialize the daemon's response into the MCP text content slot.
  // We also include structuredContent so MCP clients that support it can
  // access the typed payload directly without re-parsing.
  return {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
    structuredContent: payload,
  };
}
