import {
  type AuditWriter,
} from '../audit/index.js';
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
  RPC_INVALID_PARAMS,
  RPC_METHOD_NOT_FOUND,
  RPC_PORTAL_NOT_FOUND,
} from './rpc.js';
import { type HandleTable } from './handles.js';

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
}

export type MethodHandler = (params: unknown, ctx: MethodContext) => unknown;

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

function requirePortal(handles: HandleTable, handle: string): Buffer {
  const sb = handles.get(handle);
  if (!sb) {
    throw new RpcMethodError(RPC_PORTAL_NOT_FOUND, `portal "${handle}" not found`);
  }
  return sb.bytes();
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
      try {
        return BigInt(v);
      } catch {
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: ${key} not a valid bigint string`);
      }
    }
    if (typeof v === 'number') {
      if (!Number.isInteger(v) || v < 0) {
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: ${key} must be a non-negative integer`);
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
        throw new RpcMethodError(RPC_INVALID_PARAMS, `tx: accessList[${i}].storageKeys must be array`);
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

const sigil_eth_sign_transaction: MethodHandler = (params, ctx) => {
  const obj = asObject(params, 'eth_sign_transaction');
  const portal = asString(obj, 'portal', 'eth_sign_transaction');
  const txObj = obj['tx'];
  if (typeof txObj !== 'object' || txObj === null || Array.isArray(txObj)) {
    throw new RpcMethodError(RPC_INVALID_PARAMS, 'eth_sign_transaction: tx must be an object');
  }
  const tx = asTx(txObj as Record<string, unknown>);
  const priv = requirePortal(ctx.handles, portal);
  const signed = signTransaction(tx, priv);
  ctx.audit.append({
    kind: 'eth_sign_transaction',
    portal,
    payload: { tx: txObj },
    decision: 'allow',
    sig: signed,
  });
  return { signed };
};

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
  let sig: Buffer;
  try {
    sig = signTypedData(td as TypedData, priv);
  } catch (err) {
    throw new RpcMethodError(
      RPC_INVALID_PARAMS,
      `eth_sign_typed_data: ${(err as Error).message}`,
    );
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

export const METHODS: Readonly<Record<string, MethodHandler>> = Object.freeze({
  sigil_list_portals,
  sigil_eth_sign_message,
  sigil_eth_sign_transaction,
  sigil_eth_sign_typed_data,
});

/**
 * Dispatch a parsed RPC request to the matching method.
 * Throws RpcMethodError on user errors or method-not-found, or other Error
 * for unexpected internals.
 */
export function dispatch(method: string, params: unknown, ctx: MethodContext): unknown {
  const handler = METHODS[method];
  if (!handler) {
    throw new RpcMethodError(RPC_METHOD_NOT_FOUND, `method not found: ${method}`);
  }
  return handler(params, ctx);
}
