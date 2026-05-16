/**
 * JSON-RPC 2.0 over newline-delimited JSON (NDJSON).
 * Pure functions only — no IO. The server in server.ts wires this onto sockets.
 *
 * We use the strict JSON-RPC 2.0 envelope: every request has `jsonrpc: "2.0"`,
 * a method, and either an id (for requests expecting a response) or no id (for
 * notifications, which sigil currently rejects since every sign decision needs
 * to round-trip through the audit log).
 */

export const RPC_VERSION = '2.0';

export type RpcId = string | number | null;

export interface RpcRequest {
  jsonrpc: '2.0';
  id: RpcId;
  method: string;
  params: unknown;
}

export interface RpcSuccess {
  jsonrpc: '2.0';
  id: RpcId;
  result: unknown;
}

export interface RpcErrorObject {
  code: number;
  message: string;
  data?: unknown;
}

export interface RpcError {
  jsonrpc: '2.0';
  id: RpcId;
  error: RpcErrorObject;
}

export type RpcResponse = RpcSuccess | RpcError;

// Standard JSON-RPC 2.0 error codes.
export const RPC_PARSE_ERROR = -32700;
export const RPC_INVALID_REQUEST = -32600;
export const RPC_METHOD_NOT_FOUND = -32601;
export const RPC_INVALID_PARAMS = -32602;
export const RPC_INTERNAL_ERROR = -32603;

// Reserved range for sigil-specific errors: -32000 .. -32099.
export const RPC_PORTAL_NOT_FOUND = -32000;
export const RPC_POLICY_DENIED = -32001;
export const RPC_INVALID_PAYLOAD = -32002;

export type ParseResult =
  | { kind: 'request'; request: RpcRequest }
  | { kind: 'parse_error' }
  | { kind: 'invalid'; id: RpcId; reason: string };

/**
 * Parse a single NDJSON line into a JSON-RPC request.
 * Returns either a valid request, a parse_error (if the line is not JSON), or
 * an invalid envelope along with the id that should be echoed in the error
 * response (which is null if the id couldn't be extracted).
 */
export function parseRequest(line: string): ParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return { kind: 'parse_error' };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { kind: 'invalid', id: null, reason: 'request must be a JSON object' };
  }
  const obj = parsed as Record<string, unknown>;
  // Try to extract an id even if the rest is malformed, so the error
  // response can be correlated.
  const rawId = obj['id'];
  const id: RpcId =
    typeof rawId === 'string' || typeof rawId === 'number' || rawId === null ? rawId : null;
  if (obj['jsonrpc'] !== RPC_VERSION) {
    return { kind: 'invalid', id, reason: 'jsonrpc must be "2.0"' };
  }
  if (typeof obj['method'] !== 'string' || obj['method'].length === 0) {
    return { kind: 'invalid', id, reason: 'method must be a non-empty string' };
  }
  // Notifications (no id) are not supported — every call must be acknowledged
  // because every sign call needs an audit-log roundtrip.
  if (!('id' in obj)) {
    return { kind: 'invalid', id: null, reason: 'notifications are not supported' };
  }
  if (typeof rawId !== 'string' && typeof rawId !== 'number' && rawId !== null) {
    return { kind: 'invalid', id: null, reason: 'id must be string, number, or null' };
  }
  return {
    kind: 'request',
    request: {
      jsonrpc: '2.0',
      id,
      method: obj['method'],
      params: obj['params'],
    },
  };
}

export function encodeResponse(id: RpcId, result: unknown): string {
  const r: RpcSuccess = { jsonrpc: RPC_VERSION, id, result };
  return JSON.stringify(r);
}

export function encodeError(id: RpcId, code: number, message: string, data?: unknown): string {
  const error: RpcErrorObject = data === undefined ? { code, message } : { code, message, data };
  const r: RpcError = { jsonrpc: RPC_VERSION, id, error };
  return JSON.stringify(r);
}
