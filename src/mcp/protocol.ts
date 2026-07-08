/**
 * Minimal subset of the Model Context Protocol (MCP) wire format that sigil
 * needs to act as a stdio tool server for Claude Code (and any other MCP
 * client). MCP rides on JSON-RPC 2.0; this module defines the request,
 * response, and notification shapes plus helpers for encoding.
 *
 * Spec reference: https://modelcontextprotocol.io/specification
 *
 * We implement: initialize, notifications/initialized, tools/list, tools/call.
 * Everything else (resources, prompts, sampling, completions, logging,
 * pagination cursors) is intentionally omitted.
 */

export const PROTOCOL_VERSION = '2025-06-18';

export const SERVER_INFO = {
  name: 'sigil-mcp',
  version: '0.0.1',
} as const;

export type McpId = string | number | null;

export interface McpRequest {
  jsonrpc: '2.0';
  id: McpId;
  method: string;
  params?: unknown;
}

export interface McpNotification {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
}

export interface McpSuccess {
  jsonrpc: '2.0';
  id: McpId;
  result: unknown;
}

export interface McpErrorBody {
  code: number;
  message: string;
  data?: unknown;
}

export interface McpError {
  jsonrpc: '2.0';
  id: McpId;
  error: McpErrorBody;
}

export type McpResponse = McpSuccess | McpError;

// Standard JSON-RPC 2.0 error codes (re-stated to keep this module self-contained).
export const MCP_PARSE_ERROR = -32700;
export const MCP_INVALID_REQUEST = -32600;
export const MCP_METHOD_NOT_FOUND = -32601;
export const MCP_INVALID_PARAMS = -32602;
export const MCP_INTERNAL_ERROR = -32603;

export interface ToolInputSchema {
  type: 'object';
  properties: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: ToolInputSchema;
}

export type ToolContent = { type: 'text'; text: string };

export interface ToolResult {
  content: ToolContent[];
  /** When omitted, treated as false. */
  isError?: boolean;
  /** Structured payload for clients that want typed access; supplemental to content. */
  structuredContent?: unknown;
}

/**
 * Parse a single NDJSON line into an MCP envelope.
 *
 * Returns:
 *  - `{ kind: 'request', request }` for an incoming request (has id + method)
 *  - `{ kind: 'notification', notification }` for an incoming notification (method, no id)
 *  - `{ kind: 'parse_error' }` for non-JSON
 *  - `{ kind: 'invalid', id, reason }` for a JSON object that isn't a valid envelope
 */
export type ParseResult =
  | { kind: 'request'; request: McpRequest }
  | { kind: 'notification'; notification: McpNotification }
  | { kind: 'parse_error' }
  | { kind: 'invalid'; id: McpId; reason: string };

export function parseMessage(line: string): ParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return { kind: 'parse_error' };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { kind: 'invalid', id: null, reason: 'message must be a JSON object' };
  }
  const obj = parsed as Record<string, unknown>;
  if (obj['jsonrpc'] !== '2.0') {
    return { kind: 'invalid', id: extractId(obj['id']), reason: 'jsonrpc must be "2.0"' };
  }
  if (typeof obj['method'] !== 'string' || obj['method'].length === 0) {
    return {
      kind: 'invalid',
      id: extractId(obj['id']),
      reason: 'method must be a non-empty string',
    };
  }
  // Distinguish request vs notification by presence of id.
  if (!('id' in obj)) {
    return {
      kind: 'notification',
      notification: {
        jsonrpc: '2.0',
        method: obj['method'],
        ...(obj['params'] !== undefined ? { params: obj['params'] } : {}),
      },
    };
  }
  const rawId = obj['id'];
  if (typeof rawId !== 'string' && typeof rawId !== 'number' && rawId !== null) {
    return { kind: 'invalid', id: null, reason: 'id must be string, number, or null' };
  }
  return {
    kind: 'request',
    request: {
      jsonrpc: '2.0',
      id: rawId,
      method: obj['method'],
      ...(obj['params'] !== undefined ? { params: obj['params'] } : {}),
    },
  };
}

function extractId(raw: unknown): McpId {
  return typeof raw === 'string' || typeof raw === 'number' || raw === null ? raw : null;
}

export function encodeSuccess(id: McpId, result: unknown): string {
  const r: McpSuccess = { jsonrpc: '2.0', id, result };
  return JSON.stringify(r);
}

export function encodeError(id: McpId, code: number, message: string, data?: unknown): string {
  const error: McpErrorBody = data === undefined ? { code, message } : { code, message, data };
  const r: McpError = { jsonrpc: '2.0', id, error };
  return JSON.stringify(r);
}
