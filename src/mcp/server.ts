import { findTool, ToolError, TOOLS } from './tools.js';
import type { DaemonClient } from '../daemon/client.js';
import {
  encodeError,
  encodeSuccess,
  MCP_INTERNAL_ERROR,
  MCP_INVALID_PARAMS,
  MCP_INVALID_REQUEST,
  MCP_METHOD_NOT_FOUND,
  MCP_PARSE_ERROR,
  parseMessage,
  PROTOCOL_VERSION,
  SERVER_INFO,
  type McpId,
  type McpRequest,
} from './protocol.js';

export interface McpServerOpts {
  daemon: DaemonClient;
  /**
   * Optional log sink for protocol-level events. Defaults to a no-op.
   * The default binary entrypoint writes log events to stderr so they don't
   * collide with stdio MCP traffic on stdout.
   */
  onLog?: (event: McpLogEvent) => void;
}

export type McpLogEvent =
  | { kind: 'recv'; method: string; id: McpId | null }
  | { kind: 'send_ok'; id: McpId }
  | { kind: 'send_error'; id: McpId; code: number; message: string }
  | { kind: 'initialized' };

/**
 * Handle a single received line by dispatching it through the MCP protocol.
 * Returns either a response string to send back, or `null` if the line was a
 * notification (no response expected).
 */
export async function handleLine(
  line: string,
  opts: McpServerOpts,
): Promise<string | null> {
  const parsed = parseMessage(line);
  const log = (e: McpLogEvent): void => opts.onLog?.(e);

  if (parsed.kind === 'parse_error') {
    log({ kind: 'send_error', id: null, code: MCP_PARSE_ERROR, message: 'parse error' });
    return encodeError(null, MCP_PARSE_ERROR, 'parse error');
  }
  if (parsed.kind === 'invalid') {
    log({ kind: 'send_error', id: parsed.id, code: MCP_INVALID_REQUEST, message: parsed.reason });
    return encodeError(parsed.id, MCP_INVALID_REQUEST, parsed.reason);
  }
  if (parsed.kind === 'notification') {
    log({ kind: 'recv', method: parsed.notification.method, id: null });
    if (parsed.notification.method === 'notifications/initialized') {
      log({ kind: 'initialized' });
    }
    return null;
  }
  const req = parsed.request;
  log({ kind: 'recv', method: req.method, id: req.id });
  try {
    const result = await dispatch(req, opts);
    log({ kind: 'send_ok', id: req.id });
    return encodeSuccess(req.id, result);
  } catch (err) {
    if (err instanceof ToolError) {
      log({ kind: 'send_error', id: req.id, code: err.code, message: err.message });
      return encodeError(req.id, err.code, err.message, err.data);
    }
    const message = `internal error: ${(err as Error).message}`;
    log({ kind: 'send_error', id: req.id, code: MCP_INTERNAL_ERROR, message });
    return encodeError(req.id, MCP_INTERNAL_ERROR, message);
  }
}

async function dispatch(req: McpRequest, opts: McpServerOpts): Promise<unknown> {
  switch (req.method) {
    case 'initialize':
      return {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
      };
    case 'tools/list':
      return { tools: TOOLS.map((t) => t.definition) };
    case 'tools/call':
      return await invokeTool(req.params, opts);
    case 'ping':
      return {};
    default:
      throw new ToolError(MCP_METHOD_NOT_FOUND, `method not found: ${req.method}`);
  }
}

async function invokeTool(params: unknown, opts: McpServerOpts): Promise<unknown> {
  if (typeof params !== 'object' || params === null || Array.isArray(params)) {
    throw new ToolError(MCP_INVALID_PARAMS, 'tools/call: params must be an object');
  }
  const obj = params as Record<string, unknown>;
  const name = obj['name'];
  if (typeof name !== 'string' || name.length === 0) {
    throw new ToolError(MCP_INVALID_PARAMS, 'tools/call: name must be a non-empty string');
  }
  const tool = findTool(name);
  if (!tool) {
    throw new ToolError(MCP_METHOD_NOT_FOUND, `unknown tool: ${name}`);
  }
  const args = obj['arguments'] ?? {};
  return await tool.handler(args, { daemon: opts.daemon });
}

// ---------------------------------------------------------------------------
// Stdio runner
// ---------------------------------------------------------------------------

export interface McpStdioOpts extends McpServerOpts {
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream;
}

/**
 * Run the MCP server over arbitrary streams (stdin/stdout in production,
 * mock streams in tests). Resolves when stdin closes.
 */
export function runMcpStdio(opts: McpStdioOpts): Promise<void> {
  const { stdin, stdout } = opts;
  stdin.setEncoding?.('utf8');
  return new Promise((resolve, reject) => {
    let buf = '';
    let inflight = 0;
    let stdinEnded = false;
    const tryResolve = (): void => {
      if (stdinEnded && inflight === 0) resolve();
    };
    stdin.on('data', (chunk) => {
      buf += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
      let nl: number;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.length === 0) continue;
        inflight++;
        void handleLine(line, opts)
          .then((resp) => {
            if (resp !== null) stdout.write(resp + '\n');
          })
          .catch((err) => {
            // handleLine itself should never throw — but if it does, fail loudly.
            reject(err);
          })
          .finally(() => {
            inflight--;
            tryResolve();
          });
      }
    });
    stdin.on('end', () => {
      stdinEnded = true;
      tryResolve();
    });
    stdin.on('error', reject);
  });
}
