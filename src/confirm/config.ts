import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import toml from '@iarna/toml';
import { parsePolicy, PolicyLoadError } from '../policy/index.js';

/**
 * sigil config at ~/.sigil/config.toml. Carries the OOB confirm transport
 * block and the optional local JSON-RPC signing proxy block.
 *
 *   [confirm.ntfy]
 *   topic  = "an-unguessable-string"
 *   server = "https://ntfy.sh"   # optional, default https://ntfy.sh
 *
 *   [rpc]
 *   portal   = "evm:bot"
 *   upstream = "https://sepolia.example/v3/KEY"
 *   token    = "an-unguessable-string-16+chars"
 *   port     = 8547              # optional
 *
 * Missing file → SigilConfig with no transport configured. That's fine on
 * its own; we only fail closed at startup if some policy actually depends
 * on a transport (see `enforceConfirmTransportPresence`).
 */
export interface SigilConfig {
  confirm?: ConfirmConfig;
  rpc?: RpcConfigToml;
}

/**
 * Local JSON-RPC signing proxy (`[rpc]` block). All of portal/upstream/token
 * are required — the proxy never starts without an auth token, and a token
 * under 16 chars is rejected at parse time rather than silently weakening
 * the only thing standing between "any local process" and "signs with the
 * portal key".
 */
export interface RpcConfigToml {
  /** Portal handle whose key answers eth_accounts / signs eth_sendTransaction. */
  portal: string;
  /** Upstream JSON-RPC node everything else is proxied to. http(s) only. */
  upstream: string;
  /** Shared secret every request must present (Bearer or Basic password). */
  token: string;
  /** Listen port on 127.0.0.1. Default 8547 (clear of anvil's 8545). */
  port?: number;
}

export interface ConfirmConfig {
  /** Default timeout for any OOB confirm round-trip, in milliseconds.
   *  Defaults to 60_000. Per-portal overrides come later. */
  timeoutMs?: number;
  ntfy?: NtfyConfigToml;
}

export interface NtfyConfigToml {
  topic: string;
  server?: string;
}

export class SigilConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SigilConfigError';
  }
}

/**
 * Parse the file contents (an empty string is treated as "no file").
 * Exported for tests; production loaders should use `loadConfig` so the
 * file-not-found case is handled uniformly.
 */
export function parseConfig(source: string): SigilConfig {
  if (source.trim() === '') return {};
  let raw: toml.JsonMap;
  try {
    raw = toml.parse(source);
  } catch (err) {
    throw new SigilConfigError(`config: invalid TOML — ${(err as Error).message}`);
  }
  const out: SigilConfig = {};
  const rpc = parseRpcBlock(raw['rpc']);
  if (rpc) out.rpc = rpc;
  const confirmRaw = raw['confirm'];
  if (confirmRaw === undefined) return out;
  if (!isObject(confirmRaw)) {
    throw new SigilConfigError(`config.confirm must be a table`);
  }
  const confirm: ConfirmConfig = {};
  const timeoutMs = confirmRaw['timeout_ms'];
  if (timeoutMs !== undefined) {
    if (typeof timeoutMs !== 'number' || !Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new SigilConfigError(
        `config.confirm.timeout_ms must be a positive integer (got ${JSON.stringify(timeoutMs)})`,
      );
    }
    confirm.timeoutMs = timeoutMs;
  }
  const ntfyRaw = confirmRaw['ntfy'];
  if (ntfyRaw !== undefined) {
    if (!isObject(ntfyRaw)) {
      throw new SigilConfigError(`config.confirm.ntfy must be a table`);
    }
    const topic = ntfyRaw['topic'];
    if (typeof topic !== 'string' || topic.length === 0) {
      throw new SigilConfigError(`config.confirm.ntfy.topic is required and must be a string`);
    }
    const server = ntfyRaw['server'];
    if (server !== undefined && typeof server !== 'string') {
      throw new SigilConfigError(`config.confirm.ntfy.server must be a string if set`);
    }
    confirm.ntfy = server !== undefined ? { topic, server } : { topic };
  }
  if (confirm.timeoutMs !== undefined || confirm.ntfy !== undefined) {
    out.confirm = confirm;
  }
  return out;
}

/** Minimum length for the [rpc] auth token. Below this, brute force from a
 *  rebound browser page or a local process stops being fanciful. */
export const RPC_TOKEN_MIN_LENGTH = 16;

function parseRpcBlock(rpcRaw: unknown): RpcConfigToml | undefined {
  if (rpcRaw === undefined) return undefined;
  if (!isObject(rpcRaw)) {
    throw new SigilConfigError(`config.rpc must be a table`);
  }
  const portal = rpcRaw['portal'];
  if (typeof portal !== 'string' || portal.length === 0) {
    throw new SigilConfigError(`config.rpc.portal is required and must be a portal handle`);
  }
  const upstream = rpcRaw['upstream'];
  if (typeof upstream !== 'string' || upstream.length === 0) {
    throw new SigilConfigError(`config.rpc.upstream is required and must be a JSON-RPC URL`);
  }
  let upstreamUrl: URL;
  try {
    upstreamUrl = new URL(upstream);
  } catch {
    throw new SigilConfigError(`config.rpc.upstream is not a valid URL`);
  }
  if (upstreamUrl.protocol !== 'http:' && upstreamUrl.protocol !== 'https:') {
    throw new SigilConfigError(
      `config.rpc.upstream must be http(s), got ${upstreamUrl.protocol.replace(/:$/, '')}`,
    );
  }
  const token = rpcRaw['token'];
  if (typeof token !== 'string' || token.length === 0) {
    throw new SigilConfigError(
      `config.rpc.token is required — generate one with: openssl rand -hex 24`,
    );
  }
  if (token.length < RPC_TOKEN_MIN_LENGTH) {
    throw new SigilConfigError(
      `config.rpc.token must be at least ${RPC_TOKEN_MIN_LENGTH} characters — ` +
        `it is the only credential guarding the signing endpoint. ` +
        `Generate one with: openssl rand -hex 24`,
    );
  }
  const port = rpcRaw['port'];
  if (port !== undefined) {
    if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
      throw new SigilConfigError(`config.rpc.port must be an integer in 1..65535`);
    }
  }
  return {
    portal,
    upstream,
    token,
    ...(port !== undefined ? { port: port as number } : {}),
  };
}

/**
 * Load + parse the file at ~/.sigil/config.toml. Returns an empty config if
 * the file is absent. Throws SigilConfigError on parse/schema errors.
 */
export function loadConfig(path: string): SigilConfig {
  let source: string;
  try {
    source = readFileSync(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw new SigilConfigError(`config: failed to read ${path}: ${(err as Error).message}`);
  }
  return parseConfig(source);
}

/**
 * Walk every *.toml under the policy dir, parse each, and return true if
 * any of them can route a sign to the confirm gate: require_confirm_above_wei,
 * or strict-mode allow_contract_creation (deploys always confirm). A
 * malformed policy file is skipped (it'll surface its own error at sign
 * time); we only need to know whether some portal is *trying* to gate on
 * confirm.
 */
export function anyPolicyRequiresConfirm(policyDir: string): boolean {
  let entries: string[];
  try {
    entries = readdirSync(policyDir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw err;
  }
  for (const f of entries) {
    if (!f.endsWith('.toml')) continue;
    let source: string;
    try {
      source = readFileSync(join(policyDir, f), 'utf8');
    } catch {
      continue;
    }
    try {
      const p = parsePolicy(source);
      if (p.requireConfirmAboveWei !== undefined) return true;
      if (p.mode === 'strict' && p.allowContractCreation) return true;
    } catch (err) {
      // Malformed policy file — not our problem here; the sign path will
      // raise PolicyLoadError when this portal is used. Skip.
      if (err instanceof PolicyLoadError) continue;
      throw err;
    }
  }
  return false;
}

/**
 * Fail-closed check called at sigil-mcp boot: if any policy on disk uses
 * require_confirm_above_wei but the config has no transport, the process
 * cannot honour that policy — bail with a clear message instead of running
 * with a half-built safety net.
 */
export function enforceConfirmTransportPresence(config: SigilConfig, policyDir: string): void {
  const needsTransport = anyPolicyRequiresConfirm(policyDir);
  if (!needsTransport) return;
  const haveTransport = config.confirm?.ntfy !== undefined;
  if (haveTransport) return;
  throw new SigilConfigError(
    `at least one portal policy in ${policyDir} sets require_confirm_above_wei, ` +
      `but no OOB confirm transport is configured. ` +
      `Add a [confirm.ntfy] block to ~/.sigil/config.toml with a topic, ` +
      `or remove require_confirm_above_wei from the affected policy files.`,
  );
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
