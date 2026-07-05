import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import toml from '@iarna/toml';
import { parsePolicy, PolicyLoadError } from '../policy/index.js';

/**
 * sigil config at ~/.sigil/config.toml. Today this only carries the OOB
 * confirm transport block; will grow over time.
 *
 *   [confirm.ntfy]
 *   topic  = "an-unguessable-string"
 *   server = "https://ntfy.sh"   # optional, default https://ntfy.sh
 *
 * Missing file → SigilConfig with no transport configured. That's fine on
 * its own; we only fail closed at startup if some policy actually depends
 * on a transport (see `enforceConfirmTransportPresence`).
 */
export interface SigilConfig {
  confirm?: ConfirmConfig;
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
export function enforceConfirmTransportPresence(
  config: SigilConfig,
  policyDir: string,
): void {
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
