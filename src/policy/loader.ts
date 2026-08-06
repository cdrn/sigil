import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import toml from '@iarna/toml';
import { type Policy, PolicyLoadError, type PolicyResolver } from './types.js';

const ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const SELECTOR_RE = /^0x[0-9a-fA-F]{8}$/;
const DEC_RE = /^[0-9]+$/;

/**
 * Parse + validate + normalize a TOML policy file. Throws PolicyLoadError on
 * any schema violation with a message pointing at the offending field.
 *
 * Normalization:
 *   - addresses lowercased so allowlist membership is case-insensitive
 *   - selectors lowercased likewise
 *   - max_value_wei string → bigint
 *
 * Permissive mode tolerates missing strict fields (they're ignored anyway).
 * Strict mode applies defaults: chain_ids must be present; everything else
 * defaults to a closed/zero value.
 */
export function parsePolicy(source: string): Policy {
  let raw: toml.JsonMap;
  try {
    raw = toml.parse(source);
  } catch (err) {
    throw new PolicyLoadError(`policy: invalid TOML — ${(err as Error).message}`, err);
  }

  const mode = raw['mode'];
  if (mode !== 'permissive' && mode !== 'strict') {
    throw new PolicyLoadError(`policy.mode must be "permissive" or "strict" (got ${JSON.stringify(mode)})`);
  }

  // require_confirm_above_wei is mode-independent: it's an opt-in safety net
  // that applies whether or not the rest of the file is strict.
  const requireConfirmAboveWei = parseOptionalWei(
    raw['require_confirm_above_wei'],
    'require_confirm_above_wei',
  );
  const payRequireConfirmAbove = parseOptionalWei(
    raw['pay_require_confirm_above'],
    'pay_require_confirm_above',
  );
  const payOrigins = parsePayOrigins(raw['pay_origins']);
  const payCurrencies = asStringArray(raw['pay_currencies'], 'pay_currencies').map((s) =>
    s.toLowerCase(),
  );
  const payRecipients = asStringArray(raw['pay_recipients'], 'pay_recipients').map((s, i) => {
    if (!ADDR_RE.test(s)) {
      throw new PolicyLoadError(`policy.pay_recipients[${i}] must be 0x-prefixed 20-byte address`);
    }
    return s.toLowerCase();
  });

  if (mode === 'permissive') {
    return {
      mode: 'permissive',
      chainIds: [],
      allowTo: [],
      maxValueWei: 0n,
      allowedSelectors: [],
      allowMessageSigning: true,
      allowTypedData: true,
      payOrigins,
      payMaxAmount: 0n,
      payCurrencies,
      payRecipients,
      ...(requireConfirmAboveWei !== undefined ? { requireConfirmAboveWei } : {}),
      ...(payRequireConfirmAbove !== undefined ? { payRequireConfirmAbove } : {}),
    };
  }

  // strict mode — every field is consulted; apply defaults for absent ones.
  const chainIds = asNumberArray(raw['chain_ids'], 'chain_ids', { required: true });
  for (const id of chainIds) {
    if (!Number.isInteger(id) || id < 0) {
      throw new PolicyLoadError(`policy.chain_ids[*] must be non-negative integers (got ${id})`);
    }
  }

  const allowToRaw = asStringArray(raw['allow_to'], 'allow_to');
  const allowTo = allowToRaw.map((s, i) => {
    if (!ADDR_RE.test(s)) {
      throw new PolicyLoadError(`policy.allow_to[${i}] must be 0x-prefixed 20-byte address`);
    }
    return s.toLowerCase();
  });

  const maxValueWei = parseMaxValue(raw['max_value_wei']);

  const selectorsRaw = asStringArray(raw['allowed_selectors'], 'allowed_selectors');
  const allowedSelectors = selectorsRaw.map((s, i) => {
    if (!SELECTOR_RE.test(s)) {
      throw new PolicyLoadError(`policy.allowed_selectors[${i}] must be 0x + 4 hex bytes (got ${JSON.stringify(s)})`);
    }
    return s.toLowerCase();
  });

  const allowMessageSigning = asBool(raw['allow_message_signing'], 'allow_message_signing', false);
  const allowTypedData = asBool(raw['allow_typed_data'], 'allow_typed_data', false);

  // Catch the misconfiguration where the confirm threshold sits above the
  // hard cap: nothing would ever trigger the confirm path, the deny would
  // fire first. Easier to surface at load time than to wonder why your
  // phone never buzzed.
  if (
    requireConfirmAboveWei !== undefined &&
    requireConfirmAboveWei >= maxValueWei &&
    maxValueWei !== 0n
  ) {
    throw new PolicyLoadError(
      `policy.require_confirm_above_wei (${requireConfirmAboveWei}) must be less than ` +
      `max_value_wei (${maxValueWei}) — otherwise the value cap fires first and the ` +
      `confirm gate never triggers`,
    );
  }

  const payMaxAmount = parseOptionalWei(raw['pay_max_amount'], 'pay_max_amount') ?? 0n;
  if (
    payRequireConfirmAbove !== undefined &&
    payRequireConfirmAbove >= payMaxAmount &&
    payMaxAmount !== 0n
  ) {
    throw new PolicyLoadError(
      `policy.pay_require_confirm_above (${payRequireConfirmAbove}) must be less than ` +
      `pay_max_amount (${payMaxAmount}) — otherwise the amount cap fires first and the ` +
      `confirm gate never triggers`,
    );
  }

  return {
    mode: 'strict',
    chainIds,
    allowTo,
    maxValueWei,
    allowedSelectors,
    allowMessageSigning,
    allowTypedData,
    payOrigins,
    payMaxAmount,
    payCurrencies,
    payRecipients,
    ...(requireConfirmAboveWei !== undefined ? { requireConfirmAboveWei } : {}),
    ...(payRequireConfirmAbove !== undefined ? { payRequireConfirmAbove } : {}),
  };
}

/**
 * A PolicyResolver that returns the same permissive policy for every handle.
 * Useful for tests that want to exercise sign methods without provisioning
 * a TOML file per portal.
 */
export function permissivePolicyResolver(): PolicyResolver {
  const policy: Policy = {
    mode: 'permissive',
    chainIds: [],
    allowTo: [],
    maxValueWei: 0n,
    allowedSelectors: [],
    allowMessageSigning: true,
    allowTypedData: true,
    payOrigins: [],
    payMaxAmount: 0n,
    payCurrencies: [],
    payRecipients: [],
  };
  return { resolve: () => policy };
}

/**
 * File-backed PolicyResolver: reads ~/.sigil/policy/<handle>.toml every time
 * resolve() is called. Sign calls are human-paced so the read is cheap; the
 * fresh read also means policy edits take effect immediately (no daemon
 * restart).
 */
export class FileSystemPolicyResolver implements PolicyResolver {
  readonly #policyDir: string;
  constructor(policyDir: string) {
    this.#policyDir = policyDir;
  }
  resolve(handle: string): Policy {
    const path = join(this.#policyDir, `${handle}.toml`);
    let source: string;
    try {
      source = readFileSync(path, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new PolicyLoadError(
          `policy: no policy file for portal "${handle}" at ${path} — run "sigil policy init ${handle}" (add "--strict" for a locked-down template)`,
        );
      }
      throw new PolicyLoadError(`policy: failed to read ${path}`, err);
    }
    return parsePolicy(source);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function asNumberArray(v: unknown, name: string, opts: { required?: boolean } = {}): number[] {
  if (v === undefined) {
    if (opts.required) throw new PolicyLoadError(`policy.${name} is required in strict mode`);
    return [];
  }
  if (!Array.isArray(v)) throw new PolicyLoadError(`policy.${name} must be an array`);
  return v.map((item, i) => {
    if (typeof item !== 'number') {
      throw new PolicyLoadError(`policy.${name}[${i}] must be a number (got ${typeof item})`);
    }
    return item;
  });
}

function asStringArray(v: unknown, name: string): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new PolicyLoadError(`policy.${name} must be an array`);
  return v.map((item, i) => {
    if (typeof item !== 'string') {
      throw new PolicyLoadError(`policy.${name}[${i}] must be a string (got ${typeof item})`);
    }
    return item;
  });
}

function asBool(v: unknown, name: string, def: boolean): boolean {
  if (v === undefined) return def;
  if (typeof v !== 'boolean') {
    throw new PolicyLoadError(`policy.${name} must be a boolean (got ${typeof v})`);
  }
  return v;
}

function parseMaxValue(v: unknown): bigint {
  if (v === undefined) return 0n;
  if (typeof v !== 'string') {
    throw new PolicyLoadError(
      `policy.max_value_wei must be a decimal string (e.g. "100000000000000000"); got ${typeof v}`,
    );
  }
  if (!DEC_RE.test(v)) {
    throw new PolicyLoadError(
      `policy.max_value_wei must be a decimal integer string (got ${JSON.stringify(v)})`,
    );
  }
  return BigInt(v);
}

/**
 * pay_origins entries must be exact origins — scheme + host (+ port), no
 * path. Normalized through the URL parser so "HTTPS://Host" and
 * "https://host" compare equal at evaluation time.
 */
function parsePayOrigins(v: unknown): string[] {
  const raw = asStringArray(v, 'pay_origins');
  return raw.map((s, i) => {
    let url: URL;
    try {
      url = new URL(s);
    } catch {
      throw new PolicyLoadError(`policy.pay_origins[${i}] must be a URL origin like "https://api.example.com" (got ${JSON.stringify(s)})`);
    }
    if (url.origin.toLowerCase() !== s.toLowerCase().replace(/\/$/, '')) {
      throw new PolicyLoadError(
        `policy.pay_origins[${i}] must be a bare origin (no path/query) — did you mean ${JSON.stringify(url.origin)}?`,
      );
    }
    return url.origin.toLowerCase();
  });
}

function parseOptionalWei(v: unknown, name: string): bigint | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'string') {
    throw new PolicyLoadError(
      `policy.${name} must be a decimal string (e.g. "100000000000000000"); got ${typeof v}`,
    );
  }
  if (!DEC_RE.test(v)) {
    throw new PolicyLoadError(
      `policy.${name} must be a decimal integer string (got ${JSON.stringify(v)})`,
    );
  }
  return BigInt(v);
}
