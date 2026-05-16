import { redact, type RedactionResult } from './redactor.js';
import type { HookEnvelope, PostToolModification } from './protocol.js';

/**
 * Walk the tool_response field of a PostToolUse envelope, redacting every
 * string we find. Returns the modification envelope to emit, or null if
 * nothing changed.
 */
export function decidePostToolUse(env: HookEnvelope): PostToolModification | null {
  const response = env.tool_response;
  if (response === undefined) return null;

  const totals = new Map<string, number>();
  const redacted = walkAndRedact(response, totals);
  if (totals.size === 0) return null;

  return {
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      updatedToolResponse: redacted as Record<string, unknown> | string,
    },
  };
}

/**
 * Recursively descend into objects, arrays, and strings, applying redact()
 * to every string we encounter. Accumulates redaction counts.
 */
export function walkAndRedact(value: unknown, totals: Map<string, number>): unknown {
  if (typeof value === 'string') {
    const r: RedactionResult = redact(value);
    for (const s of r.redactions) totals.set(s.reason, (totals.get(s.reason) ?? 0) + s.count);
    return r.text;
  }
  if (Array.isArray(value)) {
    return value.map((v) => walkAndRedact(v, totals));
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = walkAndRedact(v, totals);
    }
    return out;
  }
  return value;
}
