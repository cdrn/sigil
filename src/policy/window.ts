import type { Policy } from './types.js';

/** Which per-portal running total a signed amount counts against. */
export type SpendAsset = 'wei' | 'lamports';

export interface WindowCap {
  /** TOML field name, for the deny reason. */
  label: string;
  windowMs: number;
  cap: bigint;
}

export const HOUR_MS = 60 * 60 * 1000;
export const DAY_MS = 24 * HOUR_MS;

/** The rolling-window caps a policy sets for one asset, longest window last. */
export function windowCapsFor(policy: Policy, asset: SpendAsset): WindowCap[] {
  const caps: WindowCap[] = [];
  if (asset === 'wei') {
    if (policy.maxValuePerHourWei !== undefined) {
      caps.push({
        label: 'max_value_per_hour_wei',
        windowMs: HOUR_MS,
        cap: policy.maxValuePerHourWei,
      });
    }
    if (policy.maxValuePerDayWei !== undefined) {
      caps.push({
        label: 'max_value_per_day_wei',
        windowMs: DAY_MS,
        cap: policy.maxValuePerDayWei,
      });
    }
  } else {
    if (policy.svmMaxLamportsPerHour !== undefined) {
      caps.push({
        label: 'svm_max_lamports_per_hour',
        windowMs: HOUR_MS,
        cap: policy.svmMaxLamportsPerHour,
      });
    }
    if (policy.svmMaxLamportsPerDay !== undefined) {
      caps.push({
        label: 'svm_max_lamports_per_day',
        windowMs: DAY_MS,
        cap: policy.svmMaxLamportsPerDay,
      });
    }
  }
  return caps;
}

/**
 * Pure check: would signing `amount` now push any window over its cap?
 * `spent(windowMs)` returns what the ledger already holds for that trailing
 * window. Returns a human-readable deny reason, or null if every cap holds.
 * A zero amount never breaches (a cap of 0 means "no value at all", and
 * value-less calls carry no value).
 */
export function checkWindowCaps(
  caps: readonly WindowCap[],
  amount: bigint,
  spent: (windowMs: number) => bigint,
  unit: SpendAsset,
): string | null {
  if (amount === 0n) return null;
  for (const c of caps) {
    const used = spent(c.windowMs);
    if (used + amount > c.cap) {
      return (
        `denied — ${amount} ${unit} would bring the trailing ${describe(c.windowMs)} total to ` +
        `${used + amount} ${unit}, over ${c.label} = ${c.cap}`
      );
    }
  }
  return null;
}

function describe(windowMs: number): string {
  if (windowMs === HOUR_MS) return '1h';
  if (windowMs === DAY_MS) return '24h';
  return `${windowMs}ms`;
}
