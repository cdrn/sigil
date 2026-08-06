import type { FetchLike } from './types.js';

/**
 * Read-only service discovery over the two public payment registries:
 *
 *   - MPP services directory: https://mpp.dev/api/services
 *   - x402 Bazaar (CDP facilitator catalog):
 *     https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources
 *
 * No keys, no signing, no policy involvement — this is a phonebook. Entries
 * are normalized to a small common shape and truncated hard: registry
 * listings are third-party content and get no more trust than any other
 * webpage the model reads.
 */

export interface DiscoveredService {
  registry: 'mpp' | 'x402-bazaar';
  name?: string;
  url: string;
  description?: string;
  /** Price of the cheapest advertised option, base units + asset, if known. */
  amount?: string;
  asset?: string;
  network?: string;
}

const MPP_REGISTRY_URL = 'https://mpp.dev/api/services';
const BAZAAR_URL = 'https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources';
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_RESULTS = 50;
const MAX_FIELD_CHARS = 300;

function clip(v: unknown): string | undefined {
  if (typeof v !== 'string' || v === '') return undefined;
  return v.length > MAX_FIELD_CHARS ? v.slice(0, MAX_FIELD_CHARS) + '…' : v;
}

async function fetchJson(fetchImpl: FetchLike, url: string): Promise<unknown> {
  const res = await fetchImpl(url, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`registry ${url} answered ${res.status}`);
  return (await res.json()) as unknown;
}

function asArray(doc: unknown, ...keys: string[]): unknown[] {
  if (Array.isArray(doc)) return doc;
  if (typeof doc !== 'object' || doc === null) return [];
  for (const key of keys) {
    const v = (doc as Record<string, unknown>)[key];
    if (Array.isArray(v)) return v;
  }
  return [];
}

export async function discoverMpp(fetchImpl: FetchLike): Promise<DiscoveredService[]> {
  const doc = await fetchJson(fetchImpl, MPP_REGISTRY_URL);
  const out: DiscoveredService[] = [];
  for (const item of asArray(doc, 'services', 'items')) {
    if (typeof item !== 'object' || item === null) continue;
    const it = item as Record<string, unknown>;
    const url = clip(it['url']) ?? clip(it['website']);
    if (!url) continue;
    const name = clip(it['name']);
    const description = clip(it['description']);
    out.push({
      registry: 'mpp',
      url,
      ...(name !== undefined ? { name } : {}),
      ...(description !== undefined ? { description } : {}),
    });
  }
  return out;
}

export async function discoverX402(fetchImpl: FetchLike): Promise<DiscoveredService[]> {
  const doc = await fetchJson(fetchImpl, `${BAZAAR_URL}?limit=${MAX_RESULTS}`);
  const out: DiscoveredService[] = [];
  for (const item of asArray(doc, 'items', 'resources')) {
    if (typeof item !== 'object' || item === null) continue;
    const it = item as Record<string, unknown>;
    const resource =
      typeof it['resource'] === 'object' && it['resource'] !== null
        ? (it['resource'] as Record<string, unknown>)
        : undefined;
    const url = clip(it['resource']) ?? clip(resource?.['url']) ?? clip(it['url']);
    if (!url) continue;
    const accepts = asArray(it['accepts']);
    interface PriceEntry {
      amount: string;
      asset: string | undefined;
      network: string | undefined;
    }
    const priced: PriceEntry[] = [];
    for (const a of accepts) {
      if (typeof a !== 'object' || a === null) continue;
      const acc = a as Record<string, unknown>;
      const amount = clip(acc['amount']) ?? clip(acc['maxAmountRequired']);
      if (amount === undefined || !/^[0-9]+$/.test(amount)) continue;
      priced.push({ amount, asset: clip(acc['asset']), network: clip(acc['network']) });
    }
    const cheapest = priced.sort((a, b) => (BigInt(a.amount) < BigInt(b.amount) ? -1 : 1))[0];
    const name = clip(it['name']);
    const description = clip(it['description']) ?? clip(resource?.['description']);
    out.push({
      registry: 'x402-bazaar',
      url,
      ...(name !== undefined ? { name } : {}),
      ...(description !== undefined ? { description } : {}),
      ...(cheapest !== undefined ? { amount: cheapest.amount } : {}),
      ...(cheapest?.asset !== undefined ? { asset: cheapest.asset } : {}),
      ...(cheapest?.network !== undefined ? { network: cheapest.network } : {}),
    });
  }
  return out;
}

export interface DiscoverOptions {
  registry?: 'mpp' | 'x402' | 'all';
  /** Case-insensitive substring filter over name/description/url. */
  query?: string;
}

export async function discover(
  fetchImpl: FetchLike,
  opts: DiscoverOptions = {},
): Promise<DiscoveredService[]> {
  const registry = opts.registry ?? 'all';
  const parts = await Promise.allSettled([
    registry === 'x402' ? Promise.resolve([]) : discoverMpp(fetchImpl),
    registry === 'mpp' ? Promise.resolve([]) : discoverX402(fetchImpl),
  ]);
  const services = parts.flatMap((p) => (p.status === 'fulfilled' ? p.value : []));
  if (parts.every((p) => p.status === 'rejected')) {
    throw new Error(
      `all registries failed: ${parts
        .map((p) => (p.status === 'rejected' ? String((p.reason as Error).message ?? p.reason) : ''))
        .join('; ')}`,
    );
  }
  const q = opts.query?.toLowerCase();
  const filtered = q
    ? services.filter((s) =>
        [s.name, s.description, s.url].some((f) => f?.toLowerCase().includes(q)),
      )
    : services;
  return filtered.slice(0, MAX_RESULTS);
}
