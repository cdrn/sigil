import type { ConfirmRequest, ConfirmTransport } from './types.js';

export interface NtfyConfig {
  /** Topic name — appears as the last path segment of the ntfy URL. The
   *  topic name IS the credential on ntfy.sh; pick something unguessable. */
  topic: string;
  /** Base URL, default https://ntfy.sh. Override to point at a self-hosted
   *  ntfy instance (e.g. https://ntfy.example.com). No trailing slash. */
  server?: string;
}

/** Minimal subset of the fetch API surface we use. Lets tests inject a stub
 *  without dragging in undici/MSW. */
export type FetchLike = (
  url: string,
  init: { method: 'POST'; headers: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; statusText: string }>;

/**
 * ntfy.sh transport. Publish-only — the user's phone subscribes through the
 * ntfy app, taps an action button, and the click round-trips to sigil's
 * local ack server. We never read from ntfy.
 *
 * Headers we use (all per ntfy docs):
 *   Title:    portal handle
 *   Priority: high (default 4) — bypasses Android Doze + iOS quiet hours
 *   Click:    approveUrl — tapping the body of the notification approves
 *   Actions:  http,Approve,<approveUrl>; http,Deny,<denyUrl>
 */
export class NtfyTransport implements ConfirmTransport {
  readonly name = 'ntfy';
  readonly #url: string;
  readonly #fetch: FetchLike;

  constructor(config: NtfyConfig, fetchImpl: FetchLike = globalThis.fetch as unknown as FetchLike) {
    const server = (config.server ?? 'https://ntfy.sh').replace(/\/+$/, '');
    if (!/^[A-Za-z0-9_-]+$/.test(config.topic)) {
      // ntfy permits more, but a stricter pattern catches "user pasted the full
      // URL into the topic field" right at construction time.
      throw new Error(`ntfy topic must match [A-Za-z0-9_-]+ (got ${JSON.stringify(config.topic)})`);
    }
    this.#url = `${server}/${config.topic}`;
    this.#fetch = fetchImpl;
  }

  async send(req: ConfirmRequest): Promise<void> {
    const actions = [
      `http, Approve, ${req.approveUrl}, method=POST, clear=true`,
      `http, Deny, ${req.denyUrl}, method=POST, clear=true`,
    ].join('; ');
    const resp = await this.#fetch(this.#url, {
      method: 'POST',
      headers: {
        Title: `sigil — ${req.portal}`,
        Priority: 'high',
        Click: req.approveUrl,
        Actions: actions,
        'Content-Type': 'text/plain; charset=utf-8',
      },
      body: req.summary,
    });
    if (!resp.ok) {
      throw new Error(`ntfy push failed: HTTP ${resp.status} ${resp.statusText}`);
    }
  }
}
