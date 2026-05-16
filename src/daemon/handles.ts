import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { addressFromPrivateKey } from '../eth/address.js';
import {
  type SecretBuffer,
  unsealKey,
  WrongPassphraseError,
} from '../crypto/index.js';

const KEYFILE_EXT = '.sigil';
// Handle format: <kind>:<name> where kind is currently always "eth" and name
// is restricted to characters that are safe both as identifiers and as
// filenames. Disallow '.', '/', and whitespace.
const HANDLE_RE = /^(eth):([a-zA-Z0-9_-]+)$/;

export interface PortalInfo {
  handle: string;
  kind: 'eth';
  address: string;
}

export class HandleLoadError extends Error {
  override readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'HandleLoadError';
    if (cause !== undefined) this.cause = cause;
  }
}

/**
 * In-memory registry of handle → unlocked SecretBuffer.
 *
 * The expectation is that this is constructed once at daemon startup, populated
 * via loadFromDir (or addEntry from tests), and disposed once at shutdown.
 * After dispose() any further get/list calls throw.
 */
export class HandleTable {
  // Wrapped in a private map; not exposed.
  readonly #entries = new Map<string, { secret: SecretBuffer; info: PortalInfo }>();
  #disposed = false;

  static parseHandle(handle: string): { kind: 'eth'; name: string } {
    const m = HANDLE_RE.exec(handle);
    if (!m) throw new HandleLoadError(`invalid handle "${handle}": expected <kind>:<name>`);
    return { kind: m[1] as 'eth', name: m[2]! };
  }

  static handleFromFilename(filename: string): string | null {
    if (!filename.endsWith(KEYFILE_EXT)) return null;
    const base = filename.slice(0, -KEYFILE_EXT.length);
    if (!HANDLE_RE.test(base)) return null;
    return base;
  }

  /**
   * Load every keyfile in `dir` named `<handle>.sigil`, decrypting each with
   * the same passphrase. Throws HandleLoadError on any failure.
   *
   * Order: deterministic by sorted filename, so audit logs and list_portals
   * output are stable across restarts.
   */
  loadFromDir(dir: string, passphrase: Buffer): void {
    if (this.#disposed) throw new Error('HandleTable is disposed');
    let entries: string[];
    try {
      entries = readdirSync(dir).sort();
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw new HandleLoadError(`failed to read keys directory ${dir}`, err);
    }
    for (const filename of entries) {
      const handle = HandleTable.handleFromFilename(filename);
      if (handle === null) continue; // ignore non-keyfiles
      const path = join(dir, filename);
      let blob: Buffer;
      try {
        blob = readFileSync(path);
      } catch (err) {
        throw new HandleLoadError(`failed to read keyfile ${path}`, err);
      }
      let secret: SecretBuffer;
      try {
        secret = unsealKey(blob, passphrase);
      } catch (err) {
        if (err instanceof WrongPassphraseError) {
          throw new HandleLoadError(`wrong passphrase or tampered keyfile: ${path}`, err);
        }
        throw new HandleLoadError(`failed to unseal keyfile ${path}`, err);
      }
      this.addEntry(handle, secret);
    }
  }

  /**
   * Add a handle directly (for tests or for non-file-backed key sources).
   * Takes ownership of the SecretBuffer; dispose() will zeroize it.
   */
  addEntry(handle: string, secret: SecretBuffer): void {
    if (this.#disposed) throw new Error('HandleTable is disposed');
    HandleTable.parseHandle(handle); // validates format
    if (this.#entries.has(handle)) {
      secret.dispose();
      throw new HandleLoadError(`duplicate handle "${handle}"`);
    }
    const address = addressFromPrivateKey(secret.bytes());
    this.#entries.set(handle, {
      secret,
      info: { handle, kind: 'eth', address },
    });
  }

  has(handle: string): boolean {
    if (this.#disposed) throw new Error('HandleTable is disposed');
    return this.#entries.has(handle);
  }

  /**
   * Returns the SecretBuffer for the handle. Caller must NOT dispose it —
   * the table owns the lifetime.
   */
  get(handle: string): SecretBuffer | undefined {
    if (this.#disposed) throw new Error('HandleTable is disposed');
    return this.#entries.get(handle)?.secret;
  }

  list(): PortalInfo[] {
    if (this.#disposed) throw new Error('HandleTable is disposed');
    return Array.from(this.#entries.values()).map((e) => ({ ...e.info }));
  }

  /**
   * Zeroize every key and mark the table unusable. Idempotent.
   */
  dispose(): void {
    if (this.#disposed) return;
    for (const e of this.#entries.values()) e.secret.dispose();
    this.#entries.clear();
    this.#disposed = true;
  }

  get isDisposed(): boolean {
    return this.#disposed;
  }
}
