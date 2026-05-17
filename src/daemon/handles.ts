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
 * Lifecycle inside sigil-mcp:
 *   - Constructed empty + locked at startup.
 *   - `sigil unlock` calls loadFromDir / addEntry → table becomes unlocked.
 *   - `sigil lock` calls lock() → entries zeroed + cleared, table re-lockable.
 *   - Process exit calls dispose() → final teardown, no further use.
 *
 * The unlocked flag is tracked separately from entry count so that an unlock
 * with zero portals on disk still distinguishes "no portals exist" (handle
 * lookup → PORTAL_NOT_FOUND) from "never unlocked" (handle lookup →
 * DAEMON_LOCKED).
 */
export class HandleTable {
  // Wrapped in a private map; not exposed.
  readonly #entries = new Map<string, { secret: SecretBuffer; info: PortalInfo }>();
  #unlocked = false;
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
   * the same passphrase. Throws HandleLoadError on any failure; on failure
   * the table is left locked with any partially-loaded entries zeroized.
   *
   * Order: deterministic by sorted filename, so audit logs and list_portals
   * output are stable across restarts.
   *
   * Marks the table as unlocked on success — even if the directory was
   * empty (zero portals to load). After that, sign calls see PORTAL_NOT_FOUND
   * instead of DAEMON_LOCKED.
   */
  loadFromDir(dir: string, passphrase: Buffer): void {
    if (this.#disposed) throw new Error('HandleTable is disposed');
    let entries: string[];
    try {
      entries = readdirSync(dir).sort();
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        this.#unlocked = true;
        return;
      }
      throw new HandleLoadError(`failed to read keys directory ${dir}`, err);
    }
    try {
      for (const filename of entries) {
        const handle = HandleTable.handleFromFilename(filename);
        if (handle === null) continue;
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
      this.#unlocked = true;
    } catch (err) {
      this.lock();
      throw err;
    }
  }

  /**
   * Add a handle directly (for tests or for non-file-backed key sources).
   * Takes ownership of the SecretBuffer; lock()/dispose() will zeroize it.
   * Does NOT flip the unlocked flag — loadFromDir does that once after a
   * successful pass. Tests that want an unlocked table should call
   * markUnlocked() explicitly.
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

  /**
   * Explicitly mark the table as unlocked without loading anything. Useful
   * for tests that pre-populate via addEntry and want sign methods to
   * succeed.
   */
  markUnlocked(): void {
    if (this.#disposed) throw new Error('HandleTable is disposed');
    this.#unlocked = true;
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

  isUnlocked(): boolean {
    if (this.#disposed) return false;
    return this.#unlocked;
  }

  /**
   * Zeroize every entry and re-lock the table. The table remains usable —
   * a subsequent unlock can repopulate it. Idempotent.
   */
  lock(): void {
    if (this.#disposed) return;
    for (const e of this.#entries.values()) e.secret.dispose();
    this.#entries.clear();
    this.#unlocked = false;
  }

  /**
   * Final teardown: zeroize every key and mark the table unusable. After
   * dispose(), get/has/list/lock/markUnlocked/addEntry/loadFromDir throw.
   * Idempotent.
   */
  dispose(): void {
    if (this.#disposed) return;
    for (const e of this.#entries.values()) e.secret.dispose();
    this.#entries.clear();
    this.#unlocked = false;
    this.#disposed = true;
  }

  get isDisposed(): boolean {
    return this.#disposed;
  }
}
