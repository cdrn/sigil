import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { type KdfParams, sealKey, SecretBuffer, unsealKey } from '../crypto/index.js';
import { addressFromPrivateKey } from '../eth/index.js';
import { HandleTable } from '../daemon/handles.js';
import type { SigilPaths } from './paths.js';

export interface PortalAddOpts {
  handle: string;
  keyFile: string;
  passphrase: Buffer;
  /**
   * If true, the source key file is deleted after successful encryption.
   * Defaults to true — leaving plaintext keys lying around is the whole
   * thing sigil is trying to prevent.
   */
  removeSource?: boolean;
  /**
   * Override KDF parameters. Production code path uses DEFAULT_KDF_PARAMS
   * (64MiB / 3 iters / 4 parallelism). Tests pass weaker params to keep
   * the suite fast. The CLI binary never sets this.
   */
  kdfParams?: KdfParams;
}

/**
 * Reads a private key from disk, encrypts it with the passphrase, writes it
 * to the keys directory under <handle>.sigil, and (by default) deletes the
 * source file. Returns the derived address.
 *
 * Accepts the key file as either:
 *  - 32 raw bytes (binary)
 *  - 64 hex characters (optionally 0x-prefixed, optionally with trailing whitespace)
 */
export function portalAdd(paths: SigilPaths, opts: PortalAddOpts): { address: string; keyfilePath: string } {
  HandleTable.parseHandle(opts.handle); // validates format
  mkdirSync(paths.keysDir, { recursive: true, mode: 0o700 });

  const destPath = join(paths.keysDir, `${opts.handle}.sigil`);
  if (existsSync(destPath)) {
    throw new Error(`portal "${opts.handle}" already exists at ${destPath}; remove it first`);
  }

  const raw = readFileSync(opts.keyFile);
  const priv = normalizePrivateKey(raw);
  let address: string;
  try {
    address = addressFromPrivateKey(priv);
    const sealed = opts.kdfParams
      ? sealKey(priv, opts.passphrase, opts.kdfParams)
      : sealKey(priv, opts.passphrase);
    writeFileSync(destPath, sealed, { mode: 0o600 });
  } finally {
    priv.fill(0);
  }

  if (opts.removeSource !== false) {
    try { unlinkSync(opts.keyFile); }
    catch { /* best-effort cleanup; file may already be gone */ }
  }

  return { address, keyfilePath: destPath };
}

export interface PortalInfo {
  handle: string;
  kind: 'eth';
  address: string;
}

/**
 * Lists portals by reading the keys directory and decrypting each keyfile
 * just long enough to derive the address. Requires the passphrase.
 * Returns an empty list if the directory doesn't exist.
 */
export function portalListFromDisk(paths: SigilPaths, passphrase: Buffer): PortalInfo[] {
  if (!existsSync(paths.keysDir)) return [];
  const entries = readdirSync(paths.keysDir).sort();
  const out: PortalInfo[] = [];
  for (const filename of entries) {
    const handle = HandleTable.handleFromFilename(filename);
    if (handle === null) continue;
    const blob = readFileSync(join(paths.keysDir, filename));
    const sb = unsealKey(blob, passphrase);
    try {
      out.push({ handle, kind: 'eth', address: addressFromPrivateKey(sb.bytes()) });
    } finally {
      sb.dispose();
    }
  }
  return out;
}

export interface PortalRemoveResult {
  removed: boolean;
  path: string;
}

export function portalRemove(paths: SigilPaths, handle: string): PortalRemoveResult {
  HandleTable.parseHandle(handle); // validates format
  const destPath = join(paths.keysDir, `${handle}.sigil`);
  if (!existsSync(destPath)) return { removed: false, path: destPath };
  unlinkSync(destPath);
  return { removed: true, path: destPath };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizePrivateKey(raw: Buffer): Buffer {
  if (raw.length === 32) return Buffer.from(raw); // raw 32 bytes
  // Otherwise: expect ASCII hex, possibly with 0x prefix + trailing whitespace.
  const text = raw.toString('utf8').trim();
  const stripped = text.startsWith('0x') ? text.slice(2) : text;
  if (!/^[0-9a-fA-F]{64}$/.test(stripped)) {
    throw new Error(
      'key file must be either 32 raw bytes or 64 hex chars (with optional 0x prefix)',
    );
  }
  return Buffer.from(stripped, 'hex');
}

// Re-export SecretBuffer so tests can assert it disposes correctly without
// reaching into the crypto module directly.
export { SecretBuffer };
