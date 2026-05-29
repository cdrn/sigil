import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { type KdfParams, sealKey, SecretBuffer, unsealKey } from '../crypto/index.js';
import { addressFromPrivateKey, randomSecretKey } from '../eth/index.js';
import { HandleTable } from '../daemon/handles.js';
import { type PolicyMode, policyTemplate } from '../policy/index.js';
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
  /**
   * Policy template to write at provisioning time. Defaults to "permissive"
   * (signs anything the agent asks — same UX as today, key still protected
   * from context). Pass "strict" to write a locked-down template the user
   * must edit before signing succeeds.
   */
  policyMode?: PolicyMode;
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
export function portalAdd(
  paths: SigilPaths,
  opts: PortalAddOpts,
): { address: string; keyfilePath: string; policyPath: string } {
  const raw = readFileSync(opts.keyFile);
  const priv = normalizePrivateKey(raw);
  const result = provisionPortal(paths, {
    handle: opts.handle,
    priv,
    passphrase: opts.passphrase,
    policyMode: opts.policyMode ?? 'permissive',
    ...(opts.kdfParams ? { kdfParams: opts.kdfParams } : {}),
  });
  if (opts.removeSource !== false) {
    try { unlinkSync(opts.keyFile); }
    catch { /* best-effort cleanup; file may already be gone */ }
  }
  return result;
}

export interface PortalNewOpts {
  handle: string;
  passphrase: Buffer;
  /** See PortalAddOpts.kdfParams — same test-only knob. */
  kdfParams?: KdfParams;
  /** See PortalAddOpts.policyMode. */
  policyMode?: PolicyMode;
}

/**
 * Mint a fresh secp256k1 key inside sigil, encrypt with the passphrase,
 * write the keyfile + policy file. No plaintext key ever lands on disk.
 * The randomness goes through @noble's randomSecretKey() which is uniform
 * over the valid scalar range.
 */
export function portalNew(
  paths: SigilPaths,
  opts: PortalNewOpts,
): { address: string; keyfilePath: string; policyPath: string } {
  const priv = randomSecretKey();
  return provisionPortal(paths, {
    handle: opts.handle,
    priv,
    passphrase: opts.passphrase,
    policyMode: opts.policyMode ?? 'permissive',
    ...(opts.kdfParams ? { kdfParams: opts.kdfParams } : {}),
  });
}

interface ProvisionPortalArgs {
  handle: string;
  /** 32-byte private key. Takes ownership: zeroized before this returns. */
  priv: Buffer;
  passphrase: Buffer;
  policyMode: PolicyMode;
  kdfParams?: KdfParams;
}

function provisionPortal(
  paths: SigilPaths,
  args: ProvisionPortalArgs,
): { address: string; keyfilePath: string; policyPath: string } {
  HandleTable.parseHandle(args.handle); // validates format
  mkdirSync(paths.keysDir, { recursive: true, mode: 0o700 });
  mkdirSync(paths.policyDir, { recursive: true, mode: 0o700 });

  const destPath = join(paths.keysDir, `${args.handle}.sigil`);
  if (existsSync(destPath)) {
    args.priv.fill(0);
    throw new Error(`portal "${args.handle}" already exists at ${destPath}; remove it first`);
  }
  const policyPath = join(paths.policyDir, `${args.handle}.toml`);
  if (existsSync(policyPath)) {
    args.priv.fill(0);
    throw new Error(`policy file for "${args.handle}" already exists at ${policyPath}; remove it first`);
  }

  let address: string;
  try {
    address = addressFromPrivateKey(args.priv);
    const sealed = args.kdfParams
      ? sealKey(args.priv, args.passphrase, args.kdfParams)
      : sealKey(args.priv, args.passphrase);
    writeFileSync(destPath, sealed, { mode: 0o600 });
  } finally {
    args.priv.fill(0);
  }

  // Mode 0o600 — the policy file describes what this key can sign, which is sensitive.
  writeFileSync(policyPath, policyTemplate(args.policyMode), { mode: 0o600 });

  return { address, keyfilePath: destPath, policyPath };
}

export interface PortalInfo {
  handle: string;
  kind: 'evm';
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
      out.push({ handle, kind: 'evm', address: addressFromPrivateKey(sb.bytes()) });
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

/**
 * Provision a policy file for an existing portal whose keyfile is on disk
 * but whose policy got lost (older sigil versions, manual deletion, etc).
 * Refuses to overwrite an existing policy — that's what the file is for.
 * Refuses to create one for a non-existent portal — fail loud.
 */
export function policyInit(
  paths: SigilPaths,
  handle: string,
  mode: PolicyMode,
): { policyPath: string; mode: PolicyMode } {
  HandleTable.parseHandle(handle); // validates format
  const keyfilePath = join(paths.keysDir, `${handle}.sigil`);
  if (!existsSync(keyfilePath)) {
    throw new Error(`portal "${handle}" not found at ${keyfilePath}; run "sigil portal add" first`);
  }
  mkdirSync(paths.policyDir, { recursive: true, mode: 0o700 });
  const policyPath = join(paths.policyDir, `${handle}.toml`);
  if (existsSync(policyPath)) {
    throw new Error(`policy already exists at ${policyPath}; edit it directly or remove it first`);
  }
  writeFileSync(policyPath, policyTemplate(mode), { mode: 0o600 });
  return { policyPath, mode };
}

export function portalRemove(paths: SigilPaths, handle: string): PortalRemoveResult {
  HandleTable.parseHandle(handle); // validates format
  const destPath = join(paths.keysDir, `${handle}.sigil`);
  const policyPath = join(paths.policyDir, `${handle}.toml`);
  const keyfileExisted = existsSync(destPath);
  if (keyfileExisted) unlinkSync(destPath);
  // Best-effort policy cleanup. We don't fail the remove if the keyfile is
  // missing but the policy file isn't, or vice versa — better to err on the
  // side of cleaning up orphans.
  if (existsSync(policyPath)) {
    try { unlinkSync(policyPath); } catch { /* ignore */ }
  }
  return { removed: keyfileExisted, path: destPath };
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
