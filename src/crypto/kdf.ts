import { argon2id } from '@noble/hashes/argon2.js';

export interface KdfParams {
  m: number;
  t: number;
  p: number;
}

export const DEFAULT_KDF_PARAMS: KdfParams = {
  m: 64 * 1024,
  t: 3,
  p: 4,
};

export const SALT_LEN = 16;
export const DERIVED_KEY_LEN = 32;

export function deriveKey(
  passphrase: Buffer | Uint8Array,
  salt: Buffer | Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Buffer {
  if (salt.length !== SALT_LEN) {
    throw new Error(`salt must be ${SALT_LEN} bytes, got ${salt.length}`);
  }
  if (params.m < 8) throw new Error('argon2id m must be >= 8 KiB');
  if (params.t < 1) throw new Error('argon2id t must be >= 1');
  if (params.p < 1) throw new Error('argon2id p must be >= 1');

  const out = argon2id(passphrase, salt, {
    m: params.m,
    t: params.t,
    p: params.p,
    dkLen: DERIVED_KEY_LEN,
  });
  return Buffer.from(out);
}
